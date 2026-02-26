use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command as ProcessCommand, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};

use chrono::{DateTime, Local};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};

use crate::error::{GlovesError, Result};

const NAVIGATOR_EVENT_POLL_MILLIS: u64 = 200;
const MAX_OUTPUT_LINES: usize = 2_000;
const MAX_OUTPUT_SECTION_LINES: usize = 300;
const UI_HEADER_HEIGHT: u16 = 3;
const UI_FOOTER_HEIGHT: u16 = 3;
const OUTPUT_SCROLL_STEP: u16 = 1;
const OUTPUT_SCROLL_PAGE_STEP: u16 = 8;
const HORIZONTAL_SCROLL_STEP: u16 = 4;
const OUTPUT_TAB_EXPANSION: &str = "    ";
const SET_INPUT_MODE_GENERATE_INDEX: usize = 0;
const SET_INPUT_MODE_VALUE_INDEX: usize = 1;
const SET_INPUT_MODE_STDIN_INDEX: usize = 2;
const EMPTY_FILTER_PLACEHOLDER: &str = "<no matching commands>";

#[derive(Debug, Clone, Default)]
pub(crate) struct NavigatorLaunchOptions {
    pub(crate) root: Option<String>,
    pub(crate) agent: Option<String>,
    pub(crate) config: Option<String>,
    pub(crate) no_config: bool,
    pub(crate) vault_mode: Option<String>,
    pub(crate) error_format: Option<String>,
    pub(crate) command_args: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum FieldKind {
    Text,
    Bool,
    Choice(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy)]
enum FieldArg {
    Positional,
    OptionValue(&'static str),
    Flag(&'static str),
    None,
}

#[derive(Debug, Clone, Copy)]
struct FieldSpec {
    id: &'static str,
    label: &'static str,
    help: &'static str,
    required: bool,
    kind: FieldKind,
    arg: FieldArg,
    default_text: &'static str,
    default_bool: bool,
    default_choice: usize,
}

#[derive(Debug, Clone, Copy)]
struct CommandSpec {
    id: &'static str,
    title: &'static str,
    summary: &'static str,
    path: &'static [&'static str],
    fields: &'static [FieldSpec],
}

#[derive(Debug, Clone)]
enum FieldValue {
    Text(String),
    Bool(bool),
    Choice(usize),
}

#[derive(Debug, Clone)]
struct FieldState {
    spec: &'static FieldSpec,
    value: FieldValue,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum FocusPane {
    Commands,
    Globals,
    Fields,
    Output,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum InputMode {
    Navigate,
    Edit,
}

#[derive(Debug, Clone, Copy)]
enum EditingTarget {
    Global(usize),
    Field(usize),
    CommandFilter,
}

#[derive(Debug)]
struct TuiApp {
    selected_command_index: usize,
    selected_command_tree_row: usize,
    selected_global_field_index: usize,
    selected_command_field_index: usize,
    expanded_command_tree_paths: HashSet<String>,
    command_filter: String,
    focus: FocusPane,
    input_mode: InputMode,
    editing_target: Option<EditingTarget>,
    editing_buffer: String,
    editing_original_buffer: String,
    global_fields: Vec<FieldState>,
    command_fields: Vec<FieldState>,
    run_history: Vec<RunRecord>,
    next_run_id: u64,
    active_run: Option<ActiveRun>,
    output_scroll: u16,
    output_viewport_height: u16,
    command_viewport_width: u16,
    globals_viewport_width: u16,
    fields_viewport_width: u16,
    output_viewport_width: u16,
    command_horizontal_scroll: u16,
    globals_horizontal_scroll: u16,
    fields_horizontal_scroll: u16,
    output_horizontal_scroll: u16,
    follow_tail: bool,
    fullscreen_enabled: bool,
    status_line: String,
    pending_risky_signature: Option<String>,
    startup_command_pending: bool,
    should_quit: bool,
}

#[derive(Debug, Clone)]
struct CommandTreeNode {
    label: String,
    key: String,
    parent_key: Option<String>,
    children: Vec<CommandTreeNode>,
    command_index: Option<usize>,
}

#[derive(Debug, Clone)]
struct CommandTreeRow {
    key: String,
    parent_key: Option<String>,
    depth: usize,
    label: String,
    command_index: Option<usize>,
    is_expanded: bool,
    is_branch: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RunPhase {
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RunOutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug)]
enum RunOutputEvent {
    Line {
        stream: RunOutputStream,
        line: String,
    },
    ReadError {
        stream: RunOutputStream,
        message: String,
    },
}

#[derive(Debug)]
struct ActiveRun {
    run_id: u64,
    command_title: String,
    invocation: String,
    child: Child,
    output_events: Receiver<RunOutputEvent>,
    cancel_requested: bool,
}

#[derive(Debug, Clone)]
struct RunRecord {
    run_id: u64,
    command_title: String,
    invocation: String,
    phase: RunPhase,
    exit_code: Option<i32>,
    started_at: DateTime<Local>,
    finished_at: Option<DateTime<Local>>,
    started_instant: Instant,
    finished_instant: Option<Instant>,
    stdout_lines: Vec<String>,
    stderr_lines: Vec<String>,
}

const GLOBAL_VAULT_MODE_CHOICES: &[&str] = &["<unset>", "auto", "required", "disabled"];
const GLOBAL_ERROR_FORMAT_CHOICES: &[&str] = &["text", "json"];
const SET_INPUT_MODE_CHOICES: &[&str] = &["generate", "value", "stdin"];
const VAULT_OWNER_CHOICES: &[&str] = &["agent", "human"];

const GLOBAL_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "root",
        label: "Root",
        help: "Optional --root override",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--root"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "agent",
        label: "Agent",
        help: "Optional --agent override",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--agent"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "config",
        label: "Config",
        help: "Optional --config path",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--config"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "no_config",
        label: "No Config",
        help: "Set --no-config",
        required: false,
        kind: FieldKind::Bool,
        arg: FieldArg::Flag("--no-config"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "vault_mode",
        label: "Vault Mode",
        help: "Optional --vault-mode",
        required: false,
        kind: FieldKind::Choice(GLOBAL_VAULT_MODE_CHOICES),
        arg: FieldArg::OptionValue("--vault-mode"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "error_format",
        label: "Error Format",
        help: "--error-format value",
        required: true,
        kind: FieldKind::Choice(GLOBAL_ERROR_FORMAT_CHOICES),
        arg: FieldArg::OptionValue("--error-format"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

const NO_FIELDS: &[FieldSpec] = &[];

const EXPLAIN_FIELDS: &[FieldSpec] = &[FieldSpec {
    id: "code",
    label: "Code",
    help: "Error code (e.g., E102)",
    required: true,
    kind: FieldKind::Text,
    arg: FieldArg::Positional,
    default_text: "",
    default_bool: false,
    default_choice: 0,
}];

const SET_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "name",
        label: "Name",
        help: "Secret id",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::Positional,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "input_mode",
        label: "Input Mode",
        help: "generate, value, or stdin",
        required: true,
        kind: FieldKind::Choice(SET_INPUT_MODE_CHOICES),
        arg: FieldArg::None,
        default_text: "",
        default_bool: false,
        default_choice: SET_INPUT_MODE_GENERATE_INDEX,
    },
    FieldSpec {
        id: "value",
        label: "Input Value",
        help: "Secret payload when mode=value or mode=stdin",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::None,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "ttl",
        label: "TTL Days",
        help: "--ttl value (optional)",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--ttl"),
        default_text: "1",
        default_bool: false,
        default_choice: 0,
    },
];

const GET_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "name",
        label: "Name",
        help: "Secret id",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::Positional,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "pipe_to",
        label: "Pipe To",
        help: "--pipe-to command",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--pipe-to"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "pipe_to_args",
        label: "Pipe To Args",
        help: "--pipe-to-args template",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--pipe-to-args"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

const ENV_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "name",
        label: "Name",
        help: "Secret id",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::Positional,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "var",
        label: "Variable",
        help: "Environment variable name",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::Positional,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

const REQUEST_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "name",
        label: "Name",
        help: "Secret id",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::Positional,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "reason",
        label: "Reason",
        help: "--reason text",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--reason"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "allowlist",
        label: "Allowlist",
        help: "--allowlist patterns",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--allowlist"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "blocklist",
        label: "Blocklist",
        help: "--blocklist patterns",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--blocklist"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

const REQUEST_ID_FIELD: &[FieldSpec] = &[FieldSpec {
    id: "request_id",
    label: "Request ID",
    help: "Request UUID",
    required: true,
    kind: FieldKind::Text,
    arg: FieldArg::Positional,
    default_text: "",
    default_bool: false,
    default_choice: 0,
}];

const LIST_FIELDS: &[FieldSpec] = &[FieldSpec {
    id: "pending",
    label: "Pending Only",
    help: "--pending",
    required: false,
    kind: FieldKind::Bool,
    arg: FieldArg::Flag("--pending"),
    default_text: "",
    default_bool: false,
    default_choice: 0,
}];

const SECRET_NAME_FIELD: &[FieldSpec] = &[FieldSpec {
    id: "name",
    label: "Name",
    help: "Secret id",
    required: true,
    kind: FieldKind::Text,
    arg: FieldArg::Positional,
    default_text: "",
    default_bool: false,
    default_choice: 0,
}];

const GRANT_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "name",
        label: "Name",
        help: "Secret id",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::Positional,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "to",
        label: "Grant To",
        help: "--to agent id",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--to"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

const AUDIT_FIELDS: &[FieldSpec] = &[FieldSpec {
    id: "limit",
    label: "Limit",
    help: "--limit (default 50)",
    required: false,
    kind: FieldKind::Text,
    arg: FieldArg::OptionValue("--limit"),
    default_text: "50",
    default_bool: false,
    default_choice: 0,
}];

const DAEMON_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "bind",
        label: "Bind",
        help: "--bind host:port",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--bind"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "check",
        label: "Check",
        help: "--check",
        required: false,
        kind: FieldKind::Bool,
        arg: FieldArg::Flag("--check"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "max_requests",
        label: "Max Requests",
        help: "--max-requests (testing)",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--max-requests"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

const VAULT_INIT_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "name",
        label: "Name",
        help: "Vault name",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::Positional,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "owner",
        label: "Owner",
        help: "--owner agent|human",
        required: true,
        kind: FieldKind::Choice(VAULT_OWNER_CHOICES),
        arg: FieldArg::OptionValue("--owner"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

const VAULT_MOUNT_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "name",
        label: "Name",
        help: "Vault name",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::Positional,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "ttl",
        label: "TTL",
        help: "--ttl (e.g., 1h)",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--ttl"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "mountpoint",
        label: "Mountpoint",
        help: "--mountpoint path",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--mountpoint"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "agent",
        label: "Mount Agent",
        help: "--agent for vault subcommand",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--agent"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

const VAULT_EXEC_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "name",
        label: "Name",
        help: "Vault name",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::Positional,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "ttl",
        label: "TTL",
        help: "--ttl (e.g., 1h)",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--ttl"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "mountpoint",
        label: "Mountpoint",
        help: "--mountpoint path",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--mountpoint"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "agent",
        label: "Exec Agent",
        help: "--agent for vault subcommand",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--agent"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "command_line",
        label: "Command Line",
        help: "Command after -- (shell words)",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::None,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

const VAULT_UNMOUNT_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "name",
        label: "Name",
        help: "Vault name",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::Positional,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "agent",
        label: "Unmount Agent",
        help: "--agent for vault subcommand",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--agent"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

const VAULT_ASK_FILE_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "name",
        label: "Name",
        help: "Vault name",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::Positional,
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "file",
        label: "File",
        help: "--file relative path",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--file"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "requester",
        label: "Requester",
        help: "--requester agent id",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--requester"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "trusted_agent",
        label: "Trusted Agent",
        help: "--trusted-agent agent id",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--trusted-agent"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "reason",
        label: "Reason",
        help: "--reason text",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--reason"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

const ACCESS_PATHS_FIELDS: &[FieldSpec] = &[FieldSpec {
    id: "agent",
    label: "Agent",
    help: "--agent id",
    required: true,
    kind: FieldKind::Text,
    arg: FieldArg::OptionValue("--agent"),
    default_text: "",
    default_bool: false,
    default_choice: 0,
}];

const COMMAND_SPECS: &[CommandSpec] = &[
    CommandSpec {
        id: "init",
        title: "init",
        summary: "Initialize runtime layout",
        path: &["init"],
        fields: NO_FIELDS,
    },
    CommandSpec {
        id: "explain",
        title: "explain",
        summary: "Explain a stable error code",
        path: &["explain"],
        fields: EXPLAIN_FIELDS,
    },
    CommandSpec {
        id: "set",
        title: "secrets set",
        summary: "Store an agent secret",
        path: &["secrets", "set"],
        fields: SET_FIELDS,
    },
    CommandSpec {
        id: "get",
        title: "secrets get",
        summary: "Read a secret",
        path: &["secrets", "get"],
        fields: GET_FIELDS,
    },
    CommandSpec {
        id: "env",
        title: "env",
        summary: "Print redacted export",
        path: &["env"],
        fields: ENV_FIELDS,
    },
    CommandSpec {
        id: "request",
        title: "request",
        summary: "Create pending human request",
        path: &["request"],
        fields: REQUEST_FIELDS,
    },
    CommandSpec {
        id: "requests_list",
        title: "requests list",
        summary: "List pending requests",
        path: &["requests", "list"],
        fields: NO_FIELDS,
    },
    CommandSpec {
        id: "requests_approve",
        title: "requests approve",
        summary: "Approve pending request",
        path: &["requests", "approve"],
        fields: REQUEST_ID_FIELD,
    },
    CommandSpec {
        id: "requests_deny",
        title: "requests deny",
        summary: "Deny pending request",
        path: &["requests", "deny"],
        fields: REQUEST_ID_FIELD,
    },
    CommandSpec {
        id: "list",
        title: "list",
        summary: "List all entries",
        path: &["list"],
        fields: LIST_FIELDS,
    },
    CommandSpec {
        id: "grant",
        title: "secrets grant",
        summary: "Grant secret access to an agent",
        path: &["secrets", "grant"],
        fields: GRANT_FIELDS,
    },
    CommandSpec {
        id: "revoke",
        title: "secrets revoke",
        summary: "Revoke a secret",
        path: &["secrets", "revoke"],
        fields: SECRET_NAME_FIELD,
    },
    CommandSpec {
        id: "status",
        title: "secrets status",
        summary: "Show request status",
        path: &["secrets", "status"],
        fields: SECRET_NAME_FIELD,
    },
    CommandSpec {
        id: "audit",
        title: "audit",
        summary: "View audit events",
        path: &["audit"],
        fields: AUDIT_FIELDS,
    },
    CommandSpec {
        id: "verify",
        title: "verify",
        summary: "Verify/reap runtime state",
        path: &["verify"],
        fields: NO_FIELDS,
    },
    CommandSpec {
        id: "daemon",
        title: "daemon",
        summary: "Run local sidecar daemon",
        path: &["daemon"],
        fields: DAEMON_FIELDS,
    },
    CommandSpec {
        id: "vault_init",
        title: "vault init",
        summary: "Initialize encrypted vault",
        path: &["vault", "init"],
        fields: VAULT_INIT_FIELDS,
    },
    CommandSpec {
        id: "vault_mount",
        title: "vault mount",
        summary: "Mount vault with TTL",
        path: &["vault", "mount"],
        fields: VAULT_MOUNT_FIELDS,
    },
    CommandSpec {
        id: "vault_exec",
        title: "vault exec",
        summary: "Mount, execute, unmount",
        path: &["vault", "exec"],
        fields: VAULT_EXEC_FIELDS,
    },
    CommandSpec {
        id: "vault_unmount",
        title: "vault unmount",
        summary: "Unmount vault",
        path: &["vault", "unmount"],
        fields: VAULT_UNMOUNT_FIELDS,
    },
    CommandSpec {
        id: "vault_status",
        title: "vault status",
        summary: "Show vault session status",
        path: &["vault", "status"],
        fields: NO_FIELDS,
    },
    CommandSpec {
        id: "vault_list",
        title: "vault list",
        summary: "List configured vaults",
        path: &["vault", "list"],
        fields: NO_FIELDS,
    },
    CommandSpec {
        id: "vault_ask_file",
        title: "vault ask-file",
        summary: "Generate trusted handoff prompt",
        path: &["vault", "ask-file"],
        fields: VAULT_ASK_FILE_FIELDS,
    },
    CommandSpec {
        id: "config_validate",
        title: "config validate",
        summary: "Validate effective config",
        path: &["config", "validate"],
        fields: NO_FIELDS,
    },
    CommandSpec {
        id: "access_paths",
        title: "access paths",
        summary: "Show agent path visibility",
        path: &["access", "paths"],
        fields: ACCESS_PATHS_FIELDS,
    },
    CommandSpec {
        id: "gpg_create",
        title: "gpg create",
        summary: "Create agent GPG key",
        path: &["gpg", "create"],
        fields: NO_FIELDS,
    },
    CommandSpec {
        id: "gpg_fingerprint",
        title: "gpg fingerprint",
        summary: "Print agent key fingerprint",
        path: &["gpg", "fingerprint"],
        fields: NO_FIELDS,
    },
];

const SAFE_COMMAND_IDS: &[&str] = &[
    "explain",
    "get",
    "env",
    "requests_list",
    "list",
    "status",
    "audit",
    "vault_status",
    "vault_list",
    "config_validate",
    "access_paths",
    "gpg_fingerprint",
];
const ENTRIES_LIST_TREE_PATH: &[&str] = &["entries", "list"];
const SECRETS_SET_TREE_PATH: &[&str] = &["secrets", "set"];
const SECRETS_GET_TREE_PATH: &[&str] = &["secrets", "get"];
const SECRETS_GRANT_TREE_PATH: &[&str] = &["secrets", "grant"];
const SECRETS_REVOKE_TREE_PATH: &[&str] = &["secrets", "revoke"];
const SECRETS_STATUS_TREE_PATH: &[&str] = &["secrets", "status"];

fn command_tree_path(command_spec: &CommandSpec) -> Option<&'static [&'static str]> {
    match command_spec.id {
        "list" => Some(ENTRIES_LIST_TREE_PATH),
        "set" => Some(SECRETS_SET_TREE_PATH),
        "get" => Some(SECRETS_GET_TREE_PATH),
        "grant" => Some(SECRETS_GRANT_TREE_PATH),
        "revoke" => Some(SECRETS_REVOKE_TREE_PATH),
        "status" => Some(SECRETS_STATUS_TREE_PATH),
        _ => Some(command_spec.path),
    }
}

fn visible_tree_leaf_count() -> usize {
    COMMAND_SPECS
        .iter()
        .filter(|command_spec| command_tree_path(command_spec).is_some())
        .count()
}

fn command_spec_matches_query(spec: &CommandSpec, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    spec.title.to_ascii_lowercase().contains(query)
        || spec.summary.to_ascii_lowercase().contains(query)
        || spec
            .path
            .iter()
            .any(|segment| segment.to_ascii_lowercase().contains(query))
        || command_tree_path(spec).is_some_and(|path| {
            path.iter()
                .any(|segment| segment.to_ascii_lowercase().contains(query))
        })
}

fn normalize_launch_command_args(args: &[String]) -> Vec<String> {
    if args.is_empty() {
        return Vec::new();
    }

    let mut normalized = args.to_vec();
    match normalized[0].as_str() {
        "req" => {
            normalized[0] = "requests".to_owned();
        }
        "ls" => {
            normalized[0] = "list".to_owned();
        }
        "approve" => {
            normalized[0] = "requests".to_owned();
            normalized.insert(1, "approve".to_owned());
        }
        "deny" => {
            normalized[0] = "requests".to_owned();
            normalized.insert(1, "deny".to_owned());
        }
        "set" | "get" | "grant" | "revoke" | "status" => {
            normalized.insert(0, "secrets".to_owned());
        }
        _ => {}
    }
    normalized
}

fn resolve_launch_command_spec(args: &[String]) -> Option<(usize, usize)> {
    let mut best_match: Option<(usize, usize)> = None;
    for (command_index, command_spec) in COMMAND_SPECS.iter().enumerate() {
        if args.len() < command_spec.path.len() {
            continue;
        }
        let matches_path = command_spec
            .path
            .iter()
            .zip(args.iter())
            .all(|(path_segment, argument)| *path_segment == argument.as_str());
        if !matches_path {
            continue;
        }
        match best_match {
            Some((_, matched_segments)) if matched_segments >= command_spec.path.len() => {}
            _ => {
                best_match = Some((command_index, command_spec.path.len()));
            }
        }
    }
    best_match
}

fn split_long_option_token(token: &str) -> (&str, Option<&str>) {
    if let Some((flag, value)) = token.split_once('=') {
        (flag, Some(value))
    } else {
        (token, None)
    }
}

fn child_node_mut<'a>(
    children: &'a mut [CommandTreeNode],
    label: &str,
) -> Option<&'a mut CommandTreeNode> {
    children.iter_mut().find(|node| node.label == label)
}

fn insert_command_path(
    nodes: &mut Vec<CommandTreeNode>,
    path: &[&'static str],
    command_index: usize,
    parent_key: Option<&str>,
) {
    let Some((segment, rest)) = path.split_first() else {
        return;
    };
    let key = parent_key
        .map(|value| format!("{value}/{segment}"))
        .unwrap_or_else(|| (*segment).to_owned());
    let parent_key_owned = parent_key.map(ToOwned::to_owned);

    if child_node_mut(nodes.as_mut_slice(), segment).is_none() {
        nodes.push(CommandTreeNode {
            label: (*segment).to_owned(),
            key: key.clone(),
            parent_key: parent_key_owned,
            children: Vec::new(),
            command_index: None,
        });
    }

    if let Some(node) = child_node_mut(nodes.as_mut_slice(), segment) {
        if rest.is_empty() {
            node.command_index = Some(command_index);
            return;
        }
        insert_command_path(&mut node.children, rest, command_index, Some(&key));
    }
}

fn build_command_tree() -> Vec<CommandTreeNode> {
    let mut nodes = Vec::new();
    for (index, command_spec) in COMMAND_SPECS.iter().enumerate() {
        if let Some(tree_path) = command_tree_path(command_spec) {
            insert_command_path(&mut nodes, tree_path, index, None);
        }
    }
    nodes
}

fn default_expanded_command_paths() -> HashSet<String> {
    build_command_tree()
        .into_iter()
        .filter(|node| !node.children.is_empty())
        .map(|node| node.key)
        .collect()
}

fn node_matches_query(node: &CommandTreeNode, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    if node.label.to_ascii_lowercase().contains(query) {
        return true;
    }
    if let Some(command_index) = node.command_index {
        if let Some(spec) = COMMAND_SPECS.get(command_index) {
            if command_spec_matches_query(spec, query) {
                return true;
            }
        }
    }
    node.children
        .iter()
        .any(|child| node_matches_query(child, query))
}

fn append_tree_rows(
    node: &CommandTreeNode,
    query: &str,
    expanded_paths: &HashSet<String>,
    depth: usize,
    rows: &mut Vec<CommandTreeRow>,
) {
    if !node_matches_query(node, query) {
        return;
    }
    let is_branch = !node.children.is_empty();
    let is_expanded = if query.is_empty() {
        expanded_paths.contains(&node.key)
    } else {
        true
    };
    rows.push(CommandTreeRow {
        key: node.key.clone(),
        parent_key: node.parent_key.clone(),
        depth,
        label: node.label.clone(),
        command_index: node.command_index,
        is_expanded,
        is_branch,
    });
    if is_branch && is_expanded {
        for child in &node.children {
            append_tree_rows(child, query, expanded_paths, depth + 1, rows);
        }
    }
}

pub(crate) fn run_command_navigator(launch_options: NavigatorLaunchOptions) -> Result<()> {
    if !atty::is(atty::Stream::Stdin) || !atty::is(atty::Stream::Stdout) {
        return Err(GlovesError::InvalidInput(
            "`gloves tui` requires an interactive terminal".to_owned(),
        ));
    }

    let mut terminal = init_terminal()?;
    let run_result = run_event_loop(&mut terminal, launch_options);
    let restore_result = restore_terminal(&mut terminal);
    restore_result?;
    run_result
}

fn init_terminal() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    launch_options: NavigatorLaunchOptions,
) -> Result<()> {
    let mut app = TuiApp::new(launch_options);
    app.execute_startup_command_if_needed()?;
    while !app.should_quit {
        app.poll_active_run();
        terminal.draw(|frame| app.render(frame))?;
        if !event::poll(Duration::from_millis(NAVIGATOR_EVENT_POLL_MILLIS))? {
            continue;
        }
        let event = event::read()?;
        let terminal_size = terminal.size()?;
        let terminal_area = Rect::new(0, 0, terminal_size.width, terminal_size.height);
        match event {
            Event::Key(key) => {
                app.on_key(key)?;
            }
            Event::Mouse(mouse) => {
                app.on_mouse(mouse, terminal_area);
            }
            _ => {}
        }
    }
    Ok(())
}

impl TuiApp {
    fn new(launch_options: NavigatorLaunchOptions) -> Self {
        let selected_command_index = 0;
        let command_fields = field_states_for_spec(&COMMAND_SPECS[selected_command_index]);
        let mut app = Self {
            selected_command_index,
            selected_command_tree_row: 0,
            selected_global_field_index: 0,
            selected_command_field_index: 0,
            expanded_command_tree_paths: default_expanded_command_paths(),
            command_filter: String::new(),
            focus: FocusPane::Commands,
            input_mode: InputMode::Navigate,
            editing_target: None,
            editing_buffer: String::new(),
            editing_original_buffer: String::new(),
            global_fields: GLOBAL_FIELDS.iter().map(initial_field_state).collect(),
            command_fields,
            run_history: Vec::new(),
            next_run_id: 1,
            active_run: None,
            output_scroll: 0,
            output_viewport_height: 0,
            command_viewport_width: 1,
            globals_viewport_width: 1,
            fields_viewport_width: 1,
            output_viewport_width: 1,
            command_horizontal_scroll: 0,
            globals_horizontal_scroll: 0,
            fields_horizontal_scroll: 0,
            output_horizontal_scroll: 0,
            follow_tail: true,
            fullscreen_enabled: false,
            status_line: "Ready".to_owned(),
            pending_risky_signature: None,
            startup_command_pending: false,
            should_quit: false,
        };
        app.select_first_visible_leaf();
        app.apply_launch_options(launch_options);
        app
    }

    fn apply_launch_options(&mut self, launch_options: NavigatorLaunchOptions) {
        if let Some(root) = launch_options.root {
            self.set_global_text("root", root);
        }
        if let Some(agent) = launch_options.agent {
            self.set_global_text("agent", agent);
        }
        if let Some(config) = launch_options.config {
            self.set_global_text("config", config);
        }
        if launch_options.no_config {
            self.set_global_bool("no_config", true);
        }
        if let Some(vault_mode) = launch_options.vault_mode {
            self.set_global_choice_by_value("vault_mode", &vault_mode);
        }
        if let Some(error_format) = launch_options.error_format {
            self.set_global_choice_by_value("error_format", &error_format);
        }
        self.startup_command_pending = !launch_options.command_args.is_empty()
            && self.apply_launch_command_args(&launch_options.command_args);
    }

    fn set_global_text(&mut self, field_id: &str, value: String) {
        if let Some(field) = self
            .global_fields
            .iter_mut()
            .find(|field| field.spec.id == field_id)
        {
            if let FieldValue::Text(current) = &mut field.value {
                *current = value;
            }
        }
    }

    fn set_global_bool(&mut self, field_id: &str, value: bool) {
        if let Some(field) = self
            .global_fields
            .iter_mut()
            .find(|field| field.spec.id == field_id)
        {
            if let FieldValue::Bool(current) = &mut field.value {
                *current = value;
            }
        }
    }

    fn set_global_choice_by_value(&mut self, field_id: &str, value: &str) {
        if let Some(field) = self
            .global_fields
            .iter_mut()
            .find(|field| field.spec.id == field_id)
        {
            if let (FieldKind::Choice(choices), FieldValue::Choice(choice_index)) =
                (field.spec.kind, &mut field.value)
            {
                if let Some(index) = choices.iter().position(|choice| *choice == value) {
                    *choice_index = index;
                }
            }
        }
    }

    fn set_command_text(&mut self, field_id: &str, value: String) {
        if let Some(field) = self
            .command_fields
            .iter_mut()
            .find(|field| field.spec.id == field_id)
        {
            if let FieldValue::Text(current) = &mut field.value {
                *current = value;
            }
        }
    }

    fn set_command_choice_by_value(&mut self, field_id: &str, value: &str) {
        if let Some(field) = self
            .command_fields
            .iter_mut()
            .find(|field| field.spec.id == field_id)
        {
            if let (FieldKind::Choice(choices), FieldValue::Choice(choice_index)) =
                (field.spec.kind, &mut field.value)
            {
                if let Some(index) = choices.iter().position(|choice| *choice == value) {
                    *choice_index = index;
                }
            }
        }
    }

    fn apply_launch_command_args(&mut self, args: &[String]) -> bool {
        let normalized_args = normalize_launch_command_args(args);
        let Some((command_index, consumed_path_segments)) =
            resolve_launch_command_spec(&normalized_args)
        else {
            self.status_line = format!(
                "TUI startup command not found: {}",
                format_invocation_args(&normalized_args)
            );
            return false;
        };

        self.select_command_by_index(command_index);
        self.align_tree_selection_to_command(command_index);

        let command_args = &normalized_args[consumed_path_segments..];
        match self.populate_selected_command_fields_from_args(command_args) {
            Ok(()) => {
                if command_args.is_empty() {
                    self.status_line = format!(
                        "Loaded `{}` from TUI startup arguments",
                        self.selected_command_spec().title
                    );
                } else {
                    self.status_line = format!(
                        "Loaded `{}` with startup values",
                        self.selected_command_spec().title
                    );
                }
                true
            }
            Err(error_message) => {
                self.status_line = format!(
                    "Loaded `{}` (startup parse note: {error_message})",
                    self.selected_command_spec().title
                );
                false
            }
        }
    }

    fn execute_startup_command_if_needed(&mut self) -> Result<()> {
        if !self.startup_command_pending {
            return Ok(());
        }
        self.startup_command_pending = false;
        self.focus = FocusPane::Output;
        self.fullscreen_enabled = true;
        self.follow_tail = true;
        self.sync_output_scroll();
        self.execute_selected_command_with_policy(true)
    }

    fn align_tree_selection_to_command(&mut self, command_index: usize) {
        let rows = self.command_tree_rows();
        if let Some(row_index) = rows
            .iter()
            .position(|row| row.command_index == Some(command_index))
        {
            self.selected_command_tree_row = row_index;
            self.reconcile_tree_selection();
        }
    }

    fn populate_selected_command_fields_from_args(
        &mut self,
        args: &[String],
    ) -> std::result::Result<(), String> {
        match self.selected_command_spec().id {
            "set" => self.populate_set_fields_from_args(args),
            "vault_exec" => self.populate_vault_exec_fields_from_args(args),
            _ => self.populate_generic_fields_from_args(args),
        }
    }

    fn populate_set_fields_from_args(
        &mut self,
        args: &[String],
    ) -> std::result::Result<(), String> {
        if args.is_empty() {
            return Ok(());
        }
        if args[0].starts_with("--") {
            return Err("missing secret name".to_owned());
        }
        self.set_command_text("name", args[0].clone());

        let mut index = 1;
        while index < args.len() {
            let token = &args[index];
            if token == "--" {
                return Err("unexpected `--` for secrets set".to_owned());
            }
            if !token.starts_with("--") {
                return Err(format!("unexpected argument `{token}`"));
            }
            let (flag, inline_value) = split_long_option_token(token);
            match flag {
                "--generate" => {
                    if inline_value.is_some() {
                        return Err("`--generate` does not take a value".to_owned());
                    }
                    self.set_command_choice_by_value("input_mode", "generate");
                }
                "--stdin" => {
                    if inline_value.is_some() {
                        return Err("`--stdin` does not take a value".to_owned());
                    }
                    self.set_command_choice_by_value("input_mode", "stdin");
                }
                "--value" => {
                    let value = if let Some(value) = inline_value {
                        value.to_owned()
                    } else {
                        let Some(next_value) = args.get(index + 1) else {
                            return Err("`--value` requires a value".to_owned());
                        };
                        index += 1;
                        next_value.to_owned()
                    };
                    self.set_command_choice_by_value("input_mode", "value");
                    self.set_command_text("value", value);
                }
                "--ttl" => {
                    let value = if let Some(value) = inline_value {
                        value.to_owned()
                    } else {
                        let Some(next_value) = args.get(index + 1) else {
                            return Err("`--ttl` requires a value".to_owned());
                        };
                        index += 1;
                        next_value.to_owned()
                    };
                    self.set_command_text("ttl", value);
                }
                _ => {
                    return Err(format!("unknown option `{flag}`"));
                }
            }
            index += 1;
        }
        Ok(())
    }

    fn populate_vault_exec_fields_from_args(
        &mut self,
        args: &[String],
    ) -> std::result::Result<(), String> {
        let mut index = 0;
        let mut command_start_index = None;
        let mut name_set = false;

        while index < args.len() {
            let token = &args[index];
            if token == "--" {
                command_start_index = Some(index + 1);
                break;
            }
            if token.starts_with("--") {
                let (flag, inline_value) = split_long_option_token(token);
                let value = if let Some(value) = inline_value {
                    value.to_owned()
                } else {
                    let Some(next_value) = args.get(index + 1) else {
                        return Err(format!("`{flag}` requires a value"));
                    };
                    index += 1;
                    next_value.to_owned()
                };
                match flag {
                    "--ttl" => self.set_command_text("ttl", value),
                    "--mountpoint" => self.set_command_text("mountpoint", value),
                    "--agent" => self.set_command_text("agent", value),
                    _ => return Err(format!("unknown option `{flag}`")),
                }
            } else if !name_set {
                self.set_command_text("name", token.clone());
                name_set = true;
            } else {
                return Err(format!(
                    "unexpected argument `{token}` (expected `--` before command)"
                ));
            }
            index += 1;
        }

        if let Some(command_index) = command_start_index {
            let tail = &args[command_index..];
            if !tail.is_empty() {
                self.set_command_text("command_line", format_invocation_args(tail));
            }
        }
        Ok(())
    }

    fn populate_generic_fields_from_args(
        &mut self,
        args: &[String],
    ) -> std::result::Result<(), String> {
        let positional_field_indices = self
            .command_fields
            .iter()
            .enumerate()
            .filter_map(|(index, field)| {
                matches!(field.spec.arg, FieldArg::Positional).then_some(index)
            })
            .collect::<Vec<_>>();

        let mut positional_cursor = 0usize;
        let mut index = 0usize;

        while index < args.len() {
            let token = &args[index];
            if token.starts_with("--") {
                let (flag, inline_value) = split_long_option_token(token);
                if let Some(field_index) = self.command_fields.iter().position(|field| {
                    matches!(field.spec.arg, FieldArg::Flag(candidate) if candidate == flag)
                }) {
                    if inline_value.is_some() {
                        return Err(format!("`{flag}` does not take a value"));
                    }
                    if let Some(FieldState {
                        value: FieldValue::Bool(current),
                        ..
                    }) = self.command_fields.get_mut(field_index)
                    {
                        *current = true;
                    }
                    index += 1;
                    continue;
                }
                if let Some(field_index) = self.command_fields.iter().position(|field| {
                    matches!(field.spec.arg, FieldArg::OptionValue(candidate) if candidate == flag)
                }) {
                    let value = if let Some(value) = inline_value {
                        value.to_owned()
                    } else {
                        let Some(next_value) = args.get(index + 1) else {
                            return Err(format!("`{flag}` requires a value"));
                        };
                        index += 1;
                        next_value.to_owned()
                    };
                    self.assign_command_field_literal(field_index, &value)?;
                    index += 1;
                    continue;
                }
                return Err(format!("unknown option `{flag}`"));
            }

            if positional_cursor >= positional_field_indices.len() {
                return Err(format!("unexpected argument `{token}`"));
            }
            let field_index = positional_field_indices[positional_cursor];
            self.assign_command_field_literal(field_index, token)?;
            positional_cursor += 1;
            index += 1;
        }

        Ok(())
    }

    fn assign_command_field_literal(
        &mut self,
        field_index: usize,
        literal: &str,
    ) -> std::result::Result<(), String> {
        let Some(field) = self.command_fields.get_mut(field_index) else {
            return Err("internal error: field index out of bounds".to_owned());
        };
        match (&field.spec.kind, &mut field.value) {
            (FieldKind::Text, FieldValue::Text(current)) => {
                *current = literal.to_owned();
            }
            (FieldKind::Choice(choices), FieldValue::Choice(choice_index)) => {
                let Some(index) = choices.iter().position(|choice| *choice == literal) else {
                    return Err(format!(
                        "invalid value `{literal}` for `{}`",
                        field.spec.label
                    ));
                };
                *choice_index = index;
            }
            (FieldKind::Bool, FieldValue::Bool(current)) => {
                *current = matches!(literal, "1" | "true" | "on" | "yes");
            }
            _ => {
                return Err(format!(
                    "unable to set `{}` from startup args",
                    field.spec.label
                ));
            }
        }
        Ok(())
    }

    fn selected_command_spec(&self) -> &'static CommandSpec {
        &COMMAND_SPECS[self
            .selected_command_index
            .min(COMMAND_SPECS.len().saturating_sub(1))]
    }

    fn command_tree_rows(&self) -> Vec<CommandTreeRow> {
        let query = self.command_filter.trim().to_ascii_lowercase();
        let mut rows = Vec::new();
        for node in build_command_tree() {
            append_tree_rows(
                &node,
                &query,
                &self.expanded_command_tree_paths,
                0,
                &mut rows,
            );
        }
        rows
    }

    fn selected_tree_row<'a>(&self, rows: &'a [CommandTreeRow]) -> Option<&'a CommandTreeRow> {
        rows.get(self.selected_command_tree_row)
    }

    fn selected_command_index_from_tree(&self) -> Option<usize> {
        let rows = self.command_tree_rows();
        self.selected_tree_row(&rows)
            .and_then(|row| row.command_index)
    }

    fn select_first_visible_leaf(&mut self) {
        let rows = self.command_tree_rows();
        if rows.is_empty() {
            self.selected_command_tree_row = 0;
            self.command_fields.clear();
            self.selected_command_field_index = 0;
            self.status_line = EMPTY_FILTER_PLACEHOLDER.to_owned();
            return;
        }
        let first_leaf_row = rows
            .iter()
            .position(|row| row.command_index.is_some())
            .unwrap_or(0);
        self.selected_command_tree_row = first_leaf_row;
        if let Some(command_index) = rows[first_leaf_row].command_index {
            self.select_command_by_index(command_index);
        }
    }

    fn reconcile_tree_selection(&mut self) {
        let rows = self.command_tree_rows();
        if rows.is_empty() {
            self.selected_command_tree_row = 0;
            self.command_fields.clear();
            self.selected_command_field_index = 0;
            self.status_line = EMPTY_FILTER_PLACEHOLDER.to_owned();
            self.clear_pending_confirmation();
            return;
        }
        if self.selected_command_tree_row >= rows.len() {
            self.selected_command_tree_row = rows.len() - 1;
        }
        if let Some(command_index) = rows[self.selected_command_tree_row].command_index {
            self.select_command_by_index(command_index);
        }
    }

    fn select_command_by_index(&mut self, command_index: usize) {
        if command_index >= COMMAND_SPECS.len() {
            return;
        }
        if self.selected_command_index == command_index && !self.command_fields.is_empty() {
            return;
        }
        self.selected_command_index = command_index;
        self.reload_selected_command_fields();
    }

    fn clear_pending_confirmation(&mut self) {
        self.pending_risky_signature = None;
    }

    fn on_key(&mut self, key: KeyEvent) -> Result<()> {
        if key.kind != KeyEventKind::Press {
            return Ok(());
        }
        if self.input_mode == InputMode::Edit {
            self.on_edit_key(key);
            return Ok(());
        }

        match key.code {
            KeyCode::Left if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.scroll_horizontal_for_focus(false);
            }
            KeyCode::Right if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.scroll_horizontal_for_focus(true);
            }
            KeyCode::Esc => {
                if self.fullscreen_enabled {
                    self.fullscreen_enabled = false;
                    self.focus = FocusPane::Commands;
                    self.status_line =
                        "Fullscreen disabled; focus reset to command tree".to_owned();
                } else if self.active_run.is_some() {
                    self.status_line =
                        "Run in progress. Press Ctrl+C to cancel before quitting.".to_owned();
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Char('q') => {
                if self.active_run.is_some() {
                    self.status_line =
                        "Run in progress. Press Ctrl+C to cancel before quitting.".to_owned();
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Tab => {
                self.focus = self.focus.next();
            }
            KeyCode::BackTab => {
                self.focus = self.focus.previous();
            }
            KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                if self.active_run.is_some() {
                    self.cancel_active_run();
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Char('c') => {
                self.run_history.clear();
                self.output_scroll = 0;
                self.follow_tail = true;
                self.status_line = "Output cleared".to_owned();
            }
            KeyCode::Char('/') => {
                self.input_mode = InputMode::Edit;
                self.editing_target = Some(EditingTarget::CommandFilter);
                self.editing_buffer = self.command_filter.clone();
                self.editing_original_buffer = self.command_filter.clone();
                self.status_line = "Editing command filter".to_owned();
            }
            KeyCode::Char('f') if key.modifiers.is_empty() => {
                self.toggle_fullscreen();
            }
            KeyCode::Char('o') | KeyCode::Char('O')
                if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
            {
                self.focus = FocusPane::Output;
                self.status_line = "Focus -> execution output".to_owned();
            }
            KeyCode::Char('?') => {
                self.execute_selected_help()?;
            }
            KeyCode::Enter if key.modifiers.is_empty() => {
                if self.fullscreen_enabled {
                    self.on_enter_fullscreen()?;
                } else {
                    self.on_enter_cycle()?;
                }
            }
            KeyCode::Char('x') => {
                self.reset_selected_field(false);
            }
            KeyCode::Char('X') => {
                self.reset_selected_field(true);
            }
            KeyCode::Char('r') | KeyCode::F(5)
                if key.modifiers.is_empty() || key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.execute_selected_command()?;
            }
            _ => {
                self.on_navigation_key(key);
            }
        }
        Ok(())
    }

    fn on_mouse(&mut self, mouse: MouseEvent, terminal_area: Rect) {
        let Some(target_pane) = self.mouse_target_pane(mouse.column, mouse.row, terminal_area)
        else {
            return;
        };

        match mouse.kind {
            MouseEventKind::ScrollLeft => {
                self.scroll_horizontal_for_pane(target_pane, false);
            }
            MouseEventKind::ScrollRight => {
                self.scroll_horizontal_for_pane(target_pane, true);
            }
            MouseEventKind::ScrollUp if mouse.modifiers.contains(KeyModifiers::SHIFT) => {
                self.scroll_horizontal_for_pane(target_pane, false);
            }
            MouseEventKind::ScrollDown if mouse.modifiers.contains(KeyModifiers::SHIFT) => {
                self.scroll_horizontal_for_pane(target_pane, true);
            }
            MouseEventKind::ScrollUp if target_pane == FocusPane::Commands => {
                self.scroll_command_tree(false);
            }
            MouseEventKind::ScrollDown if target_pane == FocusPane::Commands => {
                self.scroll_command_tree(true);
            }
            MouseEventKind::ScrollUp if target_pane == FocusPane::Output => {
                self.on_output_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
            }
            MouseEventKind::ScrollDown if target_pane == FocusPane::Output => {
                self.on_output_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
            }
            _ => {}
        }
    }

    fn mouse_target_pane(&self, column: u16, row: u16, terminal_area: Rect) -> Option<FocusPane> {
        let root_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(UI_HEADER_HEIGHT),
                Constraint::Min(1),
                Constraint::Length(UI_FOOTER_HEIGHT),
            ])
            .split(terminal_area);
        let body_area = root_chunks[1];
        if !rect_contains_point(body_area, column, row) {
            return None;
        }

        if self.fullscreen_enabled {
            return Some(self.focus);
        }

        let body_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(28),
                Constraint::Percentage(32),
                Constraint::Percentage(40),
            ])
            .split(body_area);
        if rect_contains_point(body_chunks[0], column, row) {
            return Some(FocusPane::Commands);
        }
        if rect_contains_point(body_chunks[2], column, row) {
            return Some(FocusPane::Output);
        }
        if !rect_contains_point(body_chunks[1], column, row) {
            return None;
        }

        let form_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(body_chunks[1]);
        if rect_contains_point(form_chunks[0], column, row) {
            return Some(FocusPane::Globals);
        }
        if rect_contains_point(form_chunks[1], column, row) {
            return Some(FocusPane::Fields);
        }

        None
    }

    fn scroll_horizontal_for_focus(&mut self, forward: bool) {
        self.scroll_horizontal_for_pane(self.focus, forward);
    }

    fn scroll_command_tree(&mut self, forward: bool) {
        let rows = self.command_tree_rows();
        if rows.is_empty() {
            self.status_line = EMPTY_FILTER_PLACEHOLDER.to_owned();
            return;
        }
        if self.selected_command_tree_row >= rows.len() {
            self.selected_command_tree_row = rows.len() - 1;
        }
        if forward {
            self.selected_command_tree_row =
                (self.selected_command_tree_row + 1).min(rows.len().saturating_sub(1));
        } else {
            self.selected_command_tree_row = self.selected_command_tree_row.saturating_sub(1);
        }
        self.reconcile_tree_selection();
    }

    fn pane_scroll_mut(&mut self, pane: FocusPane) -> &mut u16 {
        match pane {
            FocusPane::Commands => &mut self.command_horizontal_scroll,
            FocusPane::Globals => &mut self.globals_horizontal_scroll,
            FocusPane::Fields => &mut self.fields_horizontal_scroll,
            FocusPane::Output => &mut self.output_horizontal_scroll,
        }
    }

    fn pane_viewport_width(&self, pane: FocusPane) -> usize {
        let width = match pane {
            FocusPane::Commands => self.command_viewport_width,
            FocusPane::Globals => self.globals_viewport_width,
            FocusPane::Fields => self.fields_viewport_width,
            FocusPane::Output => self.output_viewport_width,
        };
        usize::from(width).max(1)
    }

    fn pane_max_line_width(&self, pane: FocusPane) -> usize {
        match pane {
            FocusPane::Commands => {
                let rows = self.command_tree_rows();
                if rows.is_empty() {
                    return EMPTY_FILTER_PLACEHOLDER.chars().count();
                }
                rows.iter()
                    .map(|row| {
                        let indent = "  ".repeat(row.depth);
                        let marker = if row.is_branch {
                            if row.is_expanded {
                                "[-]"
                            } else {
                                "[+]"
                            }
                        } else {
                            " - "
                        };
                        let mut line = format!("{indent}{marker} ");
                        line.push_str(&row.label);
                        if let Some(command_index) = row.command_index {
                            if let Some(spec) = COMMAND_SPECS.get(command_index) {
                                line.push_str("  ");
                                line.push_str(spec.summary);
                            }
                        }
                        line.chars().count()
                    })
                    .max()
                    .unwrap_or(0)
            }
            FocusPane::Globals => self
                .global_fields
                .iter()
                .map(field_line_text)
                .map(|line| line.chars().count())
                .max()
                .unwrap_or(0),
            FocusPane::Fields => self
                .command_fields
                .iter()
                .map(field_line_text)
                .map(|line| line.chars().count())
                .max()
                .unwrap_or(0),
            FocusPane::Output => self
                .flatten_output_lines()
                .iter()
                .map(|line| line.chars().count())
                .max()
                .unwrap_or(0),
        }
    }

    fn max_horizontal_scroll_for_pane(&self, pane: FocusPane) -> u16 {
        let viewport_width = self.pane_viewport_width(pane);
        let max_line_width = self.pane_max_line_width(pane);
        max_line_width
            .saturating_sub(viewport_width)
            .min(u16::MAX as usize) as u16
    }

    fn clamp_all_horizontal_scrolls(&mut self) {
        for pane in [
            FocusPane::Commands,
            FocusPane::Globals,
            FocusPane::Fields,
            FocusPane::Output,
        ] {
            let max_scroll = self.max_horizontal_scroll_for_pane(pane);
            let scroll = self.pane_scroll_mut(pane);
            *scroll = (*scroll).min(max_scroll);
        }
    }

    fn scroll_horizontal_for_pane(&mut self, pane: FocusPane, forward: bool) {
        let max_scroll = self.max_horizontal_scroll_for_pane(pane);
        let scroll = self.pane_scroll_mut(pane);
        if forward {
            *scroll = scroll
                .saturating_add(HORIZONTAL_SCROLL_STEP)
                .min(max_scroll);
        } else {
            *scroll = scroll.saturating_sub(HORIZONTAL_SCROLL_STEP);
        }
        self.status_line = format!("Horizontal scroll {}: {}", pane.label(), *scroll);
    }

    fn on_navigation_key(&mut self, key: KeyEvent) {
        match self.focus {
            FocusPane::Commands => self.on_command_list_key(key),
            FocusPane::Globals => self.on_field_list_key(key, true),
            FocusPane::Fields => self.on_field_list_key(key, false),
            FocusPane::Output => self.on_output_key(key),
        }
    }

    fn on_enter_cycle(&mut self) -> Result<()> {
        match self.focus {
            FocusPane::Commands => {
                let rows = self.command_tree_rows();
                if rows.is_empty() {
                    self.status_line = EMPTY_FILTER_PLACEHOLDER.to_owned();
                    return Ok(());
                }
                if self.selected_command_tree_row >= rows.len() {
                    self.selected_command_tree_row = rows.len() - 1;
                }
                if let Some(row) = rows.get(self.selected_command_tree_row) {
                    if row.is_branch {
                        if row.is_expanded {
                            self.expanded_command_tree_paths.remove(&row.key);
                        } else {
                            self.expanded_command_tree_paths.insert(row.key.clone());
                        }
                        self.status_line = format!("Toggled group `{}`", row.label);
                        self.reconcile_tree_selection();
                        return Ok(());
                    }
                    if let Some(command_index) = row.command_index {
                        self.select_command_by_index(command_index);
                    }
                }
                self.focus = FocusPane::Globals;
                self.status_line = format!(
                    "Cycle -> global flags for `{}`",
                    self.selected_command_spec().title
                );
            }
            FocusPane::Globals => {
                if self.command_fields.is_empty() {
                    self.execute_selected_command()?;
                    self.focus = FocusPane::Commands;
                } else {
                    self.focus = FocusPane::Fields;
                    self.status_line = "Cycle -> command fields".to_owned();
                }
            }
            FocusPane::Fields => {
                self.execute_selected_command()?;
                self.focus = FocusPane::Commands;
            }
            FocusPane::Output => {
                self.focus = FocusPane::Commands;
                self.status_line = "Cycle reset to command tree".to_owned();
            }
        }
        Ok(())
    }

    fn on_enter_fullscreen(&mut self) -> Result<()> {
        match self.focus {
            FocusPane::Commands => {
                let rows = self.command_tree_rows();
                if rows.is_empty() {
                    self.status_line = EMPTY_FILTER_PLACEHOLDER.to_owned();
                    return Ok(());
                }
                if self.selected_command_tree_row >= rows.len() {
                    self.selected_command_tree_row = rows.len() - 1;
                }
                if let Some(row) = rows.get(self.selected_command_tree_row) {
                    if row.is_branch {
                        if row.is_expanded {
                            self.expanded_command_tree_paths.remove(&row.key);
                        } else {
                            self.expanded_command_tree_paths.insert(row.key.clone());
                        }
                        self.status_line = format!("Toggled group `{}`", row.label);
                    } else if let Some(command_index) = row.command_index {
                        self.select_command_by_index(command_index);
                        self.status_line =
                            format!("Selected `{}`", self.selected_command_spec().title);
                    }
                }
                self.reconcile_tree_selection();
            }
            FocusPane::Globals => {
                self.status_line =
                    "Fullscreen mode: Enter stays on globals; use Tab to switch panes".to_owned();
            }
            FocusPane::Fields => {
                self.execute_selected_command()?;
                self.status_line.push_str(" (fullscreen focus retained)");
            }
            FocusPane::Output => {
                self.status_line =
                    "Fullscreen mode: Enter stays on output; use Tab to switch panes".to_owned();
            }
        }
        Ok(())
    }

    fn toggle_fullscreen(&mut self) {
        self.fullscreen_enabled = !self.fullscreen_enabled;
        self.status_line = if self.fullscreen_enabled {
            format!("Fullscreen enabled for {} pane", self.focus.label())
        } else {
            "Fullscreen disabled".to_owned()
        };
    }

    fn on_edit_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.cancel_edit_buffer();
                if self.fullscreen_enabled {
                    self.fullscreen_enabled = false;
                    self.focus = FocusPane::Commands;
                    self.status_line =
                        "Fullscreen disabled; focus reset to command tree".to_owned();
                }
            }
            KeyCode::Enter => {
                self.commit_edit_buffer();
            }
            KeyCode::Backspace => {
                self.editing_buffer.pop();
                self.apply_live_edit_buffer();
            }
            KeyCode::Char(character) => {
                self.editing_buffer.push(character);
                self.apply_live_edit_buffer();
            }
            _ => {}
        }
    }

    fn cancel_edit_buffer(&mut self) {
        let Some(target) = self.editing_target else {
            return;
        };
        match target {
            EditingTarget::Global(index) => {
                if let Some(field_state) = self.global_fields.get_mut(index) {
                    field_state.value = FieldValue::Text(self.editing_original_buffer.clone());
                }
            }
            EditingTarget::Field(index) => {
                if let Some(field_state) = self.command_fields.get_mut(index) {
                    field_state.value = FieldValue::Text(self.editing_original_buffer.clone());
                }
            }
            EditingTarget::CommandFilter => {
                self.command_filter = self.editing_original_buffer.trim().to_owned();
                self.selected_command_tree_row = 0;
                self.reconcile_tree_selection();
            }
        }
        self.input_mode = InputMode::Navigate;
        self.editing_target = None;
        self.editing_buffer.clear();
        self.editing_original_buffer.clear();
        self.status_line = "Edit canceled".to_owned();
    }

    fn apply_live_edit_buffer(&mut self) {
        let Some(target) = self.editing_target else {
            return;
        };
        match target {
            EditingTarget::Global(index) => {
                if let Some(field_state) = self.global_fields.get_mut(index) {
                    field_state.value = FieldValue::Text(self.editing_buffer.clone());
                    self.clear_pending_confirmation();
                }
            }
            EditingTarget::Field(index) => {
                if let Some(field_state) = self.command_fields.get_mut(index) {
                    field_state.value = FieldValue::Text(self.editing_buffer.clone());
                    self.clear_pending_confirmation();
                }
            }
            EditingTarget::CommandFilter => {
                self.command_filter = self.editing_buffer.trim().to_owned();
                self.selected_command_tree_row = 0;
                self.reconcile_tree_selection();
                self.status_line = if self.command_filter.is_empty() {
                    "Filter cleared".to_owned()
                } else {
                    format!("Filter set: {}", self.command_filter)
                };
            }
        }
    }

    fn commit_edit_buffer(&mut self) {
        let Some(target) = self.editing_target else {
            return;
        };
        match target {
            EditingTarget::Global(index) => {
                if let Some(field_state) = self.global_fields.get_mut(index) {
                    field_state.value = FieldValue::Text(self.editing_buffer.clone());
                    self.clear_pending_confirmation();
                }
            }
            EditingTarget::Field(index) => {
                if let Some(field_state) = self.command_fields.get_mut(index) {
                    field_state.value = FieldValue::Text(self.editing_buffer.clone());
                    self.clear_pending_confirmation();
                }
            }
            EditingTarget::CommandFilter => {
                self.command_filter = self.editing_buffer.trim().to_owned();
                self.selected_command_tree_row = 0;
                self.reconcile_tree_selection();
                self.status_line = if self.command_filter.is_empty() {
                    "Filter cleared".to_owned()
                } else {
                    format!("Filter set: {}", self.command_filter)
                };
            }
        }
        self.input_mode = InputMode::Navigate;
        self.editing_target = None;
        self.editing_buffer.clear();
        self.editing_original_buffer.clear();
        if !matches!(target, EditingTarget::CommandFilter) {
            self.status_line = "Value updated".to_owned();
        }
    }

    fn on_command_list_key(&mut self, key: KeyEvent) {
        let rows = self.command_tree_rows();
        if rows.is_empty() {
            self.status_line = EMPTY_FILTER_PLACEHOLDER.to_owned();
            return;
        }
        if self.selected_command_tree_row >= rows.len() {
            self.selected_command_tree_row = rows.len() - 1;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected_command_tree_row = self.selected_command_tree_row.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected_command_tree_row =
                    (self.selected_command_tree_row + 1).min(rows.len().saturating_sub(1));
            }
            KeyCode::Right if self.fullscreen_enabled => {
                self.scroll_horizontal_for_focus(true);
            }
            KeyCode::Left if self.fullscreen_enabled => {
                self.scroll_horizontal_for_focus(false);
            }
            KeyCode::Right => {
                if let Some(row) = rows.get(self.selected_command_tree_row) {
                    if row.is_branch {
                        self.expanded_command_tree_paths.insert(row.key.clone());
                    }
                }
            }
            KeyCode::Left => {
                if let Some(row) = rows.get(self.selected_command_tree_row) {
                    if row.is_branch && row.is_expanded {
                        self.expanded_command_tree_paths.remove(&row.key);
                    } else if let Some(parent_key) = row.parent_key.as_deref() {
                        if let Some(parent_index) = rows
                            .iter()
                            .position(|candidate| candidate.key == parent_key)
                        {
                            self.selected_command_tree_row = parent_index;
                        }
                    }
                }
            }
            KeyCode::Enter => {
                if let Some(row) = rows.get(self.selected_command_tree_row) {
                    if row.is_branch {
                        if row.is_expanded {
                            self.expanded_command_tree_paths.remove(&row.key);
                        } else {
                            self.expanded_command_tree_paths.insert(row.key.clone());
                        }
                        self.status_line = format!("Toggled group `{}`", row.label);
                    } else if let Some(command_index) = row.command_index {
                        self.select_command_by_index(command_index);
                        self.status_line =
                            format!("Selected `{}`", self.selected_command_spec().title);
                    }
                }
            }
            _ => {}
        }
        self.reconcile_tree_selection();
    }

    fn on_field_list_key(&mut self, key: KeyEvent, global: bool) {
        let field_count = if global {
            self.global_fields.len()
        } else {
            self.command_fields.len()
        };
        if field_count == 0 {
            return;
        }

        let mut selected_index = if global {
            self.selected_global_field_index
        } else {
            self.selected_command_field_index
        };

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                selected_index = selected_index.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                selected_index = (selected_index + 1).min(field_count.saturating_sub(1));
            }
            KeyCode::Left if self.fullscreen_enabled => {
                self.scroll_horizontal_for_focus(false);
            }
            KeyCode::Right if self.fullscreen_enabled => {
                self.scroll_horizontal_for_focus(true);
            }
            KeyCode::Left => {
                self.cycle_choice(global, selected_index, false);
            }
            KeyCode::Right => {
                self.cycle_choice(global, selected_index, true);
            }
            KeyCode::Char(' ') => {
                self.toggle_bool(global, selected_index);
            }
            KeyCode::Char('e') | KeyCode::Char('i') => {
                self.start_edit(global, selected_index);
            }
            _ => {}
        }
        if global {
            self.selected_global_field_index = selected_index;
        } else {
            self.selected_command_field_index = selected_index;
        }
    }

    fn on_output_key(&mut self, key: KeyEvent) {
        let total_lines = self.output_line_count();
        let mut disable_follow_tail = false;
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.output_scroll = self.output_scroll.saturating_sub(OUTPUT_SCROLL_STEP);
                disable_follow_tail = true;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.output_scroll = self.output_scroll.saturating_add(OUTPUT_SCROLL_STEP);
            }
            KeyCode::Left => {
                self.scroll_horizontal_for_focus(false);
            }
            KeyCode::Right => {
                self.scroll_horizontal_for_focus(true);
            }
            KeyCode::PageUp => {
                self.output_scroll = self.output_scroll.saturating_sub(OUTPUT_SCROLL_PAGE_STEP);
                disable_follow_tail = true;
            }
            KeyCode::PageDown => {
                self.output_scroll = self.output_scroll.saturating_add(OUTPUT_SCROLL_PAGE_STEP);
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.output_scroll = 0;
                self.follow_tail = false;
                self.clamp_output_scroll(total_lines);
                return;
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.follow_tail = true;
                self.output_scroll = tail_scroll_start(total_lines, self.output_viewport_height);
                self.clamp_output_scroll(total_lines);
                return;
            }
            _ => {}
        }
        if disable_follow_tail {
            self.follow_tail = false;
        }
        self.clamp_output_scroll(total_lines);
        if self.output_scroll >= tail_scroll_start(total_lines, self.output_viewport_height) {
            self.follow_tail = true;
            self.output_scroll = tail_scroll_start(total_lines, self.output_viewport_height);
        }
    }

    fn start_edit(&mut self, global: bool, index: usize) {
        let field_state = if global {
            self.global_fields.get(index)
        } else {
            self.command_fields.get(index)
        };
        let Some(field_state) = field_state else {
            return;
        };
        let FieldValue::Text(current_value) = &field_state.value else {
            self.status_line = "Field is not text-editable (use space/left/right)".to_owned();
            return;
        };
        self.input_mode = InputMode::Edit;
        self.editing_target = Some(if global {
            EditingTarget::Global(index)
        } else {
            EditingTarget::Field(index)
        });
        self.editing_buffer = current_value.clone();
        self.editing_original_buffer = current_value.clone();
        self.status_line = format!("Editing `{}`", field_state.spec.label);
    }

    fn toggle_bool(&mut self, global: bool, index: usize) {
        let field_state = if global {
            self.global_fields.get_mut(index)
        } else {
            self.command_fields.get_mut(index)
        };
        let Some(field_state) = field_state else {
            return;
        };
        if let FieldValue::Bool(value) = &mut field_state.value {
            *value = !*value;
            self.status_line = format!("Toggled `{}`", field_state.spec.label);
            self.clear_pending_confirmation();
        }
    }

    fn cycle_choice(&mut self, global: bool, index: usize, forward: bool) {
        let field_state = if global {
            self.global_fields.get_mut(index)
        } else {
            self.command_fields.get_mut(index)
        };
        let Some(field_state) = field_state else {
            return;
        };
        let FieldValue::Choice(choice_index) = &mut field_state.value else {
            return;
        };
        let FieldKind::Choice(choices) = field_state.spec.kind else {
            return;
        };
        if choices.is_empty() {
            return;
        }
        let max_index = choices.len() - 1;
        *choice_index = if forward {
            (*choice_index + 1).min(max_index)
        } else {
            choice_index.saturating_sub(1)
        };
        self.status_line = format!("Updated `{}`", field_state.spec.label);
        self.clear_pending_confirmation();
    }

    fn reload_selected_command_fields(&mut self) {
        if self.command_tree_rows().is_empty() {
            self.command_fields.clear();
            self.selected_command_field_index = 0;
            self.status_line = EMPTY_FILTER_PLACEHOLDER.to_owned();
            self.clear_pending_confirmation();
            return;
        }
        self.command_fields = field_states_for_spec(self.selected_command_spec());
        self.selected_command_field_index = 0;
        self.status_line = format!("Command: {}", self.selected_command_spec().title);
        self.clear_pending_confirmation();
    }

    fn execute_selected_command(&mut self) -> Result<()> {
        self.execute_selected_command_with_policy(false)
    }

    fn execute_selected_command_with_policy(
        &mut self,
        bypass_risky_confirmation: bool,
    ) -> Result<()> {
        if self.active_run.is_some() {
            self.status_line =
                "A run is already active. Press Ctrl+C to cancel it first.".to_owned();
            return Ok(());
        }
        if self.command_tree_rows().is_empty() {
            self.status_line = EMPTY_FILTER_PLACEHOLDER.to_owned();
            return Ok(());
        }
        let Some(command_index) = self.selected_command_index_from_tree() else {
            self.status_line = "Select a leaf command to execute".to_owned();
            return Ok(());
        };
        self.select_command_by_index(command_index);
        let command_spec = self.selected_command_spec();
        let invocation_args =
            match build_invocation_args(command_spec, &self.global_fields, &self.command_fields) {
                Ok(args) => args,
                Err(message) => {
                    self.status_line = "Validation failed".to_owned();
                    self.push_validation_run_record(
                        command_spec.title,
                        format!("validation error: {message}"),
                    );
                    return Ok(());
                }
            };
        let stdin_payload = match stdin_payload_for_command(command_spec, &self.command_fields) {
            Ok(payload) => payload,
            Err(message) => {
                self.status_line = "Validation failed".to_owned();
                self.push_validation_run_record(
                    command_spec.title,
                    format!("validation error: {message}"),
                );
                return Ok(());
            }
        };
        let signature = command_signature(command_spec, &invocation_args);
        if is_risky_command(command_spec.id)
            && !bypass_risky_confirmation
            && self.pending_risky_signature.as_deref() != Some(signature.as_str())
        {
            self.pending_risky_signature = Some(signature);
            self.status_line = format!("Confirmation required for `{}`", command_spec.title);
            return Ok(());
        }
        self.clear_pending_confirmation();
        self.start_streaming_run(command_spec.title, invocation_args, stdin_payload);
        Ok(())
    }

    fn execute_selected_help(&mut self) -> Result<()> {
        if self.active_run.is_some() {
            self.status_line =
                "A run is already active. Press Ctrl+C to cancel it first.".to_owned();
            return Ok(());
        }
        if self.command_tree_rows().is_empty() {
            self.status_line = EMPTY_FILTER_PLACEHOLDER.to_owned();
            return Ok(());
        }
        let Some(command_index) = self.selected_command_index_from_tree() else {
            self.status_line = "Select a leaf command to open help".to_owned();
            return Ok(());
        };
        self.select_command_by_index(command_index);
        let command_spec = self.selected_command_spec();
        let mut help_args = Vec::with_capacity(command_spec.path.len() + 1);
        help_args.push("help".to_owned());
        help_args.extend(
            command_spec
                .path
                .iter()
                .map(|segment| (*segment).to_owned()),
        );
        self.start_streaming_run(&format!("help {}", command_spec.title), help_args, None);
        Ok(())
    }

    fn reset_selected_field(&mut self, global: bool) {
        let selected_index = if global {
            self.selected_global_field_index
        } else {
            self.selected_command_field_index
        };
        let field_state = if global {
            self.global_fields.get_mut(selected_index)
        } else {
            self.command_fields.get_mut(selected_index)
        };
        let Some(field_state) = field_state else {
            return;
        };
        field_state.value = match field_state.spec.kind {
            FieldKind::Text => FieldValue::Text(field_state.spec.default_text.to_owned()),
            FieldKind::Bool => FieldValue::Bool(field_state.spec.default_bool),
            FieldKind::Choice(_) => FieldValue::Choice(field_state.spec.default_choice),
        };
        self.status_line = format!("Reset `{}`", field_state.spec.label);
        self.clear_pending_confirmation();
    }

    fn start_streaming_run(
        &mut self,
        command_title: &str,
        invocation_args: Vec<String>,
        stdin_payload: Option<Vec<u8>>,
    ) {
        let executable = match std::env::current_exe() {
            Ok(executable) => executable,
            Err(error) => {
                self.status_line = format!("Unable to locate executable: {error}");
                return;
            }
        };
        let (child, output_events) = match spawn_process_with_streaming_output(
            &executable,
            &invocation_args,
            stdin_payload.as_deref(),
        ) {
            Ok(process) => process,
            Err(error) => {
                self.status_line = format!("Failed to start `{command_title}`: {error}");
                return;
            }
        };

        let run_id = self.next_run_id;
        self.next_run_id += 1;
        let invocation = format!("gloves {}", format_invocation_args(&invocation_args));
        self.run_history.push(RunRecord::new(
            run_id,
            command_title.to_owned(),
            invocation.clone(),
        ));
        self.active_run = Some(ActiveRun {
            run_id,
            command_title: command_title.to_owned(),
            invocation,
            child,
            output_events,
            cancel_requested: false,
        });
        self.enforce_history_retention();
        self.follow_tail = true;
        self.sync_output_scroll();
        self.status_line =
            format!("Running `{command_title}` (run #{run_id}). Press Ctrl+C to cancel.");
    }

    fn push_validation_run_record(&mut self, command_title: &str, message: String) {
        let run_id = self.next_run_id;
        self.next_run_id += 1;
        let mut record = RunRecord::new(
            run_id,
            format!("validation {command_title}"),
            format!("gloves {command_title}"),
        );
        record.phase = RunPhase::Failed;
        record.exit_code = None;
        record.finished_at = Some(Local::now());
        record.finished_instant = Some(Instant::now());
        push_section_line(&mut record.stderr_lines, message);
        self.run_history.push(record);
        self.enforce_history_retention();
        self.sync_output_scroll();
    }

    fn poll_active_run(&mut self) {
        let mut events = Vec::new();
        let mut completion_status: Option<ExitStatus> = None;
        let mut completion_error: Option<String> = None;
        let mut run_id: Option<u64> = None;
        let mut command_title = String::new();
        let mut invocation = String::new();
        let mut cancel_requested = false;

        if let Some(active_run) = self.active_run.as_mut() {
            run_id = Some(active_run.run_id);
            command_title = active_run.command_title.clone();
            invocation = active_run.invocation.clone();
            cancel_requested = active_run.cancel_requested;

            while let Ok(event) = active_run.output_events.try_recv() {
                events.push(event);
            }
            match active_run.child.try_wait() {
                Ok(Some(status)) => {
                    completion_status = Some(status);
                    while let Ok(event) = active_run.output_events.try_recv() {
                        events.push(event);
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    completion_error = Some(format!("Failed to poll child status: {error}"));
                }
            }
        }

        let Some(run_id) = run_id else {
            return;
        };

        for event in events {
            self.apply_output_event(run_id, event);
        }

        if let Some(error) = completion_error {
            self.finish_run_with_error(run_id, &command_title, &invocation, error);
            self.active_run = None;
            return;
        }

        if let Some(status) = completion_status {
            self.finish_run_with_status(run_id, &command_title, status, cancel_requested);
            self.active_run = None;
        }
    }

    fn cancel_active_run(&mut self) {
        let Some(active_run) = self.active_run.as_mut() else {
            self.status_line = "No active run to cancel".to_owned();
            return;
        };
        if active_run.cancel_requested {
            self.status_line = format!(
                "Cancellation already requested for run #{}",
                active_run.run_id
            );
            return;
        }
        match active_run.child.kill() {
            Ok(()) => {
                active_run.cancel_requested = true;
                self.status_line = format!("Cancelling run #{}...", active_run.run_id);
            }
            Err(error) => {
                self.status_line = format!("Failed to cancel run #{}: {error}", active_run.run_id);
            }
        }
    }

    fn apply_output_event(&mut self, run_id: u64, event: RunOutputEvent) {
        if self.run_record_mut(run_id).is_none() {
            if let Some(active_run) = self.active_run.as_ref().filter(|run| run.run_id == run_id) {
                self.run_history.push(RunRecord::new(
                    run_id,
                    active_run.command_title.clone(),
                    active_run.invocation.clone(),
                ));
            }
        }
        if let Some(record) = self.run_record_mut(run_id) {
            match event {
                RunOutputEvent::Line { stream, line } => match stream {
                    RunOutputStream::Stdout => push_section_line(&mut record.stdout_lines, line),
                    RunOutputStream::Stderr => push_section_line(&mut record.stderr_lines, line),
                },
                RunOutputEvent::ReadError { stream, message } => {
                    push_section_line(&mut record.stderr_lines, format!("[{stream}] {message}"));
                }
            }
        }
        self.enforce_history_retention();
        self.sync_output_scroll();
    }

    fn finish_run_with_status(
        &mut self,
        run_id: u64,
        command_title: &str,
        status: ExitStatus,
        cancelled: bool,
    ) {
        if self.run_record_mut(run_id).is_none() {
            self.run_history.push(RunRecord::new(
                run_id,
                command_title.to_owned(),
                format!("gloves {command_title}"),
            ));
        }
        if let Some(record) = self.run_record_mut(run_id) {
            record.phase = if cancelled {
                RunPhase::Cancelled
            } else if status.success() {
                RunPhase::Succeeded
            } else {
                RunPhase::Failed
            };
            record.exit_code = status.code();
            record.finished_at = Some(Local::now());
            record.finished_instant = Some(Instant::now());
        }
        self.enforce_history_retention();
        self.sync_output_scroll();
        self.status_line = if cancelled {
            format!("Cancelled `{command_title}`")
        } else if status.success() {
            format!("Executed `{command_title}` successfully")
        } else {
            format!("Executed `{command_title}` with errors")
        };
    }

    fn finish_run_with_error(
        &mut self,
        run_id: u64,
        command_title: &str,
        invocation: &str,
        error: String,
    ) {
        if let Some(record) = self.run_record_mut(run_id) {
            record.phase = RunPhase::Failed;
            record.exit_code = None;
            record.finished_at = Some(Local::now());
            record.finished_instant = Some(Instant::now());
            push_section_line(
                &mut record.stderr_lines,
                format!("Process `{invocation}` failed: {error}"),
            );
        } else {
            let mut fallback =
                RunRecord::new(run_id, command_title.to_owned(), invocation.to_owned());
            fallback.phase = RunPhase::Failed;
            fallback.exit_code = None;
            fallback.finished_at = Some(Local::now());
            fallback.finished_instant = Some(Instant::now());
            push_section_line(
                &mut fallback.stderr_lines,
                format!("Process `{invocation}` failed: {error}"),
            );
            self.run_history.push(fallback);
        }
        self.enforce_history_retention();
        self.sync_output_scroll();
        self.status_line = format!("Run failed for `{command_title}`");
    }

    fn run_record_mut(&mut self, run_id: u64) -> Option<&mut RunRecord> {
        self.run_history
            .iter_mut()
            .find(|record| record.run_id == run_id)
    }

    fn output_line_count(&self) -> usize {
        self.flatten_output_lines().len()
    }

    fn flatten_output_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for (index, record) in self.run_history.iter().enumerate() {
            lines.extend(record.render_lines());
            if index + 1 < self.run_history.len() {
                lines.push(String::new());
            }
        }
        while lines.last().is_some_and(|line| line.trim().is_empty()) {
            lines.pop();
        }
        lines
    }

    fn flattened_history_line_count(&self) -> usize {
        let history_lines: usize = self
            .run_history
            .iter()
            .map(RunRecord::render_line_count)
            .sum();
        history_lines + self.run_history.len().saturating_sub(1)
    }

    fn enforce_history_retention(&mut self) {
        while self.flattened_history_line_count() > MAX_OUTPUT_LINES && !self.run_history.is_empty()
        {
            if self.run_history.len() == 1 {
                break;
            }
            let active_run_id = self.active_run.as_ref().map(|run| run.run_id);
            if self
                .run_history
                .first()
                .is_some_and(|record| Some(record.run_id) == active_run_id)
            {
                break;
            }
            self.run_history.remove(0);
        }
    }

    fn max_output_scroll(&self, total_lines: usize) -> u16 {
        total_lines.saturating_sub(1).min(u16::MAX as usize) as u16
    }

    fn clamp_output_scroll(&mut self, total_lines: usize) {
        self.output_scroll = self.output_scroll.min(self.max_output_scroll(total_lines));
    }

    fn sync_output_scroll(&mut self) {
        let total_lines = self.output_line_count();
        if self.follow_tail {
            self.output_scroll = tail_scroll_start(total_lines, self.output_viewport_height);
        }
        self.clamp_output_scroll(total_lines);
    }

    fn render(&mut self, frame: &mut ratatui::Frame) {
        self.clamp_all_horizontal_scrolls();
        let root_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(UI_HEADER_HEIGHT),
                Constraint::Min(1),
                Constraint::Length(UI_FOOTER_HEIGHT),
            ])
            .split(frame.area());

        let confirmation_state = if self.pending_risky_signature.is_some() {
            "pending"
        } else {
            "none"
        };
        let view_state = if self.fullscreen_enabled {
            format!("fullscreen ({})", self.focus.label())
        } else {
            "split".to_owned()
        };
        let filter_text = if self.command_filter.is_empty() {
            "<none>".to_owned()
        } else {
            self.command_filter.clone()
        };
        let header = Paragraph::new(format!(
            "gloves tui | mode: {} | view: {} | focus: {} | confirm: {} | filter: {} | status: {}",
            self.input_mode_label(),
            view_state,
            self.focus.label(),
            confirmation_state,
            filter_text,
            self.status_line
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("TUI Command Center"),
        );
        frame.render_widget(header, root_chunks[0]);

        if self.fullscreen_enabled {
            self.render_focused_pane(frame, root_chunks[1]);
        } else {
            let body_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(28),
                    Constraint::Percentage(32),
                    Constraint::Percentage(40),
                ])
                .split(root_chunks[1]);

            self.render_commands(frame, body_chunks[0]);
            self.render_forms(frame, body_chunks[1]);
            self.render_output(frame, body_chunks[2]);
        }

        let footer_text = if self.input_mode == InputMode::Edit {
            "Edit: type, Enter=save, Esc=cancel"
        } else {
            "Navigate: Tab switch pane, o output focus, f fullscreen toggle, / filter, Up/Down move, Left/Right expand/collapse tree (or cycle choices in field panes), Shift+Left/Right horizontal pan, mouse wheel left/right or Shift+wheel horizontal pan, Space toggle bool, e edit text, Enter cycles only in split view (fullscreen keeps pane focus), ? help, r/F5 run, Ctrl+C cancel active run, Home/g top, End/G tail, x/X reset field, c clear output, q quit"
        };
        let footer = Paragraph::new(footer_text)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title("Keys"));
        frame.render_widget(footer, root_chunks[2]);
    }

    fn render_focused_pane(&mut self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        match self.focus {
            FocusPane::Commands => self.render_commands(frame, area),
            FocusPane::Globals => self.render_field_list(frame, area, true),
            FocusPane::Fields => self.render_field_list(frame, area, false),
            FocusPane::Output => self.render_output(frame, area),
        }
    }

    fn render_commands(&mut self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        let rows = self.command_tree_rows();
        let visible_leaf_count = rows
            .iter()
            .filter(|row| row.command_index.is_some())
            .count();
        self.command_viewport_width = area.width.saturating_sub(4).max(1);
        self.clamp_all_horizontal_scrolls();
        let content_width = usize::from(self.command_viewport_width);
        let items = if rows.is_empty() {
            vec![ListItem::new(Line::from(visible_line_window(
                EMPTY_FILTER_PLACEHOLDER,
                self.command_horizontal_scroll,
                content_width,
            )))]
        } else {
            rows.iter()
                .map(|row| {
                    let indent = "  ".repeat(row.depth);
                    let marker = if row.is_branch {
                        if row.is_expanded {
                            "[-]"
                        } else {
                            "[+]"
                        }
                    } else {
                        " - "
                    };
                    let mut line = format!("{indent}{marker} ");
                    line.push_str(&row.label);
                    if let Some(command_index) = row.command_index {
                        if let Some(spec) = COMMAND_SPECS.get(command_index) {
                            line.push_str("  ");
                            line.push_str(spec.summary);
                        }
                    }
                    ListItem::new(Line::from(visible_line_window(
                        &line,
                        self.command_horizontal_scroll,
                        content_width,
                    )))
                })
                .collect::<Vec<_>>()
        };
        let mut state = ListState::default();
        if !rows.is_empty() {
            state.select(Some(
                self.selected_command_tree_row
                    .min(rows.len().saturating_sub(1)),
            ));
        }
        let title = pane_title(
            &format!(
                "Command Tree ({visible_leaf_count}/{})",
                visible_tree_leaf_count()
            ),
            self.focus == FocusPane::Commands,
        );
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_symbol(">> ")
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn render_forms(&mut self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        let form_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(area);
        self.render_field_list(frame, form_chunks[0], true);
        self.render_field_list(frame, form_chunks[1], false);
    }

    fn render_field_list(
        &mut self,
        frame: &mut ratatui::Frame,
        area: ratatui::layout::Rect,
        global: bool,
    ) {
        let viewport_width = area.width.saturating_sub(4).max(1);
        if global {
            self.globals_viewport_width = viewport_width;
        } else {
            self.fields_viewport_width = viewport_width;
        }
        self.clamp_all_horizontal_scrolls();
        let (fields, selected_index, title, is_focused) = if global {
            (
                &self.global_fields,
                self.selected_global_field_index,
                "Global Flags",
                self.focus == FocusPane::Globals,
            )
        } else {
            (
                &self.command_fields,
                self.selected_command_field_index,
                "Command Fields",
                self.focus == FocusPane::Fields,
            )
        };
        let horizontal_scroll = if global {
            self.globals_horizontal_scroll
        } else {
            self.fields_horizontal_scroll
        };
        let content_width = usize::from(viewport_width);
        let items = fields
            .iter()
            .map(|field_state| {
                let line = field_line_text(field_state);
                ListItem::new(Line::from(visible_line_window(
                    &line,
                    horizontal_scroll,
                    content_width,
                )))
            })
            .collect::<Vec<_>>();

        let mut state = ListState::default();
        if !fields.is_empty() {
            state.select(Some(selected_index.min(fields.len().saturating_sub(1))));
        }
        let block_title = pane_title(title, is_focused);
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(block_title))
            .highlight_symbol(">> ")
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn render_output(&mut self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        self.output_viewport_height = area.height.saturating_sub(2);
        self.output_viewport_width = area.width.saturating_sub(3).max(1);
        self.clamp_all_horizontal_scrolls();
        self.sync_output_scroll();
        let title = pane_title("Execution Output", self.focus == FocusPane::Output);
        let rendered_lines = self.flatten_output_lines();
        let output_text = format_output_text_for_viewport(
            &rendered_lines,
            area.width,
            self.output_horizontal_scroll,
        );
        let output_widget = Paragraph::new(output_text)
            .scroll((self.output_scroll, 0))
            .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(output_widget, area);
    }

    fn input_mode_label(&self) -> &'static str {
        match self.input_mode {
            InputMode::Navigate => "navigate",
            InputMode::Edit => "edit",
        }
    }
}

impl RunPhase {
    fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl std::fmt::Display for RunOutputStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdout => formatter.write_str("stdout"),
            Self::Stderr => formatter.write_str("stderr"),
        }
    }
}

impl RunRecord {
    fn new(run_id: u64, command_title: String, invocation: String) -> Self {
        Self {
            run_id,
            command_title,
            invocation,
            phase: RunPhase::Running,
            exit_code: None,
            started_at: Local::now(),
            finished_at: None,
            started_instant: Instant::now(),
            finished_instant: None,
            stdout_lines: Vec::new(),
            stderr_lines: Vec::new(),
        }
    }

    fn render_lines(&self) -> Vec<String> {
        let started = self.started_at.format("%H:%M:%S");
        let finished = self
            .finished_at
            .as_ref()
            .map(|timestamp| timestamp.format("%H:%M:%S").to_string())
            .unwrap_or_else(|| "<running>".to_owned());
        let duration = self
            .finished_instant
            .unwrap_or_else(Instant::now)
            .saturating_duration_since(self.started_instant);
        let duration_label = if duration.as_secs() > 0 {
            format!("{:.2}s", duration.as_secs_f64())
        } else {
            format!("{}ms", duration.as_millis())
        };
        let exit_label = self
            .exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "<none>".to_owned());

        let mut lines = Vec::new();
        lines.push(format!(
            "run #{:03} | {} | phase: {} | exit: {}",
            self.run_id,
            self.command_title,
            self.phase.label(),
            exit_label
        ));
        lines.push(format!(
            "started: {started} | finished: {finished} | duration: {duration_label}"
        ));
        lines.push(format!("command: {}", self.invocation));
        lines.push("stdout:".to_owned());
        if self.stdout_lines.is_empty() {
            lines.push("  <empty>".to_owned());
        } else {
            lines.extend(self.stdout_lines.iter().map(|line| format!("  {line}")));
        }
        lines.push("stderr:".to_owned());
        if self.stderr_lines.is_empty() {
            lines.push("  <empty>".to_owned());
        } else {
            lines.extend(self.stderr_lines.iter().map(|line| format!("  {line}")));
        }
        lines
    }

    fn render_line_count(&self) -> usize {
        self.render_lines().len()
    }
}

fn push_section_line(section_lines: &mut Vec<String>, line: String) {
    section_lines.push(sanitize_output_line(&line));
    if section_lines.len() > MAX_OUTPUT_SECTION_LINES {
        let overflow = section_lines.len() - MAX_OUTPUT_SECTION_LINES;
        section_lines.drain(0..overflow);
    }
}

fn format_output_text_for_viewport(
    lines: &[String],
    area_width: u16,
    horizontal_scroll: u16,
) -> String {
    if lines.is_empty() {
        return "No output yet".to_owned();
    }
    let content_width = usize::from(area_width.saturating_sub(3));
    lines
        .iter()
        .map(|line| visible_line_window(line, horizontal_scroll, content_width))
        .collect::<Vec<_>>()
        .join("\n")
}

fn visible_line_window(line: &str, horizontal_scroll: u16, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    line.chars()
        .skip(usize::from(horizontal_scroll))
        .take(max_width)
        .collect()
}

fn sanitize_output_line(raw_line: &str) -> String {
    let mut sanitized = String::with_capacity(raw_line.len());
    let mut chars = raw_line.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\u{1b}' {
            if chars.peek().is_some_and(|next| *next == '[') {
                chars.next();
                for sequence_character in chars.by_ref() {
                    if ('@'..='~').contains(&sequence_character) {
                        break;
                    }
                }
            }
            continue;
        }
        match character {
            '\t' => sanitized.push_str(OUTPUT_TAB_EXPANSION),
            _ if character.is_control() => {}
            _ => sanitized.push(character),
        }
    }
    sanitized
}

fn tail_scroll_start(total_lines: usize, viewport_height: u16) -> u16 {
    if total_lines == 0 {
        return 0;
    }
    let viewport = usize::max(usize::from(viewport_height), 1);
    let page_index = total_lines.saturating_sub(1) / viewport;
    (page_index * viewport).min(u16::MAX as usize) as u16
}

fn rect_contains_point(area: Rect, column: u16, row: u16) -> bool {
    let x_end = area.x.saturating_add(area.width);
    let y_end = area.y.saturating_add(area.height);
    column >= area.x && column < x_end && row >= area.y && row < y_end
}

fn pane_title(title: &str, focused: bool) -> Line<'static> {
    if focused {
        Line::from(vec![
            Span::styled("[*] ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(title.to_owned()),
        ])
    } else {
        Line::from(title.to_owned())
    }
}

fn initial_field_state(spec: &'static FieldSpec) -> FieldState {
    let value = match spec.kind {
        FieldKind::Text => FieldValue::Text(spec.default_text.to_owned()),
        FieldKind::Bool => FieldValue::Bool(spec.default_bool),
        FieldKind::Choice(_) => FieldValue::Choice(spec.default_choice),
    };
    FieldState { spec, value }
}

fn field_states_for_spec(command_spec: &'static CommandSpec) -> Vec<FieldState> {
    command_spec
        .fields
        .iter()
        .map(initial_field_state)
        .collect()
}

fn field_display_value(field_state: &FieldState) -> String {
    match (&field_state.value, field_state.spec.kind) {
        (FieldValue::Text(value), _) => {
            if value.is_empty() {
                "<empty>".to_owned()
            } else {
                value.clone()
            }
        }
        (FieldValue::Bool(value), _) => {
            if *value {
                "on".to_owned()
            } else {
                "off".to_owned()
            }
        }
        (FieldValue::Choice(index), FieldKind::Choice(choices)) => choices
            .get(*index)
            .copied()
            .unwrap_or("<invalid>")
            .to_owned(),
        _ => "<invalid>".to_owned(),
    }
}

fn field_line_text(field_state: &FieldState) -> String {
    let suffix = if field_state.spec.required { " *" } else { "" };
    let value = field_display_value(field_state);
    format!(
        "{}{}: {}  [{}]",
        field_state.spec.label, suffix, value, field_state.spec.help
    )
}

fn build_invocation_args(
    command_spec: &CommandSpec,
    global_fields: &[FieldState],
    command_fields: &[FieldState],
) -> std::result::Result<Vec<String>, String> {
    let mut args = Vec::new();
    append_global_args(&mut args, global_fields)?;
    args.extend(
        command_spec
            .path
            .iter()
            .map(|segment| (*segment).to_owned()),
    );
    if command_spec.id == "set" {
        append_set_args(&mut args, command_fields)?;
        return Ok(args);
    }
    if command_spec.id == "vault_exec" {
        append_generic_fields(&mut args, command_fields)?;
        append_vault_exec_command_line(&mut args, command_fields)?;
        return Ok(args);
    }
    append_generic_fields(&mut args, command_fields)?;
    Ok(args)
}

fn stdin_payload_for_command(
    command_spec: &CommandSpec,
    fields: &[FieldState],
) -> std::result::Result<Option<Vec<u8>>, String> {
    if command_spec.id != "set" {
        return Ok(None);
    }
    let input_mode_index = choice_index_field(fields, "input_mode")?;
    if input_mode_index != SET_INPUT_MODE_STDIN_INDEX {
        return Ok(None);
    }
    let value = required_text_field(fields, "value")?;
    Ok(Some(value.as_bytes().to_vec()))
}

fn spawn_process_with_streaming_output(
    executable: &std::path::Path,
    args: &[String],
    stdin_payload: Option<&[u8]>,
) -> Result<(Child, Receiver<RunOutputEvent>)> {
    let mut command = ProcessCommand::new(executable);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin_payload.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }

    let mut child = command.spawn()?;
    if let Some(payload) = stdin_payload {
        if let Some(mut child_stdin) = child.stdin.take() {
            child_stdin.write_all(payload)?;
        }
    }
    let (sender, receiver) = mpsc::channel();
    if let Some(stdout) = child.stdout.take() {
        spawn_output_reader(stdout, RunOutputStream::Stdout, sender.clone());
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_output_reader(stderr, RunOutputStream::Stderr, sender.clone());
    }
    drop(sender);

    Ok((child, receiver))
}

fn spawn_output_reader(
    stream: impl Read + Send + 'static,
    stream_kind: RunOutputStream,
    sender: Sender<RunOutputEvent>,
) {
    thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut buffer = Vec::new();
        loop {
            buffer.clear();
            match reader.read_until(b'\n', &mut buffer) {
                Ok(0) => break,
                Ok(_) => {
                    trim_line_ending(&mut buffer);
                    let line = String::from_utf8_lossy(&buffer).into_owned();
                    let _ = sender.send(RunOutputEvent::Line {
                        stream: stream_kind,
                        line,
                    });
                }
                Err(error) => {
                    let _ = sender.send(RunOutputEvent::ReadError {
                        stream: stream_kind,
                        message: error.to_string(),
                    });
                    break;
                }
            }
        }
    });
}

fn trim_line_ending(buffer: &mut Vec<u8>) {
    while buffer
        .last()
        .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
    {
        buffer.pop();
    }
}

fn format_invocation_args(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            shlex::try_quote(arg)
                .map(|quoted| quoted.into_owned())
                .unwrap_or_else(|_| format!("{arg:?}"))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn command_signature(command_spec: &CommandSpec, args: &[String]) -> String {
    format!("{}::{}", command_spec.id, format_invocation_args(args))
}

fn is_risky_command(command_id: &str) -> bool {
    !SAFE_COMMAND_IDS.contains(&command_id)
}

fn append_global_args(
    args: &mut Vec<String>,
    global_fields: &[FieldState],
) -> std::result::Result<(), String> {
    for field in global_fields {
        match field.spec.id {
            "error_format" => {
                append_choice_field(args, field)?;
            }
            "vault_mode" => {
                append_optional_choice_field(args, field)?;
            }
            _ => append_field(args, field)?,
        }
    }
    Ok(())
}

fn append_set_args(
    args: &mut Vec<String>,
    fields: &[FieldState],
) -> std::result::Result<(), String> {
    let name = required_text_field(fields, "name")?;
    args.push(name.to_owned());

    let input_mode_index = choice_index_field(fields, "input_mode")?;
    if input_mode_index == SET_INPUT_MODE_GENERATE_INDEX {
        args.push("--generate".to_owned());
    } else if input_mode_index == SET_INPUT_MODE_VALUE_INDEX {
        let value = required_text_field(fields, "value")?;
        args.push("--value".to_owned());
        args.push(value.to_owned());
    } else if input_mode_index == SET_INPUT_MODE_STDIN_INDEX {
        let _ = required_text_field(fields, "value")?;
        args.push("--stdin".to_owned());
    } else {
        return Err("`Input Mode` selection is invalid".to_owned());
    }

    if let Some(ttl) = optional_text_field(fields, "ttl") {
        args.push("--ttl".to_owned());
        args.push(ttl.to_owned());
    }
    Ok(())
}

fn append_vault_exec_command_line(
    args: &mut Vec<String>,
    fields: &[FieldState],
) -> std::result::Result<(), String> {
    let command_line = required_text_field(fields, "command_line")?;
    let split = shlex::split(command_line)
        .ok_or_else(|| "Vault exec command line must be valid shell words".to_owned())?;
    if split.is_empty() {
        return Err("Vault exec command line must not be empty".to_owned());
    }
    args.push("--".to_owned());
    args.extend(split);
    Ok(())
}

fn append_generic_fields(
    args: &mut Vec<String>,
    fields: &[FieldState],
) -> std::result::Result<(), String> {
    for field in fields {
        if matches!(field.spec.arg, FieldArg::None) {
            continue;
        }
        append_field(args, field)?;
    }
    Ok(())
}

fn append_field(args: &mut Vec<String>, field: &FieldState) -> std::result::Result<(), String> {
    match (&field.value, field.spec.kind, field.spec.arg) {
        (FieldValue::Text(value), _, FieldArg::Positional) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                if field.spec.required {
                    return Err(format!("`{}` is required", field.spec.label));
                }
                return Ok(());
            }
            args.push(trimmed.to_owned());
        }
        (FieldValue::Text(value), _, FieldArg::OptionValue(flag)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                if field.spec.required {
                    return Err(format!("`{}` is required", field.spec.label));
                }
                return Ok(());
            }
            args.push(flag.to_owned());
            args.push(trimmed.to_owned());
        }
        (FieldValue::Bool(value), _, FieldArg::Flag(flag)) => {
            if *value {
                args.push(flag.to_owned());
            }
        }
        (FieldValue::Choice(_), FieldKind::Choice(_), _) => {
            append_choice_field(args, field)?;
        }
        _ => {}
    }
    Ok(())
}

fn append_choice_field(
    args: &mut Vec<String>,
    field: &FieldState,
) -> std::result::Result<(), String> {
    let FieldValue::Choice(choice_index) = field.value else {
        return Err(format!("`{}` must be a choice field", field.spec.label));
    };
    let FieldKind::Choice(choices) = field.spec.kind else {
        return Err(format!("`{}` must define choices", field.spec.label));
    };
    let choice = choices
        .get(choice_index)
        .copied()
        .ok_or_else(|| format!("`{}` has invalid selection", field.spec.label))?;

    if choice.is_empty() || choice == "<unset>" {
        if field.spec.required {
            return Err(format!("`{}` is required", field.spec.label));
        }
        return Ok(());
    }

    match field.spec.arg {
        FieldArg::Positional => args.push(choice.to_owned()),
        FieldArg::OptionValue(flag) => {
            args.push(flag.to_owned());
            args.push(choice.to_owned());
        }
        FieldArg::Flag(flag) => {
            if choice == "true" {
                args.push(flag.to_owned());
            }
        }
        FieldArg::None => {}
    }
    Ok(())
}

fn append_optional_choice_field(
    args: &mut Vec<String>,
    field: &FieldState,
) -> std::result::Result<(), String> {
    let FieldValue::Choice(choice_index) = field.value else {
        return Ok(());
    };
    let FieldKind::Choice(choices) = field.spec.kind else {
        return Ok(());
    };
    let choice = choices
        .get(choice_index)
        .copied()
        .ok_or_else(|| format!("`{}` has invalid selection", field.spec.label))?;
    if choice == "<unset>" {
        return Ok(());
    }
    if let FieldArg::OptionValue(flag) = field.spec.arg {
        args.push(flag.to_owned());
        args.push(choice.to_owned());
    }
    Ok(())
}

fn required_text_field<'a>(
    fields: &'a [FieldState],
    id: &str,
) -> std::result::Result<&'a str, String> {
    let value = optional_text_field(fields, id).ok_or_else(|| format!("`{id}` is required"))?;
    Ok(value)
}

fn optional_text_field<'a>(fields: &'a [FieldState], id: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|field| field.spec.id == id)
        .and_then(|field| match &field.value {
            FieldValue::Text(value) if !value.trim().is_empty() => Some(value.trim()),
            _ => None,
        })
}

fn choice_index_field(fields: &[FieldState], id: &str) -> std::result::Result<usize, String> {
    let field = fields
        .iter()
        .find(|field| field.spec.id == id)
        .ok_or_else(|| format!("missing `{id}` field"))?;
    match field.value {
        FieldValue::Choice(value) => Ok(value),
        _ => Err(format!("`{id}` must be a choice field")),
    }
}

impl FocusPane {
    fn next(self) -> Self {
        match self {
            Self::Commands => Self::Globals,
            Self::Globals => Self::Fields,
            Self::Fields => Self::Output,
            Self::Output => Self::Commands,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Commands => Self::Output,
            Self::Globals => Self::Commands,
            Self::Fields => Self::Globals,
            Self::Output => Self::Fields,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Commands => "commands",
            Self::Globals => "globals",
            Self::Fields => "fields",
            Self::Output => "output",
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::{
        build_command_tree, build_invocation_args, field_states_for_spec,
        format_output_text_for_viewport, initial_field_state, is_risky_command,
        normalize_launch_command_args, resolve_launch_command_spec, sanitize_output_line,
        stdin_payload_for_command, tail_scroll_start, visible_line_window, CommandSpec,
        CommandTreeNode, FieldState, FieldValue, FocusPane, NavigatorLaunchOptions, RunPhase,
        RunRecord, TuiApp, COMMAND_SPECS, GLOBAL_FIELDS, HORIZONTAL_SCROLL_STEP, MAX_OUTPUT_LINES,
        UI_FOOTER_HEIGHT, UI_HEADER_HEIGHT,
    };
    use crate::cli::Cli;
    use clap::CommandFactory;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
    use ratatui::layout::{Constraint, Direction, Layout, Rect};
    use std::{collections::BTreeSet, process::Command as ProcessCommand, time::Instant};

    fn command_by_id(id: &str) -> &'static CommandSpec {
        COMMAND_SPECS
            .iter()
            .find(|command| command.id == id)
            .expect("command exists")
    }

    fn default_global_fields() -> Vec<FieldState> {
        GLOBAL_FIELDS.iter().map(initial_field_state).collect()
    }

    fn node_by_label<'a>(nodes: &'a [CommandTreeNode], label: &str) -> &'a CommandTreeNode {
        nodes
            .iter()
            .find(|node| node.label == label)
            .expect("tree node exists")
    }

    fn cargo_status(arguments: &[&str]) -> std::process::ExitStatus {
        ProcessCommand::new("cargo")
            .args(arguments)
            .status()
            .expect("cargo status available")
    }

    fn collect_visible_leaf_paths(
        command: &clap::Command,
        prefix: &[String],
        output: &mut Vec<Vec<String>>,
    ) {
        for subcommand in command.get_subcommands() {
            if subcommand.is_hide_set() {
                continue;
            }
            let mut path = prefix.to_vec();
            path.push(subcommand.get_name().to_owned());
            if subcommand.get_subcommands().next().is_none() {
                output.push(path);
                continue;
            }
            collect_visible_leaf_paths(subcommand, &path, output);
        }
    }

    #[test]
    fn command_catalog_covers_core_workflows() {
        assert!(COMMAND_SPECS.len() >= 25);
        assert!(COMMAND_SPECS.iter().any(|command| command.id == "set"));
        assert!(COMMAND_SPECS
            .iter()
            .any(|command| command.id == "vault_exec"));
        assert!(COMMAND_SPECS
            .iter()
            .any(|command| command.id == "requests_approve"));
    }

    #[test]
    fn command_tree_groups_nested_commands() {
        let tree = build_command_tree();
        let vault = node_by_label(&tree, "vault");
        assert!(vault.command_index.is_none());
        assert!(vault.children.iter().any(|node| node.label == "mount"));
        assert!(vault.children.iter().any(|node| node.label == "exec"));
        assert!(vault.children.iter().any(|node| node.label == "status"));

        let requests = node_by_label(&tree, "requests");
        assert!(requests.children.iter().any(|node| node.label == "approve"));
        assert!(requests.children.iter().any(|node| node.label == "deny"));
        assert!(requests.children.iter().any(|node| node.label == "list"));
    }

    #[test]
    fn command_tree_keeps_top_level_leaf_commands() {
        let tree = build_command_tree();
        let init = node_by_label(&tree, "init");
        let explain = node_by_label(&tree, "explain");
        assert!(init.command_index.is_some());
        assert!(explain.command_index.is_some());
        assert!(init.children.is_empty());
        assert!(explain.children.is_empty());
    }

    #[test]
    fn command_tree_hides_top_level_alias_commands() {
        let tree = build_command_tree();
        assert!(tree.iter().all(|node| node.label != "approve"));
        assert!(tree.iter().all(|node| node.label != "deny"));
        let requests = node_by_label(&tree, "requests");
        assert!(requests.children.iter().any(|node| node.label == "approve"));
        assert!(requests.children.iter().any(|node| node.label == "deny"));
    }

    #[test]
    fn command_tree_routes_top_level_list_through_entries_group() {
        let tree = build_command_tree();
        assert!(tree.iter().all(|node| node.label != "list"));
        let entries = node_by_label(&tree, "entries");
        let list_leaf = entries
            .children
            .iter()
            .find(|node| node.label == "list")
            .expect("entries/list exists");
        let list_command_index = list_leaf.command_index.expect("entries/list is executable");
        assert_eq!(COMMAND_SPECS[list_command_index].id, "list");
        assert_eq!(COMMAND_SPECS[list_command_index].path, &["list"]);
    }

    #[test]
    fn command_tree_routes_secret_commands_through_secrets_group() {
        let tree = build_command_tree();
        for label in ["set", "get", "grant", "revoke", "status"] {
            assert!(tree.iter().all(|node| node.label != label));
        }

        let secrets = node_by_label(&tree, "secrets");
        let expected_ids = [
            ("set", "set"),
            ("get", "get"),
            ("grant", "grant"),
            ("revoke", "revoke"),
            ("status", "status"),
        ];

        for (label, expected_id) in expected_ids {
            let leaf = secrets
                .children
                .iter()
                .find(|node| node.label == label)
                .expect("secrets leaf exists");
            let command_index = leaf.command_index.expect("secrets leaf is executable");
            assert_eq!(COMMAND_SPECS[command_index].id, expected_id);
        }
    }

    #[test]
    fn launch_command_normalization_maps_legacy_shortcuts() {
        let legacy_secret = normalize_launch_command_args(&[
            "set".to_owned(),
            "service/token".to_owned(),
            "--generate".to_owned(),
        ]);
        assert_eq!(
            legacy_secret,
            vec![
                "secrets".to_owned(),
                "set".to_owned(),
                "service/token".to_owned(),
                "--generate".to_owned()
            ]
        );

        let legacy_request = normalize_launch_command_args(&[
            "approve".to_owned(),
            "123e4567-e89b-12d3-a456-426614174000".to_owned(),
        ]);
        assert_eq!(
            legacy_request,
            vec![
                "requests".to_owned(),
                "approve".to_owned(),
                "123e4567-e89b-12d3-a456-426614174000".to_owned()
            ]
        );
    }

    #[test]
    fn launch_command_resolver_matches_nested_request_commands() {
        let args = vec![
            "requests".to_owned(),
            "approve".to_owned(),
            "123e4567-e89b-12d3-a456-426614174000".to_owned(),
        ];
        let (command_index, consumed_path_segments) =
            resolve_launch_command_spec(&args).expect("resolver should match command");
        assert_eq!(COMMAND_SPECS[command_index].id, "requests_approve");
        assert_eq!(consumed_path_segments, 2);
    }

    #[test]
    fn tui_launch_options_prefill_globals_and_select_command_fields() {
        let app = TuiApp::new(NavigatorLaunchOptions {
            root: Some("/tmp/gloves".to_owned()),
            config: Some("/etc/gloves/prod.gloves.toml".to_owned()),
            command_args: vec!["audit".to_owned(), "--limit".to_owned(), "100".to_owned()],
            ..NavigatorLaunchOptions::default()
        });

        assert_eq!(app.selected_command_spec().id, "audit");
        assert!(app.startup_command_pending);
        let limit_field = app
            .command_fields
            .iter()
            .find(|field| field.spec.id == "limit")
            .expect("audit limit field");
        match &limit_field.value {
            FieldValue::Text(value) => assert_eq!(value, "100"),
            _ => panic!("limit field must be text"),
        }

        let config_field = app
            .global_fields
            .iter()
            .find(|field| field.spec.id == "config")
            .expect("global config field");
        match &config_field.value {
            FieldValue::Text(value) => assert_eq!(value, "/etc/gloves/prod.gloves.toml"),
            _ => panic!("config field must be text"),
        }
    }

    #[test]
    fn tui_startup_autorun_enters_fullscreen_output_and_runs_command() {
        let mut app = TuiApp::new(NavigatorLaunchOptions {
            command_args: vec!["secrets".to_owned(), "revoke".to_owned()],
            ..NavigatorLaunchOptions::default()
        });
        assert!(app.startup_command_pending);
        assert_eq!(app.focus, FocusPane::Commands);
        assert!(!app.fullscreen_enabled);

        app.execute_startup_command_if_needed()
            .expect("startup autorun should execute");

        assert!(!app.startup_command_pending);
        assert_eq!(app.focus, FocusPane::Output);
        assert!(app.fullscreen_enabled);
        assert_eq!(app.status_line, "Validation failed");
        assert_eq!(app.run_history.len(), 1);
    }

    #[test]
    fn command_catalog_covers_all_visible_cli_leaf_commands_except_tui() {
        let mut paths = Vec::new();
        collect_visible_leaf_paths(&Cli::command(), &[], &mut paths);
        let visible_leaf_paths = paths
            .into_iter()
            .filter(|path| {
                !matches!(path.first().map(String::as_str), Some("help") | Some("tui"))
                    && !matches!(path.last().map(String::as_str), Some("help"))
            })
            .collect::<BTreeSet<_>>();
        let tui_leaf_paths = COMMAND_SPECS
            .iter()
            .map(|spec| {
                spec.path
                    .iter()
                    .map(|segment| (*segment).to_owned())
                    .collect()
            })
            .collect::<BTreeSet<Vec<String>>>();
        assert_eq!(tui_leaf_paths, visible_leaf_paths);
    }

    #[test]
    fn build_args_for_requests_approve_includes_request_id() {
        let command = command_by_id("requests_approve");
        let globals = default_global_fields();
        let mut fields = field_states_for_spec(command);
        fields[0].value = FieldValue::Text("123e4567-e89b-12d3-a456-426614174000".to_owned());

        let args = build_invocation_args(command, &globals, &fields).expect("build args");
        assert_eq!(
            args,
            vec![
                "--error-format",
                "text",
                "requests",
                "approve",
                "123e4567-e89b-12d3-a456-426614174000"
            ]
        );
    }

    #[test]
    fn build_args_for_grant_includes_to_flag() {
        let command = command_by_id("grant");
        let globals = default_global_fields();
        let mut fields = field_states_for_spec(command);
        fields[0].value = FieldValue::Text("service/token".to_owned());
        fields[1].value = FieldValue::Text("agent-b".to_owned());

        let args = build_invocation_args(command, &globals, &fields).expect("build args");
        assert_eq!(
            args,
            vec![
                "--error-format",
                "text",
                "secrets",
                "grant",
                "service/token",
                "--to",
                "agent-b"
            ]
        );
    }

    #[test]
    fn build_args_for_set_value_mode_includes_value_flag() {
        let command = command_by_id("set");
        let globals = default_global_fields();
        let mut fields = field_states_for_spec(command);
        fields[0].value = FieldValue::Text("service/token".to_owned());
        fields[1].value = FieldValue::Choice(1);
        fields[2].value = FieldValue::Text("secret-value".to_owned());
        fields[3].value = FieldValue::Text("7".to_owned());

        let args = build_invocation_args(command, &globals, &fields).expect("build args");
        assert_eq!(
            args,
            vec![
                "--error-format",
                "text",
                "secrets",
                "set",
                "service/token",
                "--value",
                "secret-value",
                "--ttl",
                "7"
            ]
        );
    }

    #[test]
    fn build_args_for_set_stdin_mode_includes_stdin_flag() {
        let command = command_by_id("set");
        let globals = default_global_fields();
        let mut fields = field_states_for_spec(command);
        fields[0].value = FieldValue::Text("service/token".to_owned());
        fields[1].value = FieldValue::Choice(2);
        fields[2].value = FieldValue::Text("stdin-secret".to_owned());

        let args = build_invocation_args(command, &globals, &fields).expect("build args");
        assert_eq!(
            args,
            vec![
                "--error-format",
                "text",
                "secrets",
                "set",
                "service/token",
                "--stdin",
                "--ttl",
                "1"
            ]
        );
    }

    #[test]
    fn set_stdin_mode_produces_stdin_payload() {
        let command = command_by_id("set");
        let mut fields = field_states_for_spec(command);
        fields[0].value = FieldValue::Text("service/token".to_owned());
        fields[1].value = FieldValue::Choice(2);
        fields[2].value = FieldValue::Text("stdin-secret".to_owned());

        let payload = stdin_payload_for_command(command, &fields)
            .expect("payload")
            .expect("stdin payload");
        assert_eq!(payload, b"stdin-secret");
    }

    #[test]
    fn build_args_validates_required_fields() {
        let command = command_by_id("revoke");
        let globals = default_global_fields();
        let fields = field_states_for_spec(command);
        let error = build_invocation_args(command, &globals, &fields).unwrap_err();
        assert!(error.contains("Name"));
    }

    #[test]
    fn build_args_for_vault_exec_includes_separator_and_split_command() {
        let command = command_by_id("vault_exec");
        let globals = default_global_fields();
        let mut fields = field_states_for_spec(command);
        fields[0].value = FieldValue::Text("agent_data".to_owned());
        fields[4].value = FieldValue::Text("sh -c 'echo hi'".to_owned());

        let args = build_invocation_args(command, &globals, &fields).expect("build args");
        assert!(args.contains(&"--".to_owned()));
        assert!(args.ends_with(&["sh".to_owned(), "-c".to_owned(), "echo hi".to_owned()]));
    }

    #[test]
    fn risky_classification_matches_read_and_write_commands() {
        assert!(!is_risky_command("list"));
        assert!(!is_risky_command("requests_list"));
        assert!(is_risky_command("set"));
        assert!(is_risky_command("approve"));
    }

    #[test]
    fn tail_scroll_start_aligns_to_viewport_pages() {
        assert_eq!(tail_scroll_start(0, 8), 0);
        assert_eq!(tail_scroll_start(1, 8), 0);
        assert_eq!(tail_scroll_start(8, 4), 4);
        assert_eq!(tail_scroll_start(9, 4), 8);
        assert_eq!(tail_scroll_start(10, 4), 8);
    }

    #[test]
    fn sanitize_output_line_removes_escape_sequences_and_control_characters() {
        let sanitized = sanitize_output_line("\u{1b}[32mok\u{1b}[0m\tone\rtwo\u{0007}");
        assert_eq!(sanitized, "ok    onetwo");
    }

    #[test]
    fn visible_line_window_applies_horizontal_offset_and_width() {
        assert_eq!(visible_line_window("abcdefgh", 0, 4), "abcd");
        assert_eq!(visible_line_window("abcdefgh", 3, 4), "defg");
        assert_eq!(visible_line_window("abc", 9, 4), "");
    }

    #[test]
    fn output_text_for_viewport_honors_horizontal_scroll() {
        let text =
            format_output_text_for_viewport(&["alpha-beta".to_owned(), "two".to_owned()], 8, 3);
        assert_eq!(text, "ha-be\n");
    }

    #[test]
    fn output_arrow_keys_scroll_horizontally() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        app.focus = FocusPane::Output;
        app.output_viewport_width = 10;
        let mut record = RunRecord::new(1, "version".to_owned(), "gloves version".to_owned());
        record
            .stdout_lines
            .push("0123456789abcdefghijklmnop".to_owned());
        app.run_history.push(record);
        assert_eq!(app.output_horizontal_scroll, 0);
        app.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE))
            .expect("right scroll");
        assert_eq!(app.output_horizontal_scroll, HORIZONTAL_SCROLL_STEP);
        app.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE))
            .expect("left scroll");
        assert_eq!(app.output_horizontal_scroll, 0);
    }

    #[test]
    fn mouse_scroll_right_pans_fullscreen_output() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        app.focus = FocusPane::Output;
        app.fullscreen_enabled = true;
        app.output_viewport_width = 10;
        let mut record = RunRecord::new(2, "version".to_owned(), "gloves version".to_owned());
        record
            .stdout_lines
            .push("0123456789abcdefghijklmnop".to_owned());
        app.run_history.push(record);
        let terminal_area = Rect::new(0, 0, 140, 40);

        app.on_mouse(
            MouseEvent {
                kind: MouseEventKind::ScrollRight,
                column: 20,
                row: 10,
                modifiers: KeyModifiers::NONE,
            },
            terminal_area,
        );
        assert_eq!(app.output_horizontal_scroll, HORIZONTAL_SCROLL_STEP);

        app.on_mouse(
            MouseEvent {
                kind: MouseEventKind::ScrollLeft,
                column: 20,
                row: 10,
                modifiers: KeyModifiers::NONE,
            },
            terminal_area,
        );
        assert_eq!(app.output_horizontal_scroll, 0);
    }

    #[test]
    fn mouse_shift_wheel_pans_output_in_split_view_without_focus_change() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        app.focus = FocusPane::Commands;
        app.output_viewport_width = 10;
        let mut record = RunRecord::new(3, "version".to_owned(), "gloves version".to_owned());
        record
            .stdout_lines
            .push("0123456789abcdefghijklmnop".to_owned());
        app.run_history.push(record);
        let terminal_area = Rect::new(0, 0, 140, 40);
        let root_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(UI_HEADER_HEIGHT),
                Constraint::Min(1),
                Constraint::Length(UI_FOOTER_HEIGHT),
            ])
            .split(terminal_area);
        let body_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(28),
                Constraint::Percentage(32),
                Constraint::Percentage(40),
            ])
            .split(root_chunks[1]);
        let output_area = body_chunks[2];

        app.on_mouse(
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: output_area.x + 1,
                row: output_area.y + 1,
                modifiers: KeyModifiers::SHIFT,
            },
            terminal_area,
        );

        assert_eq!(app.output_horizontal_scroll, HORIZONTAL_SCROLL_STEP);
        assert_eq!(app.focus, FocusPane::Commands);
    }

    #[test]
    fn mouse_wheel_scrolls_command_tree_selection() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        let terminal_area = Rect::new(0, 0, 140, 40);
        let root_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(UI_HEADER_HEIGHT),
                Constraint::Min(1),
                Constraint::Length(UI_FOOTER_HEIGHT),
            ])
            .split(terminal_area);
        let body_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(28),
                Constraint::Percentage(32),
                Constraint::Percentage(40),
            ])
            .split(root_chunks[1]);
        let command_area = body_chunks[0];
        let initial_index = app.selected_command_tree_row;

        app.on_mouse(
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: command_area.x + 1,
                row: command_area.y + 1,
                modifiers: KeyModifiers::NONE,
            },
            terminal_area,
        );
        assert!(app.selected_command_tree_row >= initial_index);

        app.on_mouse(
            MouseEvent {
                kind: MouseEventKind::ScrollUp,
                column: command_area.x + 1,
                row: command_area.y + 1,
                modifiers: KeyModifiers::NONE,
            },
            terminal_area,
        );
        assert_eq!(app.selected_command_tree_row, initial_index);
    }

    #[test]
    fn output_horizontal_scroll_is_clamped_to_content_width() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        app.focus = FocusPane::Output;
        app.output_viewport_width = 10;
        let mut record = RunRecord::new(4, "version".to_owned(), "gloves version".to_owned());
        record
            .stdout_lines
            .push("0123456789abcdefghijklmnop".to_owned());
        app.run_history.push(record);
        let expected_max = app.max_horizontal_scroll_for_pane(FocusPane::Output);

        for _ in 0..40 {
            app.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE))
                .expect("right scroll");
        }

        assert_eq!(app.output_horizontal_scroll, expected_max);

        for _ in 0..40 {
            app.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE))
                .expect("left scroll");
        }

        assert_eq!(app.output_horizontal_scroll, 0);
    }

    #[test]
    fn o_key_focuses_output_pane() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        app.focus = FocusPane::Commands;
        app.on_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE))
            .expect("focus output");

        assert_eq!(app.focus, FocusPane::Output);
        assert_eq!(app.status_line, "Focus -> execution output");
    }

    #[test]
    fn output_scroll_follow_tail_transitions_with_manual_navigation() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        let run_id = 9;
        let mut record = RunRecord::new(run_id, "version".to_owned(), "gloves version".to_owned());
        for index in 0..32 {
            record.stdout_lines.push(format!("line-{index}"));
        }
        record.phase = RunPhase::Succeeded;
        record.exit_code = Some(0);
        record.finished_instant = Some(Instant::now());
        record.finished_at = Some(chrono::Local::now());
        app.run_history.push(record);
        app.output_viewport_height = 6;
        app.follow_tail = true;
        app.sync_output_scroll();

        let tail_start = tail_scroll_start(app.output_line_count(), app.output_viewport_height);
        assert_eq!(app.output_scroll, tail_start);

        app.on_output_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert!(!app.follow_tail);

        app.on_output_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        assert!(app.follow_tail);
        assert_eq!(
            app.output_scroll,
            tail_scroll_start(app.output_line_count(), app.output_viewport_height)
        );
    }

    #[test]
    fn fullscreen_toggle_follows_focused_pane() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        assert!(!app.fullscreen_enabled);

        app.focus = FocusPane::Output;
        app.on_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE))
            .expect("toggle fullscreen on");
        assert!(app.fullscreen_enabled);
        assert!(app
            .status_line
            .contains("Fullscreen enabled for output pane"));

        app.focus = FocusPane::Commands;
        app.on_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE))
            .expect("toggle fullscreen off");
        assert!(!app.fullscreen_enabled);
        assert_eq!(app.status_line, "Fullscreen disabled");
    }

    #[test]
    fn escape_exits_fullscreen_before_quitting() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        app.focus = FocusPane::Fields;
        app.fullscreen_enabled = true;

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .expect("Esc should exit fullscreen");
        assert!(!app.fullscreen_enabled);
        assert_eq!(app.focus, FocusPane::Commands);
        assert!(!app.should_quit);

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .expect("Esc should quit from split view");
        assert!(app.should_quit);
    }

    #[test]
    fn text_field_edit_streams_updates_and_escape_reverts() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        let set_index = COMMAND_SPECS
            .iter()
            .position(|spec| spec.id == "set")
            .expect("set command exists");
        app.select_command_by_index(set_index);

        app.start_edit(false, 0);
        assert_eq!(app.input_mode_label(), "edit");

        app.on_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE))
            .expect("live update a");
        app.on_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE))
            .expect("live update b");

        match &app.command_fields[0].value {
            FieldValue::Text(value) => assert_eq!(value, "ab"),
            _ => panic!("expected text field"),
        }

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .expect("cancel edit");
        assert_eq!(app.input_mode_label(), "navigate");
        match &app.command_fields[0].value {
            FieldValue::Text(value) => assert!(value.is_empty()),
            _ => panic!("expected text field"),
        }
    }

    #[test]
    fn command_filter_edit_streams_updates_and_escape_reverts() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        assert!(app.command_filter.is_empty());

        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE))
            .expect("start filter edit");
        app.on_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE))
            .expect("live filter update");
        assert_eq!(app.command_filter, "v");

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .expect("cancel filter edit");
        assert!(app.command_filter.is_empty());
        assert_eq!(app.input_mode_label(), "navigate");
    }

    #[test]
    fn enter_cycle_moves_focus_from_leaf_commands_to_globals_to_fields() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        let set_index = COMMAND_SPECS
            .iter()
            .position(|spec| spec.id == "set")
            .expect("set command exists");
        let rows = app.command_tree_rows();
        let set_row = rows
            .iter()
            .position(|row| row.command_index == Some(set_index))
            .expect("set row exists");
        app.selected_command_tree_row = set_row;
        app.reconcile_tree_selection();
        app.focus = FocusPane::Commands;
        assert_eq!(app.focus, FocusPane::Commands);

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("commands -> globals");
        assert_eq!(app.focus, FocusPane::Globals);

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("globals -> fields");
        assert_eq!(app.focus, FocusPane::Fields);
    }

    #[test]
    fn enter_cycle_runs_from_fields_and_returns_focus_to_commands() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        let revoke_index = COMMAND_SPECS
            .iter()
            .position(|spec| spec.id == "revoke")
            .expect("revoke command exists");
        let rows = app.command_tree_rows();
        let revoke_row = rows
            .iter()
            .position(|row| row.command_index == Some(revoke_index))
            .expect("revoke row exists");
        app.selected_command_tree_row = revoke_row;
        app.reconcile_tree_selection();
        app.focus = FocusPane::Fields;

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("fields -> run -> commands");
        assert_eq!(app.focus, FocusPane::Commands);
        assert_eq!(app.status_line, "Validation failed");
        assert_eq!(app.run_history.len(), 1);
    }

    #[test]
    fn enter_in_fullscreen_keeps_focus_on_current_pane() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        app.fullscreen_enabled = true;

        app.focus = FocusPane::Commands;
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("enter in fullscreen commands");
        assert_eq!(app.focus, FocusPane::Commands);

        app.focus = FocusPane::Globals;
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("enter in fullscreen globals");
        assert_eq!(app.focus, FocusPane::Globals);

        app.focus = FocusPane::Output;
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("enter in fullscreen output");
        assert_eq!(app.focus, FocusPane::Output);

        let revoke_index = COMMAND_SPECS
            .iter()
            .position(|spec| spec.id == "revoke")
            .expect("revoke command exists");
        let rows = app.command_tree_rows();
        let revoke_row = rows
            .iter()
            .position(|row| row.command_index == Some(revoke_index))
            .expect("revoke row exists");
        app.selected_command_tree_row = revoke_row;
        app.reconcile_tree_selection();
        app.focus = FocusPane::Fields;

        let run_count_before = app.run_history.len();
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("enter in fullscreen fields");
        assert_eq!(app.focus, FocusPane::Fields);
        assert_eq!(app.run_history.len(), run_count_before + 1);
        assert!(app.status_line.contains("(fullscreen focus retained)"));
    }

    #[test]
    fn enter_on_command_branch_toggles_expand_collapse() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        let rows = app.command_tree_rows();
        let requests_index = rows
            .iter()
            .position(|row| row.label == "requests" && row.is_branch)
            .expect("requests branch exists");
        let requests_key = rows[requests_index].key.clone();
        app.selected_command_tree_row = requests_index;
        app.focus = FocusPane::Commands;
        assert!(app.expanded_command_tree_paths.contains(&requests_key));

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("collapse branch");
        assert!(!app.expanded_command_tree_paths.contains(&requests_key));
        assert_eq!(app.focus, FocusPane::Commands);

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("expand branch");
        assert!(app.expanded_command_tree_paths.contains(&requests_key));
        assert_eq!(app.focus, FocusPane::Commands);
    }

    #[test]
    fn run_record_lifecycle_transitions_cover_success_failure_and_cancel() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());

        let success_run_id = 21;
        app.run_history.push(RunRecord::new(
            success_run_id,
            "version".to_owned(),
            "gloves version".to_owned(),
        ));
        app.finish_run_with_status(
            success_run_id,
            "version",
            cargo_status(&["--version"]),
            false,
        );
        let success_record = app.run_record_mut(success_run_id).expect("success record");
        assert_eq!(success_record.phase, RunPhase::Succeeded);
        assert!(success_record.exit_code == Some(0));

        let failed_run_id = 22;
        app.run_history.push(RunRecord::new(
            failed_run_id,
            "version".to_owned(),
            "gloves version --not-a-real-flag".to_owned(),
        ));
        app.finish_run_with_status(
            failed_run_id,
            "version",
            cargo_status(&["--not-a-real-flag"]),
            false,
        );
        let failed_record = app.run_record_mut(failed_run_id).expect("failed record");
        assert_eq!(failed_record.phase, RunPhase::Failed);
        assert!(failed_record.exit_code.is_some());

        let cancelled_run_id = 23;
        app.run_history.push(RunRecord::new(
            cancelled_run_id,
            "daemon".to_owned(),
            "gloves daemon".to_owned(),
        ));
        app.finish_run_with_status(
            cancelled_run_id,
            "daemon",
            cargo_status(&["--version"]),
            true,
        );
        let cancelled_record = app
            .run_record_mut(cancelled_run_id)
            .expect("cancelled record");
        assert_eq!(cancelled_record.phase, RunPhase::Cancelled);
    }

    #[test]
    fn run_record_rendering_keeps_summary_when_streams_are_empty() {
        let mut record = RunRecord::new(3, "version".to_owned(), "gloves version".to_owned());
        record.phase = RunPhase::Succeeded;
        record.exit_code = Some(0);
        record.finished_instant = Some(Instant::now());
        record.finished_at = Some(chrono::Local::now());
        let rendered = record.render_lines();

        assert!(rendered
            .iter()
            .any(|line| line.contains("run #003") && line.contains("phase: succeeded")));
        assert!(rendered.iter().any(|line| line.contains("exit: 0")));
        assert!(rendered.iter().any(|line| line == "stdout:"));
        assert!(rendered.iter().any(|line| line == "stderr:"));
    }

    #[test]
    fn output_history_respects_global_retention_cap() {
        let mut app = TuiApp::new(NavigatorLaunchOptions::default());
        for index in 0..64 {
            let mut record = RunRecord::new(
                index as u64,
                format!("command-{index}"),
                format!("gloves command-{index}"),
            );
            for line in 0..128 {
                record.stdout_lines.push(format!("stdout-{index}-{line}"));
            }
            record.phase = RunPhase::Succeeded;
            record.exit_code = Some(0);
            record.finished_instant = Some(Instant::now());
            record.finished_at = Some(chrono::Local::now());
            app.run_history.push(record);
        }
        app.enforce_history_retention();
        assert!(app.flattened_history_line_count() <= MAX_OUTPUT_LINES);

        app.output_scroll = u16::MAX;
        app.follow_tail = false;
        app.sync_output_scroll();
        assert!(app.output_scroll <= app.max_output_scroll(app.output_line_count()));
    }
}
