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
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
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
const SET_INPUT_MODE_GENERATE_INDEX: usize = 0;
const SET_INPUT_MODE_VALUE_INDEX: usize = 1;
const SET_INPUT_MODE_STDIN_INDEX: usize = 2;
const EMPTY_FILTER_PLACEHOLDER: &str = "<no matching commands>";

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
    global_fields: Vec<FieldState>,
    command_fields: Vec<FieldState>,
    run_history: Vec<RunRecord>,
    next_run_id: u64,
    active_run: Option<ActiveRun>,
    output_scroll: u16,
    output_viewport_height: u16,
    follow_tail: bool,
    status_line: String,
    pending_risky_signature: Option<String>,
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

const VERSION_FIELDS: &[FieldSpec] = &[FieldSpec {
    id: "json",
    label: "JSON",
    help: "--json",
    required: false,
    kind: FieldKind::Bool,
    arg: FieldArg::Flag("--json"),
    default_text: "",
    default_bool: false,
    default_choice: 0,
}];

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

const AUDIT_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "limit",
        label: "Limit",
        help: "--limit (default 50)",
        required: false,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--limit"),
        default_text: "50",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "json",
        label: "JSON",
        help: "--json",
        required: false,
        kind: FieldKind::Bool,
        arg: FieldArg::Flag("--json"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

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

const ACCESS_PATHS_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "agent",
        label: "Agent",
        help: "--agent id",
        required: true,
        kind: FieldKind::Text,
        arg: FieldArg::OptionValue("--agent"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
    FieldSpec {
        id: "json",
        label: "JSON",
        help: "--json",
        required: false,
        kind: FieldKind::Bool,
        arg: FieldArg::Flag("--json"),
        default_text: "",
        default_bool: false,
        default_choice: 0,
    },
];

const COMMAND_SPECS: &[CommandSpec] = &[
    CommandSpec {
        id: "init",
        title: "init",
        summary: "Initialize runtime layout",
        path: &["init"],
        fields: NO_FIELDS,
    },
    CommandSpec {
        id: "version",
        title: "version",
        summary: "Print version/runtime defaults",
        path: &["version"],
        fields: VERSION_FIELDS,
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
        title: "set",
        summary: "Store an agent secret",
        path: &["set"],
        fields: SET_FIELDS,
    },
    CommandSpec {
        id: "get",
        title: "get",
        summary: "Read a secret",
        path: &["get"],
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
        id: "approve",
        title: "approve",
        summary: "Approve pending request",
        path: &["approve"],
        fields: REQUEST_ID_FIELD,
    },
    CommandSpec {
        id: "deny",
        title: "deny",
        summary: "Deny pending request",
        path: &["deny"],
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
        title: "grant",
        summary: "Grant secret access to an agent",
        path: &["grant"],
        fields: GRANT_FIELDS,
    },
    CommandSpec {
        id: "revoke",
        title: "revoke",
        summary: "Revoke a secret",
        path: &["revoke"],
        fields: SECRET_NAME_FIELD,
    },
    CommandSpec {
        id: "status",
        title: "status",
        summary: "Show request status",
        path: &["status"],
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
    "version",
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
const TREE_HIDDEN_COMMAND_IDS: &[&str] = &["approve", "deny"];
const ENTRIES_LIST_TREE_PATH: &[&str] = &["entries", "list"];

fn is_tree_hidden_command(command_id: &str) -> bool {
    TREE_HIDDEN_COMMAND_IDS.contains(&command_id)
}

fn command_tree_path(command_spec: &CommandSpec) -> Option<&'static [&'static str]> {
    if is_tree_hidden_command(command_spec.id) {
        return None;
    }
    if command_spec.id == "list" {
        return Some(ENTRIES_LIST_TREE_PATH);
    }
    Some(command_spec.path)
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

pub(crate) fn run_command_navigator() -> Result<()> {
    if !atty::is(atty::Stream::Stdin) || !atty::is(atty::Stream::Stdout) {
        return Err(GlovesError::InvalidInput(
            "`gloves tui` requires an interactive terminal".to_owned(),
        ));
    }

    let mut terminal = init_terminal()?;
    let run_result = run_event_loop(&mut terminal);
    let restore_result = restore_terminal(&mut terminal);
    restore_result?;
    run_result
}

fn init_terminal() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn run_event_loop(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
    let mut app = TuiApp::new();
    while !app.should_quit {
        app.poll_active_run();
        terminal.draw(|frame| app.render(frame))?;
        if !event::poll(Duration::from_millis(NAVIGATOR_EVENT_POLL_MILLIS))? {
            continue;
        }
        let event = event::read()?;
        if let Event::Key(key) = event {
            app.on_key(key)?;
        }
    }
    Ok(())
}

impl TuiApp {
    fn new() -> Self {
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
            global_fields: GLOBAL_FIELDS.iter().map(initial_field_state).collect(),
            command_fields,
            run_history: Vec::new(),
            next_run_id: 1,
            active_run: None,
            output_scroll: 0,
            output_viewport_height: 0,
            follow_tail: true,
            status_line: "Ready".to_owned(),
            pending_risky_signature: None,
            should_quit: false,
        };
        app.select_first_visible_leaf();
        app
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
            KeyCode::Esc | KeyCode::Char('q') => {
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
                self.status_line = "Editing command filter".to_owned();
            }
            KeyCode::Char('?') => {
                self.execute_selected_help()?;
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

    fn on_navigation_key(&mut self, key: KeyEvent) {
        match self.focus {
            FocusPane::Commands => self.on_command_list_key(key),
            FocusPane::Globals => self.on_field_list_key(key, true),
            FocusPane::Fields => self.on_field_list_key(key, false),
            FocusPane::Output => self.on_output_key(key),
        }
    }

    fn on_edit_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Navigate;
                self.editing_target = None;
                self.editing_buffer.clear();
                self.status_line = "Edit canceled".to_owned();
            }
            KeyCode::Enter => {
                self.commit_edit_buffer();
            }
            KeyCode::Backspace => {
                self.editing_buffer.pop();
            }
            KeyCode::Char(character) => {
                self.editing_buffer.push(character);
            }
            _ => {}
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
            KeyCode::Right | KeyCode::Char('l') => {
                if let Some(row) = rows.get(self.selected_command_tree_row) {
                    if row.is_branch {
                        self.expanded_command_tree_paths.insert(row.key.clone());
                    }
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
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
            KeyCode::Left | KeyCode::Char('h') => {
                self.cycle_choice(global, selected_index, false);
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.cycle_choice(global, selected_index, true);
            }
            KeyCode::Char(' ') => {
                self.toggle_bool(global, selected_index);
            }
            KeyCode::Char('e') | KeyCode::Char('i') | KeyCode::Enter => {
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
        let filter_text = if self.command_filter.is_empty() {
            "<none>".to_owned()
        } else {
            self.command_filter.clone()
        };
        let header = Paragraph::new(format!(
            "gloves tui | mode: {} | focus: {} | confirm: {} | filter: {} | status: {}",
            self.input_mode_label(),
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

        let footer_text = if self.input_mode == InputMode::Edit {
            "Edit: type, Enter=save, Esc=cancel"
        } else {
            "Navigate: Tab switch pane, / filter, Up/Down move, Left/Right expand/collapse tree (or cycle choices in field panes), Space toggle bool, e edit text, Enter toggle tree node, ? help, r/F5 run, Ctrl+C cancel active run, Home/g top, End/G tail, x/X reset field, c clear output, q quit"
        };
        let footer = Paragraph::new(footer_text)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title("Keys"));
        frame.render_widget(footer, root_chunks[2]);
    }

    fn render_commands(&self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        let rows = self.command_tree_rows();
        let visible_leaf_count = rows
            .iter()
            .filter(|row| row.command_index.is_some())
            .count();
        let items = if rows.is_empty() {
            vec![ListItem::new(Line::from(EMPTY_FILTER_PLACEHOLDER))]
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
                    let mut spans = vec![Span::raw(format!("{indent}{marker} "))];
                    if row.command_index.is_some() {
                        spans.push(Span::styled(
                            row.label.clone(),
                            Style::default().add_modifier(Modifier::BOLD),
                        ));
                    } else {
                        spans.push(Span::raw(row.label.clone()));
                    }
                    if let Some(command_index) = row.command_index {
                        if let Some(spec) = COMMAND_SPECS.get(command_index) {
                            spans.push(Span::raw(format!("  {}", spec.summary)));
                        }
                    }
                    ListItem::new(Line::from(spans))
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

    fn render_forms(&self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        let form_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(area);
        self.render_field_list(frame, form_chunks[0], true);
        self.render_field_list(frame, form_chunks[1], false);
    }

    fn render_field_list(
        &self,
        frame: &mut ratatui::Frame,
        area: ratatui::layout::Rect,
        global: bool,
    ) {
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

        let items = fields
            .iter()
            .map(|field_state| {
                let suffix = if field_state.spec.required { " *" } else { "" };
                let value = field_display_value(field_state);
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{}{}: ", field_state.spec.label, suffix),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(value),
                    Span::raw(format!("  [{}]", field_state.spec.help)),
                ]))
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
        self.sync_output_scroll();
        let title = pane_title("Execution Output", self.focus == FocusPane::Output);
        let rendered_lines = self.flatten_output_lines();
        let output_text = if rendered_lines.is_empty() {
            "No output yet".to_owned()
        } else {
            rendered_lines.join("\n")
        };
        let output_widget = Paragraph::new(output_text)
            .wrap(Wrap { trim: false })
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
    section_lines.push(line);
    if section_lines.len() > MAX_OUTPUT_SECTION_LINES {
        let overflow = section_lines.len() - MAX_OUTPUT_SECTION_LINES;
        section_lines.drain(0..overflow);
    }
}

fn tail_scroll_start(total_lines: usize, viewport_height: u16) -> u16 {
    if total_lines == 0 {
        return 0;
    }
    let viewport = usize::max(usize::from(viewport_height), 1);
    let page_index = total_lines.saturating_sub(1) / viewport;
    (page_index * viewport).min(u16::MAX as usize) as u16
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
        build_command_tree, build_invocation_args, field_states_for_spec, initial_field_state,
        is_risky_command, stdin_payload_for_command, tail_scroll_start, CommandSpec,
        CommandTreeNode, FieldState, FieldValue, RunPhase, RunRecord, TuiApp, COMMAND_SPECS,
        GLOBAL_FIELDS, MAX_OUTPUT_LINES,
    };
    use crate::cli::Cli;
    use clap::CommandFactory;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
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
        let version = node_by_label(&tree, "version");
        assert!(init.command_index.is_some());
        assert!(version.command_index.is_some());
        assert!(init.children.is_empty());
        assert!(version.children.is_empty());
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
        assert!(!is_risky_command("version"));
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
    fn output_scroll_follow_tail_transitions_with_manual_navigation() {
        let mut app = TuiApp::new();
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
    fn run_record_lifecycle_transitions_cover_success_failure_and_cancel() {
        let mut app = TuiApp::new();

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
        let mut app = TuiApp::new();
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
