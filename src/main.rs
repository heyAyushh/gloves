use std::{io::Write, process::Command as ProcessCommand, thread, time::Duration};

use clap::{error::ErrorKind, Parser};

use gloves::{
    cli::{run, Cli, ErrorFormatArg},
    error::{classify_error_code, GlovesError, ValidationError},
};

const CLI_GLOBAL_HELP_HINT: &str =
    "help: run `gloves --help` for global usage or `gloves help [topic...]` for command details";
const CLI_TTL_HINT: &str = "hint: use a positive day count, for example `--ttl 1`";
const CLI_FORBIDDEN_HINT: &str = "hint: this action is blocked by policy. check ACLs with `gloves access paths --agent <id> --json` and review `.gloves.toml`";
const CLI_NOT_FOUND_HINT: &str =
    "hint: check existing entries with `gloves list` or pending requests with `gloves requests list`";
const CLI_ALREADY_EXISTS_HINT: &str =
    "hint: entry already exists. choose a new name or remove the old one with `gloves secrets revoke <name>`";
const CLI_UNAUTHORIZED_HINT: &str = "hint: this caller is not authorized for the operation. check `--agent` and request/approval state";
const CLI_EXPIRED_HINT: &str =
    "hint: the item has expired. rotate by creating a new value (`gloves secrets set <name> ...`) and retry";
const CLI_GPG_DENIED_HINT: &str =
    "hint: `pass`/GPG denied access. verify your session can read it with `pass show <secret-name>`";
const CLI_INTEGRITY_HINT: &str =
    "hint: integrity verification failed. run `gloves verify`; if needed, rotate the secret";
const CLI_NAME_RULE_HINT: &str =
    "hint: secret names must be 1..=128 chars, no traversal, and only `[A-Za-z0-9._/-]`";
const CLI_PATH_TRAVERSAL_HINT: &str =
    "hint: secret names cannot start with `/`, contain `..`, or contain `//`";
const CLI_IO_HINT: &str =
    "hint: check path existence and permissions for `--root` (default `.openclaw/secrets`)";
const CLI_REQUEST_PENDING_HINT: &str =
    "hint: request may already be resolved. check current pending requests with `gloves requests list`";
const CLI_PIPE_POLICY_HINT: &str = "hint: for safe secret piping, configure `GLOVES_GET_PIPE_ALLOWLIST` or command policy in `.gloves.toml`";
const CLI_MISSING_RUNTIME_HINT: &str =
    "hint: install the missing runtime binary and ensure it is available in PATH";

const PARSE_ERROR_CODE: &str = "E001";
const PARSE_SUGGESTION_MARKER: &str = "a similar subcommand exists: '";
const PARSE_SUGGESTIONS_MARKER: &str = "some similar subcommands exist:";
const PARSE_UNKNOWN_SUBCOMMAND_MARKER: &str = "unrecognized subcommand '";
const AUTORUN_ENV: &str = "GLOVES_SUGGEST_AUTORUN";
const AUTORUN_RISKY_ENV: &str = "GLOVES_SUGGEST_AUTORUN_RISKY";
const AUTORUN_DELAY_ENV: &str = "GLOVES_SUGGEST_AUTORUN_DELAY_MS";
const AUTORUN_DEFAULT_DELAY_MS: u64 = 1200;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CliErrorFormat {
    Text,
    Json,
}

#[derive(Debug, Clone)]
struct SubcommandSuggestion {
    unknown: String,
    suggested: String,
    corrected_args: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AutoRunDecision {
    Disabled,
    BlockedRisky,
    Enabled { delay_ms: u64 },
}

impl From<ErrorFormatArg> for CliErrorFormat {
    fn from(value: ErrorFormatArg) -> Self {
        match value {
            ErrorFormatArg::Text => CliErrorFormat::Text,
            ErrorFormatArg::Json => CliErrorFormat::Json,
        }
    }
}

fn main() {
    let invocation_args = std::env::args().skip(1).collect::<Vec<_>>();
    let fallback_error_format = parse_error_format_from_args(&invocation_args);

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(parse_error) => {
            let exit_code =
                handle_parse_error(parse_error, fallback_error_format, &invocation_args);
            std::process::exit(exit_code);
        }
    };

    let error_format = CliErrorFormat::from(cli.error_format);
    match run(cli) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            let exit_code = write_runtime_error(error_format, &error);
            std::process::exit(exit_code);
        }
    }
}

fn write_runtime_error(error_format: CliErrorFormat, error: &GlovesError) -> i32 {
    match error_format {
        CliErrorFormat::Text => write_runtime_error_text(error),
        CliErrorFormat::Json => write_runtime_error_json(error),
    }
    1
}

fn write_runtime_error_text(error: &GlovesError) {
    let error_code = classify_error_code(error);
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    let _ = handle.write_all(format!("error[{error_code}]: {error}\n").as_bytes());
    let _ = handle.write_all(
        format!("explain: run `gloves explain {error_code}` for detailed recovery\n").as_bytes(),
    );
    for hint in collect_error_hints(error) {
        let _ = handle.write_all(format!("{hint}\n").as_bytes());
    }
    let _ = handle.flush();
}

fn write_runtime_error_json(error: &GlovesError) {
    let error_code = classify_error_code(error);
    let payload = serde_json::json!({
        "kind": "runtime_error",
        "code": error_code,
        "message": error.to_string(),
        "explain": format!("gloves explain {error_code}"),
        "hints": collect_error_hints(error),
    });
    write_json_stderr(&payload);
}

fn collect_error_hints(error: &GlovesError) -> Vec<String> {
    let mut hints = vec![CLI_GLOBAL_HELP_HINT.to_owned()];
    match error {
        GlovesError::InvalidInput(message) => {
            if message.contains("--ttl must be greater than zero") {
                hints.push(CLI_TTL_HINT.to_owned());
            }
            if message.contains("request is not pending") {
                hints.push(CLI_REQUEST_PENDING_HINT.to_owned());
            }
            if message.contains("required binary not found:") {
                hints.push(CLI_MISSING_RUNTIME_HINT.to_owned());
            }
            if message.contains("not allowlisted") || message.contains("secret piping is disabled")
            {
                hints.push(CLI_PIPE_POLICY_HINT.to_owned());
            }
        }
        GlovesError::Validation(validation_error) => match validation_error {
            ValidationError::InvalidName | ValidationError::InvalidCharacter => {
                hints.push(CLI_NAME_RULE_HINT.to_owned());
            }
            ValidationError::PathTraversal => {
                hints.push(CLI_PATH_TRAVERSAL_HINT.to_owned());
            }
        },
        GlovesError::Forbidden => {
            hints.push(CLI_FORBIDDEN_HINT.to_owned());
        }
        GlovesError::NotFound => {
            hints.push(CLI_NOT_FOUND_HINT.to_owned());
        }
        GlovesError::AlreadyExists => {
            hints.push(CLI_ALREADY_EXISTS_HINT.to_owned());
        }
        GlovesError::Unauthorized => {
            hints.push(CLI_UNAUTHORIZED_HINT.to_owned());
        }
        GlovesError::Expired => {
            hints.push(CLI_EXPIRED_HINT.to_owned());
        }
        GlovesError::GpgDenied => {
            hints.push(CLI_GPG_DENIED_HINT.to_owned());
        }
        GlovesError::IntegrityViolation => {
            hints.push(CLI_INTEGRITY_HINT.to_owned());
        }
        GlovesError::Io(_) => {
            hints.push(CLI_IO_HINT.to_owned());
        }
        GlovesError::Serde(_) | GlovesError::Utf8(_) | GlovesError::Crypto(_) => {}
    }
    hints
}

fn handle_parse_error(
    parse_error: clap::Error,
    error_format: CliErrorFormat,
    invocation_args: &[String],
) -> i32 {
    if matches!(
        parse_error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        print!("{parse_error}");
        return 0;
    }

    let message = parse_error.to_string();
    let suggestion = parse_subcommand_suggestion(&message, invocation_args);
    let autorun_decision = suggestion
        .as_ref()
        .map(|value| decide_autorun(&value.corrected_args))
        .unwrap_or(AutoRunDecision::Disabled);

    match error_format {
        CliErrorFormat::Text => {
            eprint!("{message}");
            if let Some(value) = suggestion.as_ref() {
                eprintln!(
                    "hint: rerun as `gloves {}`",
                    shell_words_join(&value.corrected_args)
                );
                eprintln!(
                    "hint: enable safe auto-run with `{AUTORUN_ENV}=1`; allow risky auto-run with `{AUTORUN_RISKY_ENV}=1`"
                );
            }
            match autorun_decision {
                AutoRunDecision::Enabled { delay_ms } => {
                    if let Some(value) = suggestion.as_ref() {
                        eprintln!(
                            "auto-run: executing corrected command in {delay_ms}ms: gloves {}",
                            shell_words_join(&value.corrected_args)
                        );
                    }
                }
                AutoRunDecision::BlockedRisky => {
                    eprintln!(
                        "auto-run: suggestion detected but blocked because the command can mutate state; set `{AUTORUN_RISKY_ENV}=1` to allow"
                    );
                }
                AutoRunDecision::Disabled => {}
            }
        }
        CliErrorFormat::Json => {
            let payload = serde_json::json!({
                "kind": "parse_error",
                "code": PARSE_ERROR_CODE,
                "message": message.trim_end(),
                "suggestion": suggestion.as_ref().map(|value| serde_json::json!({
                    "unknown": value.unknown,
                    "suggested": value.suggested,
                    "corrected_command": format!("gloves {}", shell_words_join(&value.corrected_args)),
                })),
                "autorun": match autorun_decision {
                    AutoRunDecision::Disabled => serde_json::json!({"status": "disabled"}),
                    AutoRunDecision::BlockedRisky => serde_json::json!({"status": "blocked_risky"}),
                    AutoRunDecision::Enabled { delay_ms } => serde_json::json!({"status": "enabled", "delay_ms": delay_ms}),
                },
                "hints": [
                    CLI_GLOBAL_HELP_HINT,
                    format!("set {AUTORUN_ENV}=1 for safe typo auto-run"),
                ],
            });
            write_json_stderr(&payload);
        }
    }

    if let (Some(value), AutoRunDecision::Enabled { delay_ms }) =
        (suggestion.as_ref(), autorun_decision)
    {
        thread::sleep(Duration::from_millis(delay_ms));
        return run_corrected_command(&value.corrected_args);
    }

    2
}

fn write_json_stderr(payload: &serde_json::Value) {
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    let serialized = serde_json::to_string_pretty(payload).unwrap_or_else(|_| {
        "{\"kind\":\"runtime_error\",\"code\":\"E999\",\"message\":\"failed to serialize error\"}"
            .to_owned()
    });
    let _ = handle.write_all(format!("{serialized}\n").as_bytes());
    let _ = handle.flush();
}

fn parse_error_format_from_args(args: &[String]) -> CliErrorFormat {
    let mut index = 0usize;
    while index < args.len() {
        let argument = &args[index];
        if let Some(value) = argument.strip_prefix("--error-format=") {
            return parse_error_format_value(value);
        }
        if argument == "--error-format" {
            if let Some(value) = args.get(index + 1) {
                return parse_error_format_value(value);
            }
            return CliErrorFormat::Text;
        }
        index += 1;
    }
    CliErrorFormat::Text
}

fn parse_error_format_value(value: &str) -> CliErrorFormat {
    if value.eq_ignore_ascii_case("json") {
        CliErrorFormat::Json
    } else {
        CliErrorFormat::Text
    }
}

fn parse_subcommand_suggestion(
    parse_error_message: &str,
    invocation_args: &[String],
) -> Option<SubcommandSuggestion> {
    let unknown =
        extract_single_quoted_value(parse_error_message, PARSE_UNKNOWN_SUBCOMMAND_MARKER)?;
    let candidates = parse_subcommand_candidates(parse_error_message);
    let suggested = choose_best_suggestion(&unknown, &candidates)?;
    let corrected_args = corrected_args_for_subcommand(invocation_args, &unknown, &suggested)?;
    Some(SubcommandSuggestion {
        unknown,
        suggested,
        corrected_args,
    })
}

fn parse_subcommand_candidates(parse_error_message: &str) -> Vec<String> {
    if let Some(suggested) =
        extract_single_quoted_value(parse_error_message, PARSE_SUGGESTION_MARKER)
    {
        return vec![suggested];
    }

    let Some(start_index) = parse_error_message.find(PARSE_SUGGESTIONS_MARKER) else {
        return Vec::new();
    };
    let start = start_index + PARSE_SUGGESTIONS_MARKER.len();
    let line = parse_error_message
        .get(start..)
        .and_then(|remainder| remainder.lines().next())
        .unwrap_or_default();
    extract_single_quoted_values(line)
}

fn choose_best_suggestion(unknown: &str, candidates: &[String]) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    for candidate in candidates {
        let distance = levenshtein_distance(unknown, candidate);
        match best.as_ref() {
            Some((best_distance, _)) if distance >= *best_distance => {}
            _ => {
                best = Some((distance, candidate.clone()));
            }
        }
    }
    best.map(|(_, candidate)| candidate)
}

fn extract_single_quoted_values(line: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut cursor = line;
    loop {
        let Some(start) = cursor.find('\'') else {
            break;
        };
        let tail = &cursor[start + 1..];
        let Some(end) = tail.find('\'') else {
            break;
        };
        values.push(tail[..end].to_owned());
        cursor = &tail[end + 1..];
    }
    values
}

fn levenshtein_distance(left: &str, right: &str) -> usize {
    let left_chars = left.chars().collect::<Vec<_>>();
    let right_chars = right.chars().collect::<Vec<_>>();
    if left_chars.is_empty() {
        return right_chars.len();
    }
    if right_chars.is_empty() {
        return left_chars.len();
    }

    let mut previous_row = (0..=right_chars.len()).collect::<Vec<_>>();
    let mut current_row = vec![0usize; right_chars.len() + 1];

    for (left_index, left_char) in left_chars.iter().enumerate() {
        current_row[0] = left_index + 1;
        for (right_index, right_char) in right_chars.iter().enumerate() {
            let insertion = current_row[right_index] + 1;
            let deletion = previous_row[right_index + 1] + 1;
            let substitution =
                previous_row[right_index] + if left_char == right_char { 0 } else { 1 };
            current_row[right_index + 1] = insertion.min(deletion).min(substitution);
        }
        std::mem::swap(&mut previous_row, &mut current_row);
    }

    previous_row[right_chars.len()]
}

fn extract_single_quoted_value(message: &str, marker: &str) -> Option<String> {
    let start_index = message.find(marker)?;
    let start = start_index + marker.len();
    let remainder = message.get(start..)?;
    let end = remainder.find('\'')?;
    remainder.get(..end).map(ToOwned::to_owned)
}

fn corrected_args_for_subcommand(
    invocation_args: &[String],
    unknown: &str,
    suggested: &str,
) -> Option<Vec<String>> {
    let command_index = top_level_command_index(invocation_args)?;
    if invocation_args.get(command_index)? != unknown {
        return None;
    }
    let mut corrected = invocation_args.to_vec();
    corrected[command_index] = suggested.to_owned();
    Some(corrected)
}

fn top_level_command_index(invocation_args: &[String]) -> Option<usize> {
    let mut index = 0usize;
    while index < invocation_args.len() {
        let argument = invocation_args.get(index)?;
        if argument == "--" {
            return None;
        }
        if let Some(step) = option_token_len(argument, invocation_args, index) {
            index += step;
            continue;
        }
        if argument.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(index);
    }
    None
}

fn option_token_len(argument: &str, invocation_args: &[String], index: usize) -> Option<usize> {
    if argument.starts_with("--root=")
        || argument.starts_with("--agent=")
        || argument.starts_with("--config=")
        || argument.starts_with("--vault-mode=")
        || argument.starts_with("--error-format=")
    {
        return Some(1);
    }
    if matches!(
        argument,
        "--root" | "--agent" | "--config" | "--vault-mode" | "--error-format"
    ) {
        if invocation_args.get(index + 1).is_some() {
            return Some(2);
        }
        return Some(1);
    }
    None
}

fn decide_autorun(corrected_args: &[String]) -> AutoRunDecision {
    if !env_truthy(AUTORUN_ENV) {
        return AutoRunDecision::Disabled;
    }
    if !is_autorun_safe_command(corrected_args) && !env_truthy(AUTORUN_RISKY_ENV) {
        return AutoRunDecision::BlockedRisky;
    }
    let delay_ms = std::env::var(AUTORUN_DELAY_ENV)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(AUTORUN_DEFAULT_DELAY_MS)
        .min(10_000);
    AutoRunDecision::Enabled { delay_ms }
}

fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn is_autorun_safe_command(corrected_args: &[String]) -> bool {
    let Some(command_index) = top_level_command_index(corrected_args) else {
        return false;
    };
    let command = corrected_args
        .get(command_index)
        .map(String::as_str)
        .unwrap_or_default();
    match command {
        "help" | "version" | "ver" | "explain" | "list" | "ls" | "audit" | "tui" | "ui" => true,
        "secrets" => matches!(
            corrected_args.get(command_index + 1).map(String::as_str),
            Some("help" | "get" | "status")
        ),
        "requests" | "req" => matches!(
            corrected_args.get(command_index + 1).map(String::as_str),
            Some("list")
        ),
        "config" => matches!(
            corrected_args.get(command_index + 1).map(String::as_str),
            Some("validate")
        ),
        "access" => matches!(
            corrected_args.get(command_index + 1).map(String::as_str),
            Some("paths")
        ),
        "vault" => matches!(
            corrected_args.get(command_index + 1).map(String::as_str),
            Some("status" | "list")
        ),
        "gpg" => matches!(
            corrected_args.get(command_index + 1).map(String::as_str),
            Some("fingerprint")
        ),
        _ => false,
    }
}

fn run_corrected_command(corrected_args: &[String]) -> i32 {
    let current_executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("auto-run failed: unable to locate current executable: {error}");
            return 1;
        }
    };
    let status = match ProcessCommand::new(current_executable)
        .args(corrected_args)
        .status()
    {
        Ok(status) => status,
        Err(error) => {
            eprintln!("auto-run failed: unable to execute corrected command: {error}");
            return 1;
        }
    };
    status.code().unwrap_or(1)
}

fn shell_words_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| match shlex::try_quote(arg) {
            Ok(value) => value.into_owned(),
            Err(_) => arg.replace('\0', ""),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod unit_tests {
    use super::{
        choose_best_suggestion, corrected_args_for_subcommand, decide_autorun,
        extract_single_quoted_value, parse_error_format_from_args, parse_subcommand_candidates,
        parse_subcommand_suggestion, AutoRunDecision, CliErrorFormat, PARSE_SUGGESTION_MARKER,
        PARSE_UNKNOWN_SUBCOMMAND_MARKER,
    };

    #[test]
    fn parse_error_format_detects_json_long_form() {
        let format = parse_error_format_from_args(&[
            "--error-format".to_owned(),
            "json".to_owned(),
            "version".to_owned(),
        ]);
        assert_eq!(format, CliErrorFormat::Json);
    }

    #[test]
    fn parse_error_format_detects_json_equals_form() {
        let format = parse_error_format_from_args(&["--error-format=json".to_owned()]);
        assert_eq!(format, CliErrorFormat::Json);
    }

    #[test]
    fn extract_single_quoted_value_extracts_marker_value() {
        let text = "error: unrecognized subcommand 'aproov'";
        let value = extract_single_quoted_value(text, PARSE_UNKNOWN_SUBCOMMAND_MARKER).unwrap();
        assert_eq!(value, "aproov");
    }

    #[test]
    fn parse_subcommand_suggestion_extracts_replacement() {
        let error = "error: unrecognized subcommand 'aproov'\n\n  tip: a similar subcommand exists: 'approve'\n";
        let suggestion =
            parse_subcommand_suggestion(error, &["aproov".to_owned(), "x".to_owned()]).unwrap();
        assert_eq!(suggestion.unknown, "aproov");
        assert_eq!(suggestion.suggested, "approve");
        assert_eq!(
            suggestion.corrected_args,
            vec!["approve".to_owned(), "x".to_owned()]
        );
    }

    #[test]
    fn parse_subcommand_suggestion_chooses_best_candidate_from_plural_tip() {
        let error = "error: unrecognized subcommand 'versoin'\n\n  tip: some similar subcommands exist: 'verify', 'ver', 'version'\n";
        let suggestion = parse_subcommand_suggestion(error, &["versoin".to_owned()]).unwrap();
        assert_eq!(suggestion.suggested, "version");
        assert_eq!(suggestion.corrected_args, vec!["version".to_owned()]);
    }

    #[test]
    fn parse_subcommand_candidates_extracts_plural_list() {
        let error = "tip: some similar subcommands exist: 'verify', 'ver', 'version'";
        let candidates = parse_subcommand_candidates(error);
        assert_eq!(
            candidates,
            vec!["verify".to_owned(), "ver".to_owned(), "version".to_owned()]
        );
    }

    #[test]
    fn choose_best_suggestion_prefers_smallest_distance() {
        let best = choose_best_suggestion(
            "versoin",
            &["verify".to_owned(), "ver".to_owned(), "version".to_owned()],
        )
        .unwrap();
        assert_eq!(best, "version");
    }

    #[test]
    fn corrected_args_requires_command_position_match() {
        let corrected = corrected_args_for_subcommand(
            &["set".to_owned(), "aproov".to_owned()],
            "aproov",
            "approve",
        );
        assert!(corrected.is_none());
    }

    #[test]
    fn decide_autorun_defaults_to_disabled() {
        let decision = decide_autorun(&["version".to_owned()]);
        assert_eq!(decision, AutoRunDecision::Disabled);
    }

    #[test]
    fn suggestion_marker_constant_is_expected() {
        assert_eq!(PARSE_SUGGESTION_MARKER, "a similar subcommand exists: '");
    }
}
