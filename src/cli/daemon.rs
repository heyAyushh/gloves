use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener},
    path::Path,
    time::Duration as StdDuration,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use chrono::Duration;

use crate::{
    error::{GlovesError, Result},
    fs_secure::ensure_private_dir,
    paths::SecretsPaths,
    reaper::TtlReaper,
    types::{AgentId, Owner, SecretId, SecretValue},
    vault::gocryptfs::GocryptfsDriver,
};

use super::{
    output::{self, OutputStatus},
    runtime, secret_input, DEFAULT_AGENT_ID, DEFAULT_TTL_DAYS,
};

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum DaemonRequest {
    Ping,
    List,
    Verify,
    Status {
        name: String,
    },
    Get {
        name: String,
    },
    Set {
        name: String,
        #[serde(default)]
        generate: bool,
        value: Option<String>,
        ttl_days: Option<i64>,
    },
    Revoke {
        name: String,
    },
    Request {
        name: String,
        reason: String,
    },
    Approve {
        request_id: String,
    },
    Deny {
        request_id: String,
    },
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum DaemonResponse {
    Ok {
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },
    Error {
        error: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DaemonRuntimeOptions {
    pub io_timeout_seconds: u64,
    pub request_limit_bytes: usize,
}

pub(crate) fn run_daemon(
    paths: &SecretsPaths,
    bind: &str,
    options: DaemonRuntimeOptions,
    check: bool,
    max_requests: usize,
) -> Result<()> {
    runtime::init_layout(paths)?;
    enforce_daemon_root_strictness(paths)?;
    run_daemon_tcp(paths, bind, options, check, max_requests)
}

#[cfg(unix)]
fn assert_private_directory(path: &Path, label: &str) -> Result<()> {
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(GlovesError::InvalidInput(format!(
            "{label} must not be group/world accessible: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn assert_private_directory(path: &Path, _label: &str) -> Result<()> {
    let _ = path;
    Ok(())
}

fn enforce_daemon_root_strictness(paths: &SecretsPaths) -> Result<()> {
    ensure_private_dir(paths.root())?;
    assert_private_directory(paths.root(), "secrets root")?;
    Ok(())
}

fn parse_daemon_bind(bind: &str) -> Result<SocketAddr> {
    let bind_addr = bind.parse::<SocketAddr>().map_err(|error| {
        GlovesError::InvalidInput(format!("invalid daemon bind address: {error}"))
    })?;
    if bind_addr.port() == 0 {
        return Err(GlovesError::InvalidInput(
            "daemon bind port must be non-zero".to_owned(),
        ));
    }
    if !bind_addr.ip().is_loopback() {
        return Err(GlovesError::InvalidInput(
            "daemon bind address must be loopback (127.0.0.1 or ::1)".to_owned(),
        ));
    }
    Ok(bind_addr)
}

fn run_daemon_tcp(
    paths: &SecretsPaths,
    bind: &str,
    options: DaemonRuntimeOptions,
    check: bool,
    max_requests: usize,
) -> Result<()> {
    let bind_addr = parse_daemon_bind(bind)?;
    if check {
        let listener = TcpListener::bind(bind_addr)?;
        drop(listener);
        emit_stdout_line("ok")?;
        return Ok(());
    }

    let listener = TcpListener::bind(bind_addr)?;
    let listening_addr = listener.local_addr()?;
    emit_stdout_line(&format!("listening: {listening_addr}"))?;

    let mut handled_requests = 0_usize;
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                let _ = emit_stderr_line(&format!("error: daemon accept failed: {error}"));
                continue;
            }
        };
        let io_timeout = Some(StdDuration::from_secs(options.io_timeout_seconds));
        if let Err(error) = stream.set_read_timeout(io_timeout) {
            let _ = emit_stderr_line(&format!("error: daemon read-timeout setup failed: {error}"));
            continue;
        }
        if let Err(error) = stream.set_write_timeout(io_timeout) {
            let _ = emit_stderr_line(&format!(
                "error: daemon write-timeout setup failed: {error}"
            ));
            continue;
        }

        if let Err(error) =
            handle_daemon_connection(paths, &mut stream, options.request_limit_bytes)
        {
            let _ = write_daemon_response(
                &mut stream,
                &DaemonResponse::Error {
                    error: error.to_string(),
                },
            );
        }

        handled_requests += 1;
        if max_requests > 0 && handled_requests >= max_requests {
            break;
        }
    }
    Ok(())
}

fn emit_stdout_line(line: &str) -> Result<()> {
    match output::stdout_line(line) {
        Ok(OutputStatus::Written | OutputStatus::BrokenPipe) => Ok(()),
        Err(error) => Err(GlovesError::Io(error)),
    }
}

fn emit_stderr_line(line: &str) -> std::io::Result<()> {
    match output::stderr_line(line) {
        Ok(OutputStatus::Written | OutputStatus::BrokenPipe) => Ok(()),
        Err(error) => Err(error),
    }
}

fn handle_daemon_connection<S>(
    paths: &SecretsPaths,
    stream: &mut S,
    request_limit_bytes: usize,
) -> Result<()>
where
    S: Read + Write,
{
    let request = read_daemon_request(stream, request_limit_bytes)?;
    let response = execute_daemon_request(paths, request);
    write_daemon_response(stream, &response)
}

fn read_daemon_request<R>(stream: &mut R, request_limit_bytes: usize) -> Result<DaemonRequest>
where
    R: Read,
{
    let mut reader = BufReader::new(stream.take((request_limit_bytes + 1) as u64));
    let mut bytes = Vec::new();
    reader.read_until(b'\n', &mut bytes)?;

    if bytes.is_empty() {
        return Err(GlovesError::InvalidInput("empty daemon request".to_owned()));
    }
    if bytes.len() > request_limit_bytes {
        return Err(GlovesError::InvalidInput(format!(
            "daemon request too large (max {} bytes)",
            request_limit_bytes
        )));
    }

    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(GlovesError::InvalidInput("empty daemon request".to_owned()));
    }

    serde_json::from_slice::<DaemonRequest>(&bytes)
        .map_err(|error| GlovesError::InvalidInput(format!("invalid daemon request: {error}")))
}

fn write_daemon_response<W>(stream: &mut W, response: &DaemonResponse) -> Result<()>
where
    W: Write,
{
    let payload = serde_json::to_vec(response)?;
    stream.write_all(&payload)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn execute_daemon_request(paths: &SecretsPaths, request: DaemonRequest) -> DaemonResponse {
    match execute_daemon_request_inner(paths, request) {
        Ok((message, data)) => DaemonResponse::Ok { message, data },
        Err(error) => DaemonResponse::Error {
            error: error.to_string(),
        },
    }
}

fn execute_daemon_request_inner(
    paths: &SecretsPaths,
    request: DaemonRequest,
) -> Result<(String, Option<serde_json::Value>)> {
    match request {
        DaemonRequest::Ping => Ok(("pong".to_owned(), None)),
        DaemonRequest::List => {
            let manager = runtime::manager_for_paths(paths)?;
            let entries = manager.list_all()?;
            Ok(("ok".to_owned(), Some(serde_json::to_value(entries)?)))
        }
        DaemonRequest::Verify => {
            let manager = runtime::manager_for_paths(paths)?;
            TtlReaper::reap(
                &manager.agent_backend,
                &manager.metadata_store,
                &manager.audit_log,
            )?;
            TtlReaper::reap_vault_sessions(&GocryptfsDriver::new(), paths, &manager.audit_log)?;
            Ok(("ok".to_owned(), None))
        }
        DaemonRequest::Status { name } => {
            let manager = runtime::manager_for_paths(paths)?;
            let pending = manager.pending_store.load_all()?;
            let status = pending
                .into_iter()
                .find(|request| request.secret_name.as_str() == name)
                .map(|request| request.status)
                .unwrap_or(crate::types::RequestStatus::Fulfilled);
            Ok(("ok".to_owned(), Some(serde_json::to_value(status)?)))
        }
        DaemonRequest::Get { name } => {
            let manager = runtime::manager_for_paths(paths)?;
            let secret_id = SecretId::new(&name)?;
            let caller = AgentId::new(DEFAULT_AGENT_ID)?;
            let identity_file = runtime::load_or_create_default_identity(paths)?;
            let secret_value = manager.get(&secret_id, &caller, Some(identity_file.as_path()))?;
            let value = secret_value.expose(|bytes| String::from_utf8_lossy(bytes).to_string());
            Ok((
                "ok".to_owned(),
                Some(serde_json::json!({ "secret": value })),
            ))
        }
        DaemonRequest::Set {
            name,
            generate,
            value,
            ttl_days,
        } => {
            let manager = runtime::manager_for_paths(paths)?;
            let secret_id = SecretId::new(&name)?;
            let creator = AgentId::new(DEFAULT_AGENT_ID)?;
            let recipient = runtime::load_or_create_default_recipient(paths)?;
            let mut recipients = HashSet::new();
            recipients.insert(creator.clone());
            let ttl_days =
                runtime::validate_ttl_days(ttl_days.unwrap_or(DEFAULT_TTL_DAYS), "ttl_days")?;
            let secret_value =
                SecretValue::new(secret_input::resolve_daemon_secret_input(generate, value)?);
            manager.set(
                secret_id.clone(),
                secret_value,
                crate::manager::SetSecretOptions {
                    owner: Owner::Agent,
                    ttl: Duration::days(ttl_days),
                    created_by: creator,
                    recipients,
                    recipient_keys: vec![recipient],
                },
            )?;
            Ok((
                "ok".to_owned(),
                Some(serde_json::json!({ "id": secret_id.as_str() })),
            ))
        }
        DaemonRequest::Revoke { name } => {
            let manager = runtime::manager_for_paths(paths)?;
            let secret_id = SecretId::new(&name)?;
            let caller = AgentId::new(DEFAULT_AGENT_ID)?;
            manager.revoke(&secret_id, &caller)?;
            Ok(("revoked".to_owned(), None))
        }
        DaemonRequest::Request { name, reason } => {
            let manager = runtime::manager_for_paths(paths)?;
            let secret_id = SecretId::new(&name)?;
            let requester = AgentId::new(DEFAULT_AGENT_ID)?;
            let signing_key = runtime::load_or_create_default_signing_key(paths)?;
            let request = manager.request(
                secret_id,
                requester,
                reason,
                Duration::days(DEFAULT_TTL_DAYS),
                &signing_key,
            )?;
            Ok((
                "pending".to_owned(),
                Some(serde_json::json!({ "request_id": request.id })),
            ))
        }
        DaemonRequest::Approve { request_id } => {
            let manager = runtime::manager_for_paths(paths)?;
            let request_id = runtime::parse_request_uuid(&request_id)?;
            let reviewer = AgentId::new(DEFAULT_AGENT_ID)?;
            let request = manager.approve_request(request_id, reviewer)?;
            Ok((
                "approved".to_owned(),
                Some(serde_json::json!({
                    "request_id": request.id,
                    "secret_name": request.secret_name,
                    "requested_by": request.requested_by,
                    "reason": request.reason,
                    "requested_at": request.requested_at,
                    "expires_at": request.expires_at,
                    "status": request.status,
                    "pending": request.pending,
                    "approved_at": request.approved_at,
                    "approved_by": request.approved_by,
                    "denied_at": request.denied_at,
                    "denied_by": request.denied_by,
                })),
            ))
        }
        DaemonRequest::Deny { request_id } => {
            let manager = runtime::manager_for_paths(paths)?;
            let request_id = runtime::parse_request_uuid(&request_id)?;
            let reviewer = AgentId::new(DEFAULT_AGENT_ID)?;
            let request = manager.deny_request(request_id, reviewer)?;
            Ok((
                "denied".to_owned(),
                Some(serde_json::json!({
                    "request_id": request.id,
                    "secret_name": request.secret_name,
                    "requested_by": request.requested_by,
                    "reason": request.reason,
                    "requested_at": request.requested_at,
                    "expires_at": request.expires_at,
                    "status": request.status,
                    "pending": request.pending,
                    "approved_at": request.approved_at,
                    "approved_by": request.approved_by,
                    "denied_at": request.denied_at,
                    "denied_by": request.denied_by,
                })),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn setup_paths() -> (tempfile::TempDir, SecretsPaths) {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let paths = SecretsPaths::new(temp_dir.path());
        runtime::init_layout(&paths).expect("layout");
        (temp_dir, paths)
    }

    fn expect_data(data: Option<Value>) -> Value {
        data.expect("expected response data")
    }

    #[test]
    fn parse_daemon_bind_rejects_invalid_address() {
        let error = parse_daemon_bind("not-a-socket-address").expect_err("must fail");
        assert!(error.to_string().contains("invalid daemon bind address"));
    }

    #[cfg(unix)]
    #[test]
    fn assert_private_directory_rejects_group_world_access() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut permissions = std::fs::metadata(temp_dir.path())
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(temp_dir.path(), permissions).expect("permissions");

        let error = assert_private_directory(temp_dir.path(), "secrets root").expect_err("error");
        assert!(error
            .to_string()
            .contains("secrets root must not be group/world accessible"));
    }

    #[test]
    fn read_daemon_request_validates_empty_and_size_limits() {
        let mut empty_input: &[u8] = b"";
        let error = read_daemon_request(&mut empty_input, 64).expect_err("must fail");
        assert!(error.to_string().contains("empty daemon request"));

        let mut blank_line: &[u8] = b"\n";
        let error = read_daemon_request(&mut blank_line, 64).expect_err("must fail");
        assert!(error.to_string().contains("empty daemon request"));

        let mut oversized: &[u8] = br#"{"action":"ping"}"#;
        let error = read_daemon_request(&mut oversized, 4).expect_err("must fail");
        assert!(error.to_string().contains("daemon request too large"));
    }

    #[test]
    fn read_daemon_request_rejects_invalid_json_and_accepts_ping() {
        let mut invalid: &[u8] = br#"{"action":"ping""#;
        let error = read_daemon_request(&mut invalid, 64).expect_err("must fail");
        assert!(error.to_string().contains("invalid daemon request"));

        let mut valid: &[u8] = br#"{"action":"ping"}"#;
        let request = read_daemon_request(&mut valid, 64).expect("request");
        assert!(matches!(request, DaemonRequest::Ping));
    }

    #[test]
    fn write_daemon_response_outputs_json_line() {
        let mut buffer = Vec::new();
        write_daemon_response(
            &mut buffer,
            &DaemonResponse::Ok {
                message: "ok".to_owned(),
                data: Some(serde_json::json!({ "value": 1 })),
            },
        )
        .expect("response");

        let text = String::from_utf8(buffer).expect("utf8");
        assert!(text.ends_with('\n'));
        let payload = text.trim_end_matches('\n');
        let value: Value = serde_json::from_str(payload).expect("json");
        assert_eq!(value["status"], "ok");
        assert_eq!(value["message"], "ok");
        assert_eq!(value["data"]["value"], 1);
    }

    #[test]
    fn execute_daemon_request_inner_supports_set_get_list_status_and_revoke() {
        let (_temp_dir, paths) = setup_paths();

        let (message, data) = execute_daemon_request_inner(
            &paths,
            DaemonRequest::Set {
                name: "alpha".to_owned(),
                generate: false,
                value: Some("secret-value".to_owned()),
                ttl_days: None,
            },
        )
        .expect("set");
        assert_eq!(message, "ok");
        assert_eq!(expect_data(data)["id"], "alpha");

        let (message, data) =
            execute_daemon_request_inner(&paths, DaemonRequest::List).expect("list");
        assert_eq!(message, "ok");
        assert!(expect_data(data).to_string().contains("alpha"));

        let (message, data) = execute_daemon_request_inner(
            &paths,
            DaemonRequest::Status {
                name: "alpha".to_owned(),
            },
        )
        .expect("status");
        assert_eq!(message, "ok");
        assert_eq!(expect_data(data), serde_json::json!("fulfilled"));

        let (message, data) = execute_daemon_request_inner(
            &paths,
            DaemonRequest::Get {
                name: "alpha".to_owned(),
            },
        )
        .expect("get");
        assert_eq!(message, "ok");
        assert_eq!(expect_data(data)["secret"], "secret-value");

        let (message, data) = execute_daemon_request_inner(
            &paths,
            DaemonRequest::Revoke {
                name: "alpha".to_owned(),
            },
        )
        .expect("revoke");
        assert_eq!(message, "revoked");
        assert!(data.is_none());
    }

    #[test]
    fn execute_daemon_request_inner_supports_request_approve_deny_and_verify() {
        let (_temp_dir, paths) = setup_paths();

        let (message, data) = execute_daemon_request_inner(
            &paths,
            DaemonRequest::Request {
                name: "alpha".to_owned(),
                reason: "need access".to_owned(),
            },
        )
        .expect("request");
        assert_eq!(message, "pending");
        let request_id = expect_data(data)["request_id"]
            .as_str()
            .expect("request id")
            .to_owned();

        let (message, data) = execute_daemon_request_inner(
            &paths,
            DaemonRequest::Status {
                name: "alpha".to_owned(),
            },
        )
        .expect("status");
        assert_eq!(message, "ok");
        assert_eq!(expect_data(data), serde_json::json!("pending"));

        let (message, data) =
            execute_daemon_request_inner(&paths, DaemonRequest::Approve { request_id })
                .expect("approve");
        assert_eq!(message, "approved");
        let approved_payload = expect_data(data);
        assert_eq!(approved_payload["status"], "fulfilled");
        assert_eq!(approved_payload["pending"], false);
        assert_eq!(approved_payload["approved_by"], "default-agent");
        assert!(approved_payload["approved_at"].is_string());
        assert!(approved_payload["denied_by"].is_null());

        let (message, data) = execute_daemon_request_inner(
            &paths,
            DaemonRequest::Request {
                name: "bravo".to_owned(),
                reason: "need access".to_owned(),
            },
        )
        .expect("request");
        assert_eq!(message, "pending");
        let deny_request_id = expect_data(data)["request_id"]
            .as_str()
            .expect("request id")
            .to_owned();

        let (message, data) = execute_daemon_request_inner(
            &paths,
            DaemonRequest::Deny {
                request_id: deny_request_id,
            },
        )
        .expect("deny");
        assert_eq!(message, "denied");
        let denied_payload = expect_data(data);
        assert_eq!(denied_payload["status"], "denied");
        assert_eq!(denied_payload["pending"], false);
        assert_eq!(denied_payload["denied_by"], "default-agent");
        assert!(denied_payload["denied_at"].is_string());
        assert!(denied_payload["approved_by"].is_null());

        let (message, data) =
            execute_daemon_request_inner(&paths, DaemonRequest::Verify).expect("verify");
        assert_eq!(message, "ok");
        assert!(data.is_none());
    }

    #[test]
    fn execute_daemon_request_wraps_errors() {
        let (_temp_dir, paths) = setup_paths();
        let response = execute_daemon_request(
            &paths,
            DaemonRequest::Approve {
                request_id: "not-a-uuid".to_owned(),
            },
        );

        match response {
            DaemonResponse::Error { error } => {
                assert!(error.contains("invalid character"));
            }
            DaemonResponse::Ok { .. } => panic!("expected error response"),
        }
    }
}
