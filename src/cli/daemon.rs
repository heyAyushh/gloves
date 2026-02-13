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

use super::{runtime, secret_input, DEFAULT_AGENT_ID, DEFAULT_TTL_DAYS};

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
        println!("ok");
        return Ok(());
    }

    let listener = TcpListener::bind(bind_addr)?;
    let listening_addr = listener.local_addr()?;
    println!("listening: {}", listening_addr);

    let mut handled_requests = 0_usize;
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("error: daemon accept failed: {error}");
                continue;
            }
        };
        let io_timeout = Some(StdDuration::from_secs(options.io_timeout_seconds));
        if let Err(error) = stream.set_read_timeout(io_timeout) {
            eprintln!("error: daemon read-timeout setup failed: {error}");
            continue;
        }
        if let Err(error) = stream.set_write_timeout(io_timeout) {
            eprintln!("error: daemon write-timeout setup failed: {error}");
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
            let identity = runtime::load_or_create_default_identity(paths)?;
            let secret_value = manager.get(&secret_id, &caller, Some(identity))?;
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
            let identity = runtime::load_or_create_default_identity(paths)?;
            let recipient = identity.to_public().to_string();
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
            manager.approve_request(request_id)?;
            Ok(("approved".to_owned(), None))
        }
        DaemonRequest::Deny { request_id } => {
            let manager = runtime::manager_for_paths(paths)?;
            let request_id = runtime::parse_request_uuid(&request_id)?;
            manager.deny_request(request_id)?;
            Ok(("denied".to_owned(), None))
        }
    }
}
