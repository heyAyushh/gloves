use std::io::{self, Write};

/// Result of writing to an output stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputStatus {
    /// Write completed.
    Written,
    /// Stream was closed by the reader.
    BrokenPipe,
}

fn map_result(result: io::Result<()>) -> io::Result<OutputStatus> {
    match result {
        Ok(()) => Ok(OutputStatus::Written),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(OutputStatus::BrokenPipe),
        Err(error) => Err(error),
    }
}

/// Writes bytes to stdout and flushes.
pub(crate) fn stdout_bytes(bytes: &[u8]) -> io::Result<OutputStatus> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    map_result(handle.write_all(bytes).and_then(|_| handle.flush()))
}

/// Writes text and a newline to stdout.
pub(crate) fn stdout_line(text: &str) -> io::Result<OutputStatus> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    map_result(
        handle
            .write_all(text.as_bytes())
            .and_then(|_| handle.write_all(b"\n"))
            .and_then(|_| handle.flush()),
    )
}

/// Writes text and a newline to stderr.
pub(crate) fn stderr_line(text: &str) -> io::Result<OutputStatus> {
    let stderr = io::stderr();
    let mut handle = stderr.lock();
    map_result(
        handle
            .write_all(text.as_bytes())
            .and_then(|_| handle.write_all(b"\n"))
            .and_then(|_| handle.flush()),
    )
}
