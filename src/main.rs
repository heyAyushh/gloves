use std::io::Write;

use clap::Parser;

use gloves::cli::{run, Cli};

fn main() {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            let stderr = std::io::stderr();
            let mut handle = stderr.lock();
            let _ = handle.write_all(format!("error: {error}\n").as_bytes());
            let _ = handle.flush();
            std::process::exit(1);
        }
    }
}
