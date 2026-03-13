use std::process;

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match gloves::runtime_bridge::run_docker_bridge(&arguments) {
        Ok(exit_code) => process::exit(exit_code),
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}
