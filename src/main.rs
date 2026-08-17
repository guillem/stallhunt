mod cli;
mod cpu;
mod psi;
mod render;

use std::env;
use std::process::ExitCode;

use cli::{Command, parse};

fn main() -> ExitCode {
    match parse(env::args().skip(1)) {
        Ok(command) => {
            let output = match command {
                Command::Hunt(options) => render::hunt(&options, cpu::observe_hunt),
                Command::Capabilities(options) => {
                    render::capabilities(&options, psi::probe_cpu_psi(), cpu::probe_cpu_telemetry())
                }
                Command::Help(topic) => render::help(topic).to_owned(),
                Command::Version => render::version(),
            };

            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}\n\nTry 'bottleneck --help' for usage.");
            ExitCode::from(2)
        }
    }
}
