mod analysis;
mod cgroup;
mod cli;
mod cpu;
mod duration_us;
mod io;
mod memory;
mod observe;
mod presentation;
mod psi;
mod record;
mod render;
mod tui;
mod watch;

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use clap_complete::generate;
use cli::{Cli, Command};
use record::{read_recording, recording_from_observation, redact_recording, write_recording};

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            error.print().expect("stderr should be writable");
            return ExitCode::from(error.exit_code() as u8);
        }
    };

    match execute(cli.into_command()) {
        Ok(output) => write_stdout(&output),
        Err(error) if error.downcast_ref::<InterruptedWatch>().is_some() => ExitCode::from(130),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn write_stdout(output: &str) -> ExitCode {
    match std::io::stdout().write_all(output.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn execute(command: Command) -> Result<String, Box<dyn std::error::Error>> {
    match command {
        Command::Hunt(options) => {
            render::hunt(&options, observe::observe_hunt).map_err(|error| error.into())
        }
        Command::Capabilities(options) => render::capabilities(
            &options,
            psi::probe_cpu_psi(),
            cpu::probe_cpu_telemetry(),
            psi::probe_memory_psi(),
            memory::probe_memory_context(),
            psi::probe_io_psi(),
            io::probe_io_context(),
            cgroup::probe_cgroup_v2(),
        )
        .map_err(|error| error.into()),
        Command::Record(options) => {
            let observation = observe::observe_hunt(Duration::from_millis(options.duration_ms));
            let recording =
                recording_from_observation(&observation, options.duration_ms, options.redaction)?;
            write_recording(&options.output, &recording, options.force)?;
            Ok(render::record_written(&options.output, &recording))
        }
        Command::Replay(options) => {
            let recording = read_recording(&options.input)?;
            render::replay(&options, recording).map_err(|error| error.into())
        }
        Command::Redact(options) => {
            let mut recording = read_recording(&options.input)?;
            redact_recording(&mut recording);
            write_recording(&options.output, &recording, options.force)?;
            Ok(render::redact_written(&options, &recording))
        }
        Command::Watch(options) => match watch::run(&options)? {
            watch::WatchExit::Completed => Ok(String::new()),
            watch::WatchExit::Interrupted => Err(Box::new(InterruptedWatch)),
        },
        Command::Completions(shell) => {
            let mut command = cli::command();
            generate(shell, &mut command, "stallhunt", &mut std::io::stdout());
            Ok(String::new())
        }
        Command::Version => Ok(render::version()),
    }
}

#[derive(Debug)]
struct InterruptedWatch;

impl std::fmt::Display for InterruptedWatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("watch interrupted")
    }
}

impl std::error::Error for InterruptedWatch {}

#[cfg(test)]
mod main_tests {
    use super::*;
    use cli::parse_from;

    #[test]
    fn parse_from_empty_args_defaults_to_hunt() {
        assert!(matches!(
            parse_from(["stallhunt"]).expect("parse"),
            Command::Hunt(_)
        ));
    }
}
