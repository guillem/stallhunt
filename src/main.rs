mod analysis;
mod cgroup;
mod cli;
mod color;
mod cpu;
mod duration_us;
mod io;
mod memory;
mod observe;
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
            let colors = color::resolve(options.no_color);
            render::hunt(&options, observe::observe_hunt, colors).map_err(|error| error.into())
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
            let colors = color::resolve(options.no_color);
            render::replay(&options, recording, colors).map_err(|error| error.into())
        }
        Command::Redact(options) => {
            let mut recording = read_recording(&options.input)?;
            redact_recording(&mut recording);
            write_recording(&options.output, &recording, options.force)?;
            Ok(render::redact_written(&options, &recording))
        }
        Command::Watch(options) => {
            watch::run(&options)?;
            Ok(String::new())
        }
        Command::Completions(shell) => {
            let mut command = cli::command();
            generate(shell, &mut command, "stallhunt", &mut std::io::stdout());
            Ok(String::new())
        }
        Command::Version => Ok(render::version()),
    }
}

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
