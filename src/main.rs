mod analysis;
mod cgroup;
mod cli;
mod cpu;
mod duration_us;
mod io;
mod memory;
mod observe;
mod psi;
mod record;
mod render;

use std::env;
use std::process::ExitCode;
use std::time::Duration;

use cli::{Command, parse};
use record::{read_recording, recording_from_observation, redact_recording, write_recording};

fn main() -> ExitCode {
    match parse(env::args().skip(1)) {
        Ok(command) => match execute(command) {
            Ok(output) => {
                print!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(1)
            }
        },
        Err(error) => {
            eprintln!("error: {error}\n\nTry 'bottleneck --help' for usage.");
            ExitCode::from(2)
        }
    }
}

fn execute(command: Command) -> Result<String, Box<dyn std::error::Error>> {
    match command {
        Command::Hunt(options) => Ok(render::hunt(&options, observe::observe_hunt)),
        Command::Capabilities(options) => Ok(render::capabilities(
            &options,
            psi::probe_cpu_psi(),
            cpu::probe_cpu_telemetry(),
            psi::probe_memory_psi(),
            memory::probe_memory_context(),
            psi::probe_io_psi(),
            io::probe_io_context(),
            cgroup::probe_cgroup_v2(),
        )),
        Command::Record(options) => {
            let observation = observe::observe_hunt(Duration::from_millis(options.duration_ms));
            let recording =
                recording_from_observation(&observation, options.duration_ms, options.redaction)?;
            write_recording(&options.output, &recording, options.force)?;
            Ok(render::record_written(&options.output, &recording))
        }
        Command::Replay(options) => {
            let recording = read_recording(&options.input)?;
            Ok(render::replay(&options, recording)?)
        }
        Command::Redact(options) => {
            let mut recording = read_recording(&options.input)?;
            redact_recording(&mut recording);
            write_recording(&options.output, &recording, options.force)?;
            Ok(render::redact_written(&options, &recording))
        }
        Command::Help(topic) => Ok(render::help(topic).to_owned()),
        Command::Version => Ok(render::version()),
    }
}
