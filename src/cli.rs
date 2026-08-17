use std::fmt;
use std::path::PathBuf;

pub const DEFAULT_HUNT_DURATION_MS: u64 = 10_000;
pub const MIN_HUNT_DURATION_MS: u64 = 100;
pub const MAX_HUNT_DURATION_MS: u64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HuntOptions {
    pub duration_ms: u64,
    pub output: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitiesOptions {
    pub output: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpTopic {
    Root,
    Hunt,
    Capabilities,
    Record,
    Replay,
    Redact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordOptions {
    pub duration_ms: u64,
    pub output: PathBuf,
    pub redaction: crate::record::Redaction,
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayOptions {
    pub input: PathBuf,
    pub output: OutputFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactOptions {
    pub input: PathBuf,
    pub output: PathBuf,
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Hunt(HuntOptions),
    Capabilities(CapabilitiesOptions),
    Record(RecordOptions),
    Replay(ReplayOptions),
    Redact(RedactOptions),
    Help(HelpTopic),
    Version,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    message: String,
}

impl CliError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for CliError {}

pub fn parse<I, S>(arguments: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let Some(command) = arguments.next() else {
        return Ok(Command::Help(HelpTopic::Root));
    };

    match command.as_str() {
        "-h" | "--help" | "help" => parse_help(arguments),
        "-V" | "--version" => reject_trailing_arguments(arguments, Command::Version),
        "version" => reject_trailing_arguments(arguments, Command::Version),
        "hunt" => parse_hunt(arguments),
        "capabilities" => parse_capabilities(arguments),
        "record" => parse_record(arguments),
        "replay" => parse_replay(arguments),
        "redact" => parse_redact(arguments),
        _ if command.starts_with('-') => Err(CliError::new(format!("unknown option '{command}'"))),
        _ => Err(CliError::new(format!("unknown command '{command}'"))),
    }
}

fn parse_help<I>(mut arguments: I) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    let topic = match arguments.next().as_deref() {
        None => HelpTopic::Root,
        Some("hunt") => HelpTopic::Hunt,
        Some("capabilities") => HelpTopic::Capabilities,
        Some("record") => HelpTopic::Record,
        Some("replay") => HelpTopic::Replay,
        Some("redact") => HelpTopic::Redact,
        Some(other) => return Err(CliError::new(format!("unknown help topic '{other}'"))),
    };

    reject_trailing_arguments(arguments, Command::Help(topic))
}

fn parse_hunt<I>(arguments: I) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    let mut duration_ms = DEFAULT_HUNT_DURATION_MS;
    let mut duration_seen = false;
    let mut output = OutputFormat::Text;

    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                return reject_trailing_arguments(arguments, Command::Help(HelpTopic::Hunt));
            }
            "--json" => set_json_output(&mut output)?,
            "--duration" => {
                if duration_seen {
                    return Err(CliError::new("option '--duration' may only be used once"));
                }
                let value = arguments
                    .next()
                    .ok_or_else(|| CliError::new("option '--duration' requires a value"))?;
                duration_ms = parse_duration(&value)?;
                duration_seen = true;
            }
            _ if argument.starts_with("--duration=") => {
                if duration_seen {
                    return Err(CliError::new("option '--duration' may only be used once"));
                }
                let (_, value) = argument
                    .split_once('=')
                    .expect("prefix check guarantees an equals sign");
                duration_ms = parse_duration(value)?;
                duration_seen = true;
            }
            _ if argument.starts_with('-') => {
                return Err(CliError::new(format!(
                    "unknown option '{argument}' for 'hunt'"
                )));
            }
            _ => {
                return Err(CliError::new(format!(
                    "unexpected argument '{argument}' for 'hunt'"
                )));
            }
        }
    }

    Ok(Command::Hunt(HuntOptions {
        duration_ms,
        output,
    }))
}

fn parse_capabilities<I>(arguments: I) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    let mut output = OutputFormat::Text;

    for argument in arguments {
        match argument.as_str() {
            "-h" | "--help" => {
                return Ok(Command::Help(HelpTopic::Capabilities));
            }
            "--json" => set_json_output(&mut output)?,
            _ if argument.starts_with('-') => {
                return Err(CliError::new(format!(
                    "unknown option '{argument}' for 'capabilities'"
                )));
            }
            _ => {
                return Err(CliError::new(format!(
                    "unexpected argument '{argument}' for 'capabilities'"
                )));
            }
        }
    }

    Ok(Command::Capabilities(CapabilitiesOptions { output }))
}

fn parse_record<I>(arguments: I) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    let mut duration_ms = DEFAULT_HUNT_DURATION_MS;
    let mut duration_seen = false;
    let mut output = None;
    let mut redaction = crate::record::Redaction::None;
    let mut force = false;

    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                return reject_trailing_arguments(arguments, Command::Help(HelpTopic::Record));
            }
            "--redact" => {
                if redaction != crate::record::Redaction::None {
                    return Err(CliError::new("option '--redact' may only be used once"));
                }
                redaction = crate::record::Redaction::Identifiers;
            }
            "--force" => set_flag(&mut force, "--force")?,
            "--duration" => {
                if duration_seen {
                    return Err(CliError::new("option '--duration' may only be used once"));
                }
                let value = arguments
                    .next()
                    .ok_or_else(|| CliError::new("option '--duration' requires a value"))?;
                duration_ms = parse_duration(&value)?;
                duration_seen = true;
            }
            "--output" => {
                if output.is_some() {
                    return Err(CliError::new("option '--output' may only be used once"));
                }
                let value = arguments
                    .next()
                    .ok_or_else(|| CliError::new("option '--output' requires a value"))?;
                output = Some(PathBuf::from(value));
            }
            _ if argument.starts_with("--duration=") => {
                if duration_seen {
                    return Err(CliError::new("option '--duration' may only be used once"));
                }
                let (_, value) = argument
                    .split_once('=')
                    .expect("prefix check guarantees an equals sign");
                duration_ms = parse_duration(value)?;
                duration_seen = true;
            }
            _ if argument.starts_with("--output=") => {
                if output.is_some() {
                    return Err(CliError::new("option '--output' may only be used once"));
                }
                let (_, value) = argument
                    .split_once('=')
                    .expect("prefix check guarantees an equals sign");
                if value.is_empty() {
                    return Err(CliError::new("option '--output' requires a value"));
                }
                output = Some(PathBuf::from(value));
            }
            _ if argument.starts_with('-') => {
                return Err(CliError::new(format!(
                    "unknown option '{argument}' for 'record'"
                )));
            }
            _ => {
                return Err(CliError::new(format!(
                    "unexpected argument '{argument}' for 'record'"
                )));
            }
        }
    }

    let output = output.ok_or_else(|| CliError::new("option '--output' is required"))?;
    Ok(Command::Record(RecordOptions {
        duration_ms,
        output,
        redaction,
        force,
    }))
}

fn parse_replay<I>(arguments: I) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    let mut output = OutputFormat::Text;
    let mut input = None;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                return reject_trailing_arguments(arguments, Command::Help(HelpTopic::Replay));
            }
            "--json" => set_json_output(&mut output)?,
            _ if argument.starts_with('-') => {
                return Err(CliError::new(format!(
                    "unknown option '{argument}' for 'replay'"
                )));
            }
            _ if input.is_some() => {
                return Err(CliError::new(format!(
                    "unexpected argument '{argument}' for 'replay'"
                )));
            }
            _ => input = Some(PathBuf::from(argument)),
        }
    }
    let input = input.ok_or_else(|| CliError::new("replay requires a recording path"))?;
    Ok(Command::Replay(ReplayOptions { input, output }))
}

fn parse_redact<I>(arguments: I) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    let mut input = None;
    let mut output = None;
    let mut force = false;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                return reject_trailing_arguments(arguments, Command::Help(HelpTopic::Redact));
            }
            "--force" => set_flag(&mut force, "--force")?,
            "--output" => {
                if output.is_some() {
                    return Err(CliError::new("option '--output' may only be used once"));
                }
                let value = arguments
                    .next()
                    .ok_or_else(|| CliError::new("option '--output' requires a value"))?;
                output = Some(PathBuf::from(value));
            }
            _ if argument.starts_with("--output=") => {
                if output.is_some() {
                    return Err(CliError::new("option '--output' may only be used once"));
                }
                let (_, value) = argument
                    .split_once('=')
                    .expect("prefix check guarantees an equals sign");
                if value.is_empty() {
                    return Err(CliError::new("option '--output' requires a value"));
                }
                output = Some(PathBuf::from(value));
            }
            _ if argument.starts_with('-') => {
                return Err(CliError::new(format!(
                    "unknown option '{argument}' for 'redact'"
                )));
            }
            _ if input.is_some() => {
                return Err(CliError::new(format!(
                    "unexpected argument '{argument}' for 'redact'"
                )));
            }
            _ => input = Some(PathBuf::from(argument)),
        }
    }
    let input = input.ok_or_else(|| CliError::new("redact requires a recording path"))?;
    let output = output.ok_or_else(|| CliError::new("option '--output' is required"))?;
    Ok(Command::Redact(RedactOptions {
        input,
        output,
        force,
    }))
}

fn set_flag(flag: &mut bool, name: &str) -> Result<(), CliError> {
    if *flag {
        return Err(CliError::new(format!(
            "option '{name}' may only be used once"
        )));
    }
    *flag = true;
    Ok(())
}

fn reject_trailing_arguments<I>(mut arguments: I, command: Command) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    if let Some(argument) = arguments.next() {
        Err(CliError::new(format!("unexpected argument '{argument}'")))
    } else {
        Ok(command)
    }
}

fn set_json_output(output: &mut OutputFormat) -> Result<(), CliError> {
    if *output == OutputFormat::Json {
        return Err(CliError::new("option '--json' may only be used once"));
    }
    *output = OutputFormat::Json;
    Ok(())
}

fn parse_duration(value: &str) -> Result<u64, CliError> {
    let (number, unit_ms) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000_u64)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000_u64)
    } else {
        return Err(invalid_duration(value));
    };

    let duration_ms =
        parse_decimal_milliseconds(number, unit_ms).ok_or_else(|| invalid_duration(value))?;

    if !(MIN_HUNT_DURATION_MS..=MAX_HUNT_DURATION_MS).contains(&duration_ms) {
        return Err(CliError::new(format!(
            "duration '{value}' is outside the supported range (100ms to 5m)"
        )));
    }

    Ok(duration_ms)
}

fn parse_decimal_milliseconds(number: &str, unit_ms: u64) -> Option<u64> {
    let (whole, fraction) = match number.split_once('.') {
        Some((whole, fraction)) if !whole.is_empty() && !fraction.is_empty() => {
            if fraction.contains('.') {
                return None;
            }
            (whole, Some(fraction))
        }
        Some(_) => return None,
        None if !number.is_empty() => (number, None),
        None => return None,
    };

    if !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    let whole_ms = whole.parse::<u64>().ok()?.checked_mul(unit_ms)?;
    let Some(fraction) = fraction else {
        return Some(whole_ms);
    };

    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) || fraction.len() > 18 {
        return None;
    }

    let scale = 10_u64.checked_pow(u32::try_from(fraction.len()).ok()?)?;
    let numerator = fraction.parse::<u64>().ok()?.checked_mul(unit_ms)?;
    if numerator % scale != 0 {
        return None;
    }

    whole_ms.checked_add(numerator / scale)
}

fn invalid_duration(value: &str) -> CliError {
    CliError::new(format!(
        "invalid duration '{value}'; use a value such as 500ms, 2s, 1.5s, or 1m"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn no_arguments_shows_root_help() {
        assert_eq!(
            parse(Vec::<String>::new()),
            Ok(Command::Help(HelpTopic::Root))
        );
    }

    #[test]
    fn hunt_uses_documented_defaults() {
        assert_eq!(
            parse(["hunt"]),
            Ok(Command::Hunt(HuntOptions {
                duration_ms: DEFAULT_HUNT_DURATION_MS,
                output: OutputFormat::Text,
            }))
        );
    }

    #[test]
    fn hunt_accepts_supported_duration_units_and_json() {
        for (value, expected_ms) in [
            ("500ms", 500),
            ("2s", 2_000),
            ("1.5s", 1_500),
            ("1m", 60_000),
        ] {
            assert_eq!(
                parse(["hunt", "--json", "--duration", value]),
                Ok(Command::Hunt(HuntOptions {
                    duration_ms: expected_ms,
                    output: OutputFormat::Json,
                }))
            );
        }
    }

    #[test]
    fn hunt_accepts_duration_equals_syntax() {
        assert_eq!(
            parse(["hunt", "--duration=750ms"]),
            Ok(Command::Hunt(HuntOptions {
                duration_ms: 750,
                output: OutputFormat::Text,
            }))
        );
    }

    #[test]
    fn hunt_accepts_inclusive_duration_boundaries() {
        assert!(parse(["hunt", "--duration", "100ms"]).is_ok());
        assert!(parse(["hunt", "--duration", "5m"]).is_ok());
    }

    #[test]
    fn hunt_rejects_out_of_range_durations() {
        for value in ["99ms", "5.1m", "6m"] {
            let error = parse(["hunt", "--duration", value]).unwrap_err();
            assert!(error.to_string().contains("outside the supported range"));
        }
    }

    #[test]
    fn hunt_rejects_malformed_or_sub_millisecond_durations() {
        for value in ["", "10", "ms", "1.", ".5s", "1.2.3s", "0.0001s", "-1s"] {
            let error = parse(["hunt", "--duration", value]).unwrap_err();
            assert!(error.to_string().contains("invalid duration"), "{value}");
        }
    }

    #[test]
    fn options_cannot_be_repeated() {
        assert!(parse(["hunt", "--json", "--json"]).is_err());
        assert!(parse(["hunt", "--duration", "1s", "--duration=2s"]).is_err());
    }

    #[test]
    fn capabilities_supports_json() {
        assert_eq!(
            parse(["capabilities", "--json"]),
            Ok(Command::Capabilities(CapabilitiesOptions {
                output: OutputFormat::Json,
            }))
        );
    }

    #[test]
    fn unknown_commands_and_options_are_errors() {
        assert!(parse(["watch"]).is_err());
        assert!(parse(["hunt", "--verbose"]).is_err());
        assert!(parse(["capabilities", "extra"]).is_err());
    }

    #[test]
    fn record_requires_output_and_accepts_redact() {
        assert!(parse(["record"]).is_err());
        assert_eq!(
            parse([
                "record",
                "--duration",
                "500ms",
                "--redact",
                "--output",
                "out.json"
            ]),
            Ok(Command::Record(RecordOptions {
                duration_ms: 500,
                output: PathBuf::from("out.json"),
                redaction: crate::record::Redaction::Identifiers,
                force: false,
            }))
        );
    }

    #[test]
    fn replay_and_redact_require_paths() {
        assert!(parse(["replay"]).is_err());
        assert_eq!(
            parse(["replay", "--json", "incident.json"]),
            Ok(Command::Replay(ReplayOptions {
                input: PathBuf::from("incident.json"),
                output: OutputFormat::Json,
            }))
        );
        assert_eq!(
            parse(["redact", "in.json", "--output=out.json", "--force"]),
            Ok(Command::Redact(RedactOptions {
                input: PathBuf::from("in.json"),
                output: PathBuf::from("out.json"),
                force: true,
            }))
        );
    }
}
