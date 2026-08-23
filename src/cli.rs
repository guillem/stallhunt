use std::fmt;
use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use crate::style;

pub const DEFAULT_HUNT_DURATION_MS: u64 = 10_000;
#[allow(dead_code)] // referenced by CLI defaults, docs, and unit tests
pub const DEFAULT_WATCH_INTERVAL_MS: u64 = 2_000;
pub const MIN_HUNT_DURATION_MS: u64 = 100;
pub const MAX_HUNT_DURATION_MS: u64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TextStyle {
    pub explain: bool,
    pub color: bool,
    pub unicode: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HuntOptions {
    pub duration_ms: u64,
    pub output: OutputFormat,
    pub style: TextStyle,
}

impl HuntOptions {
    #[cfg(test)]
    pub fn new(duration_ms: u64, output: OutputFormat) -> Self {
        Self {
            duration_ms,
            output,
            style: TextStyle::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitiesOptions {
    pub output: OutputFormat,
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
    pub style: TextStyle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactOptions {
    pub input: PathBuf,
    pub output: PathBuf,
    pub force: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchOptions {
    pub interval_ms: u64,
    pub count: Option<u32>,
    pub output: OutputFormat,
    pub plain: bool,
    pub style: TextStyle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Hunt(HuntOptions),
    Capabilities(CapabilitiesOptions),
    Record(RecordOptions),
    Replay(ReplayOptions),
    Redact(RedactOptions),
    Watch(WatchOptions),
    Completions(Shell),
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

#[derive(Parser)]
#[command(
    name = "stallhunt",
    version,
    about = "Linux performance triage that reports evidence-backed bottlenecks",
    after_help = "Run `stallhunt` with no subcommand for a default 10s hunt.\nUse `stallhunt completions <SHELL>` to generate shell completions."
)]
pub struct Cli {
    /// Emit machine-readable JSON
    #[arg(long, global = true)]
    json: bool,
    /// Expand qualifier text and finding-kind help
    #[arg(long, global = true)]
    explain: bool,
    /// Disable ANSI color even on a TTY
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a bounded diagnosis
    Hunt(HuntArgs),
    /// Track rolling finding lifecycle
    Watch(WatchArgs),
    /// Report available telemetry
    Capabilities(CapabilitiesArgs),
    /// Capture a normalized observation for later replay
    Record(RecordArgs),
    /// Re-analyze a recording without collecting live telemetry
    Replay(ReplayArgs),
    /// Replace identifiers in a recording for sharing
    Redact(RedactArgs),
    /// Print shell completions to stdout
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Print version information
    Version,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
struct HuntArgs {
    /// Observation duration from 100ms to 5m
    #[arg(long, value_name = "DURATION", default_value = "10s", value_parser = parse_duration_value)]
    duration: u64,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
struct CapabilitiesArgs {}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
struct RecordArgs {
    /// Recording file to create
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
    /// Observation duration from 100ms to 5m
    #[arg(long, value_name = "DURATION", default_value = "10s", value_parser = parse_duration_value)]
    duration: u64,
    /// Replace process names, device names, and cgroup paths
    #[arg(long)]
    redact: bool,
    /// Overwrite the output path if it already exists
    #[arg(long)]
    force: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
struct ReplayArgs {
    /// Recording to replay
    path: PathBuf,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
struct RedactArgs {
    /// Recording to redact
    path: PathBuf,
    /// Redacted recording to create
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
    /// Overwrite the output path if it already exists
    #[arg(long)]
    force: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
struct WatchArgs {
    /// Rolling window from 100ms to 5m
    #[arg(long, value_name = "DURATION", default_value = "2s", value_parser = parse_duration_value)]
    interval: u64,
    /// Stop after N windows; omit to run until interrupted
    #[arg(long, value_name = "N", value_parser = parse_count_value)]
    count: Option<u32>,
    /// Force compact text on a TTY instead of the findings TUI
    #[arg(long)]
    plain: bool,
}

impl From<RecordArgs> for RecordOptions {
    fn from(args: RecordArgs) -> Self {
        Self {
            duration_ms: args.duration,
            output: args.output,
            redaction: if args.redact {
                crate::record::Redaction::Identifiers
            } else {
                crate::record::Redaction::None
            },
            force: args.force,
        }
    }
}

impl From<RedactArgs> for RedactOptions {
    fn from(args: RedactArgs) -> Self {
        Self {
            input: args.path,
            output: args.output,
            force: args.force,
        }
    }
}

impl Cli {
    pub fn into_command(self) -> Command {
        let output = output_format(self.json);
        let style = TextStyle {
            explain: self.explain,
            color: style::color_enabled(self.no_color),
            unicode: style::unicode_enabled(),
        };
        match self.command {
            None => Command::Hunt(HuntOptions {
                duration_ms: DEFAULT_HUNT_DURATION_MS,
                output,
                style,
            }),
            Some(Commands::Hunt(args)) => Command::Hunt(HuntOptions {
                duration_ms: args.duration,
                output,
                style,
            }),
            Some(Commands::Watch(args)) => Command::Watch(WatchOptions {
                interval_ms: args.interval,
                count: args.count,
                output,
                plain: args.plain,
                style,
            }),
            Some(Commands::Capabilities(_)) => {
                Command::Capabilities(CapabilitiesOptions { output })
            }
            Some(Commands::Record(args)) => Command::Record(args.into()),
            Some(Commands::Replay(args)) => Command::Replay(ReplayOptions {
                input: args.path,
                output,
                style,
            }),
            Some(Commands::Redact(args)) => Command::Redact(args.into()),
            Some(Commands::Completions { shell }) => Command::Completions(shell),
            Some(Commands::Version) => Command::Version,
        }
    }
}

const fn output_format(json: bool) -> OutputFormat {
    if json {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    }
}

pub fn command() -> clap::Command {
    Cli::command()
}

#[allow(dead_code)] // used by integration tests and CLI unit tests
pub fn parse_from<I, T>(arguments: I) -> Result<Command, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::try_parse_from(arguments).map(Cli::into_command)
}

fn parse_duration_value(value: &str) -> Result<u64, String> {
    parse_duration(value).map_err(|error| error.to_string())
}

fn parse_count_value(value: &str) -> Result<u32, String> {
    parse_count(value).map_err(|error| error.to_string())
}

pub fn parse_duration(value: &str) -> Result<u64, CliError> {
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

fn parse_count(value: &str) -> Result<u32, CliError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid_count(value));
    }
    let count = value.parse::<u32>().map_err(|_| invalid_count(value))?;
    if count == 0 {
        return Err(CliError::new("option '--count' must be a positive integer"));
    }
    Ok(count)
}

fn invalid_count(value: &str) -> CliError {
    CliError::new(format!(
        "invalid count '{value}'; use a positive integer such as 1 or 30"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(arguments: impl IntoIterator<Item = &'static str>) -> Result<Command, clap::Error> {
        parse_from(arguments)
    }

    fn expect_parse(arguments: impl IntoIterator<Item = &'static str>) -> Command {
        parse(arguments).expect("parse should succeed")
    }

    #[test]
    fn no_arguments_defaults_to_hunt() {
        match expect_parse(["stallhunt"]) {
            Command::Hunt(options) => {
                assert_eq!(options.duration_ms, DEFAULT_HUNT_DURATION_MS);
                assert_eq!(options.output, OutputFormat::Text);
                assert!(!options.style.explain);
            }
            other => panic!("expected hunt, got {other:?}"),
        }
    }

    #[test]
    fn hunt_uses_documented_defaults() {
        match expect_parse(["stallhunt", "hunt"]) {
            Command::Hunt(options) => {
                assert_eq!(options.duration_ms, DEFAULT_HUNT_DURATION_MS);
                assert_eq!(options.output, OutputFormat::Text);
            }
            other => panic!("expected hunt, got {other:?}"),
        }
    }

    #[test]
    fn hunt_accepts_supported_duration_units_and_json() {
        for (value, expected_ms) in [
            ("500ms", 500),
            ("2s", 2_000),
            ("1.5s", 1_500),
            ("1m", 60_000),
        ] {
            match expect_parse(["stallhunt", "hunt", "--json", "--duration", value]) {
                Command::Hunt(options) => {
                    assert_eq!(options.duration_ms, expected_ms);
                    assert_eq!(options.output, OutputFormat::Json);
                }
                other => panic!("expected hunt, got {other:?}"),
            }
        }
    }

    #[test]
    fn hunt_accepts_duration_equals_syntax() {
        match expect_parse(["stallhunt", "hunt", "--duration=750ms"]) {
            Command::Hunt(options) => {
                assert_eq!(options.duration_ms, 750);
                assert_eq!(options.output, OutputFormat::Text);
            }
            other => panic!("expected hunt, got {other:?}"),
        }
    }

    #[test]
    fn hunt_accepts_inclusive_duration_boundaries() {
        assert!(parse(["stallhunt", "hunt", "--duration", "100ms"]).is_ok());
        assert!(parse(["stallhunt", "hunt", "--duration", "5m"]).is_ok());
    }

    #[test]
    fn hunt_rejects_out_of_range_durations() {
        for value in ["99ms", "5.1m", "6m"] {
            let error = parse(["stallhunt", "hunt", "--duration", value]).unwrap_err();
            assert!(error.to_string().contains("outside the supported range"));
        }
    }

    #[test]
    fn hunt_rejects_malformed_or_sub_millisecond_durations() {
        for value in ["", "10", "ms", "1.", ".5s", "1.2.3s", "0.0001s"] {
            let error = parse(["stallhunt", "hunt", "--duration", value]).unwrap_err();
            assert!(error.to_string().contains("invalid duration"), "{value}");
        }
        assert!(parse(["stallhunt", "hunt", "--duration=-1s"]).is_err());
    }

    #[test]
    fn options_cannot_be_repeated() {
        assert!(parse(["stallhunt", "hunt", "--json", "--json"]).is_err());
        assert!(parse(["stallhunt", "hunt", "--duration", "1s", "--duration=2s"]).is_err());
    }

    #[test]
    fn capabilities_supports_json() {
        assert_eq!(
            expect_parse(["stallhunt", "capabilities", "--json"]),
            Command::Capabilities(CapabilitiesOptions {
                output: OutputFormat::Json,
            })
        );
    }

    #[test]
    fn unknown_commands_and_options_are_errors() {
        assert!(parse(["stallhunt", "verbose"]).is_err());
        assert!(parse(["stallhunt", "hunt", "--verbose"]).is_err());
        assert!(parse(["stallhunt", "capabilities", "extra"]).is_err());
    }

    #[test]
    fn explain_and_no_color_are_global_flags() {
        match expect_parse(["stallhunt", "--explain", "--no-color"]) {
            Command::Hunt(options) => {
                assert!(options.style.explain);
                assert!(!options.style.color);
            }
            other => panic!("expected hunt, got {other:?}"),
        }
        match expect_parse(["stallhunt", "hunt", "--explain"]) {
            Command::Hunt(options) => assert!(options.style.explain),
            other => panic!("expected hunt, got {other:?}"),
        }
        match expect_parse(["stallhunt", "watch", "--plain"]) {
            Command::Watch(options) => {
                assert!(options.plain);
                assert_eq!(options.output, OutputFormat::Text);
            }
            other => panic!("expected watch, got {other:?}"),
        }
    }

    #[test]
    fn watch_uses_documented_defaults_and_bounds() {
        match expect_parse(["stallhunt", "watch"]) {
            Command::Watch(options) => {
                assert_eq!(options.interval_ms, DEFAULT_WATCH_INTERVAL_MS);
                assert_eq!(options.count, None);
                assert_eq!(options.output, OutputFormat::Text);
                assert!(!options.plain);
            }
            other => panic!("expected watch, got {other:?}"),
        }
        match expect_parse([
            "stallhunt",
            "watch",
            "--json",
            "--interval",
            "1s",
            "--count=3",
        ]) {
            Command::Watch(options) => {
                assert_eq!(options.interval_ms, 1_000);
                assert_eq!(options.count, Some(3));
                assert_eq!(options.output, OutputFormat::Json);
            }
            other => panic!("expected watch, got {other:?}"),
        }
        assert!(parse(["stallhunt", "watch", "--count", "0"]).is_err());
        assert!(parse(["stallhunt", "watch", "--interval", "1s", "--interval=2s"]).is_err());
    }

    #[test]
    fn record_requires_output_and_accepts_redact() {
        assert!(parse(["stallhunt", "record"]).is_err());
        assert_eq!(
            expect_parse([
                "stallhunt",
                "record",
                "--duration",
                "500ms",
                "--redact",
                "--output",
                "out.json"
            ]),
            Command::Record(RecordOptions {
                duration_ms: 500,
                output: PathBuf::from("out.json"),
                redaction: crate::record::Redaction::Identifiers,
                force: false,
            })
        );
    }

    #[test]
    fn replay_and_redact_require_paths() {
        assert!(parse(["stallhunt", "replay"]).is_err());
        match expect_parse(["stallhunt", "replay", "--json", "incident.json"]) {
            Command::Replay(options) => {
                assert_eq!(options.input, PathBuf::from("incident.json"));
                assert_eq!(options.output, OutputFormat::Json);
            }
            other => panic!("expected replay, got {other:?}"),
        }
        assert_eq!(
            expect_parse([
                "stallhunt",
                "redact",
                "in.json",
                "--output=out.json",
                "--force"
            ]),
            Command::Redact(RedactOptions {
                input: PathBuf::from("in.json"),
                output: PathBuf::from("out.json"),
                force: true,
            })
        );
    }

    #[test]
    fn completions_subcommand_is_available() {
        assert!(matches!(
            parse(["stallhunt", "completions", "bash"]),
            Ok(Command::Completions(Shell::Bash))
        ));
    }

    #[test]
    fn root_help_exposes_the_initial_command_set() {
        let mut command = command();
        let help = command.render_help().to_string();
        assert!(help.contains("hunt"));
        assert!(help.contains("watch"));
        assert!(help.contains("capabilities"));
        assert!(help.contains("record"));
        assert!(help.contains("replay"));
        assert!(help.contains("redact"));
        assert!(help.contains("completions"));
        assert!(help.contains("version"));
    }
}
