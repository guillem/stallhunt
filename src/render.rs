use crate::cli::{CapabilitiesOptions, HelpTopic, HuntOptions, OutputFormat};

const ROOT_HELP: &str = "Linux performance triage that reports evidence-backed bottlenecks.\n\nUSAGE:\n    bottleneck <COMMAND>\n\nCOMMANDS:\n    hunt          Run a bounded diagnosis\n    capabilities  Report available telemetry\n    version       Print version information\n    help          Print this help or help for a command\n\nOPTIONS:\n    -h, --help     Print help\n    -V, --version  Print version information\n";

const HUNT_HELP: &str = "Run a bounded bottleneck diagnosis.\n\nUSAGE:\n    bottleneck hunt [OPTIONS]\n\nOPTIONS:\n    --duration <DURATION>  Observation duration from 100ms to 5m [default: 10s]\n    --json                 Emit machine-readable JSON\n    -h, --help             Print help\n\nDURATION EXAMPLES:\n    500ms  2s  1.5s  1m\n";

const CAPABILITIES_HELP: &str = "Report telemetry availability and permission limitations.\n\nUSAGE:\n    bottleneck capabilities [OPTIONS]\n\nOPTIONS:\n    --json      Emit machine-readable JSON\n    -h, --help  Print help\n";

pub fn help(topic: HelpTopic) -> &'static str {
    match topic {
        HelpTopic::Root => ROOT_HELP,
        HelpTopic::Hunt => HUNT_HELP,
        HelpTopic::Capabilities => CAPABILITIES_HELP,
    }
}

pub fn version() -> String {
    format!("bottleneck {}\n", env!("CARGO_PKG_VERSION"))
}

pub fn hunt(options: &HuntOptions) -> String {
    match options.output {
        OutputFormat::Text => format!(
            "Hunt unavailable\n\nNo telemetry collectors are implemented yet.\nRequested observation duration: {}\nNo observation was performed and no findings were produced.\n",
            human_duration(options.duration_ms)
        ),
        OutputFormat::Json => format!(
            concat!(
                "{{\n",
                "  \"schema_version\": 1,\n",
                "  \"tool_version\": \"{}\",\n",
                "  \"status\": \"unavailable\",\n",
                "  \"requested_observation\": {{ \"duration_ms\": {} }},\n",
                "  \"observation\": null,\n",
                "  \"capabilities\": {{ \"status\": \"not_checked\", \"items\": [] }},\n",
                "  \"findings\": [],\n",
                "  \"qualifiers\": [\n",
                "    {{ \"kind\": \"implementation_limit\", \"message\": \"No telemetry collectors are implemented; no observation or diagnosis was performed.\" }}\n",
                "  ]\n",
                "}}\n"
            ),
            env!("CARGO_PKG_VERSION"),
            options.duration_ms
        ),
    }
}

pub fn capabilities(options: &CapabilitiesOptions) -> String {
    match options.output {
        OutputFormat::Text => "Telemetry capabilities\n\nCapability discovery is not implemented yet.\nNo system capabilities were checked.\n".to_owned(),
        OutputFormat::Json => format!(
            concat!(
                "{{\n",
                "  \"schema_version\": 1,\n",
                "  \"tool_version\": \"{}\",\n",
                "  \"status\": \"not_checked\",\n",
                "  \"capabilities\": [],\n",
                "  \"limitations\": [\n",
                "    {{ \"kind\": \"implementation_limit\", \"message\": \"Capability discovery is not implemented.\" }}\n",
                "  ]\n",
                "}}\n"
            ),
            env!("CARGO_PKG_VERSION")
        ),
    }
}

fn human_duration(duration_ms: u64) -> String {
    if duration_ms.is_multiple_of(60_000) {
        format!("{}m", duration_ms / 60_000)
    } else if duration_ms.is_multiple_of(1_000) {
        format!("{}s", duration_ms / 1_000)
    } else if duration_ms > 1_000 {
        let seconds = duration_ms / 1_000;
        let fractional_ms = duration_ms % 1_000;
        let fraction = format!("{fractional_ms:03}");
        format!("{seconds}.{}s", fraction.trim_end_matches('0'))
    } else {
        format!("{duration_ms}ms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunt_text_explicitly_denies_observation_and_findings() {
        let output = hunt(&HuntOptions {
            duration_ms: 1_000,
            output: OutputFormat::Text,
        });

        assert!(output.contains("Hunt unavailable"));
        assert!(output.contains("Requested observation duration: 1s"));
        assert!(output.contains("No observation was performed"));
        assert!(output.contains("no findings were produced"));
    }

    #[test]
    fn hunt_json_has_typed_unavailable_state_and_no_findings() {
        let output = hunt(&HuntOptions {
            duration_ms: 1_500,
            output: OutputFormat::Json,
        });

        assert!(output.contains("\"schema_version\": 1"));
        assert!(output.contains("\"status\": \"unavailable\""));
        assert!(output.contains("\"duration_ms\": 1500"));
        assert!(output.contains("\"observation\": null"));
        assert!(output.contains("\"findings\": []"));
    }

    #[test]
    fn fractional_duration_does_not_gain_a_second_suffix() {
        assert_eq!(human_duration(1_500), "1.5s");
        assert_eq!(human_duration(1_050), "1.05s");
        assert_eq!(human_duration(1_005), "1.005s");
    }
}
