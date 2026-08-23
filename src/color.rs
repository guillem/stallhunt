//! Color policy for human-readable text output.
//!
//! Color is decorative only: status and severity words remain in the text, so
//! color is never the only carrier of meaning.

use std::io::IsTerminal;

use crate::analysis::Severity;

const BOLD: &str = "\u{1b}[1m";
const RED: &str = "\u{1b}[31m";
const YELLOW: &str = "\u{1b}[33m";
const GREEN: &str = "\u{1b}[32m";
const CYAN: &str = "\u{1b}[36m";
const RESET: &str = "\u{1b}[0m";

/// When text output may carry ANSI color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorPolicy {
    /// Color only when stdout is a terminal.
    Auto,
    /// Never color.
    Never,
    /// Test seam: always color, regardless of the terminal.
    #[doc(hidden)]
    #[allow(dead_code)] // constructed by renderer tests only
    ForcedOn,
}

impl ColorPolicy {
    fn enabled(self) -> bool {
        match self {
            Self::Auto => std::io::stdout().is_terminal(),
            Self::Never => false,
            Self::ForcedOn => true,
        }
    }

    /// Wraps `text` in an ANSI `code` when the policy allows color.
    pub fn paint(self, code: &str, text: &str) -> String {
        if self.enabled() {
            format!("{code}{text}{RESET}")
        } else {
            text.to_owned()
        }
    }

    pub fn bold(self, text: &str) -> String {
        self.paint(BOLD, text)
    }

    /// Colors text by severity: severe/high red, moderate yellow, low cyan,
    /// none green.
    pub fn severity(self, severity: Severity, text: &str) -> String {
        let code = match severity {
            Severity::Severe | Severity::High => RED,
            Severity::Moderate => YELLOW,
            Severity::Low => CYAN,
            Severity::None => GREEN,
        };
        self.paint(code, text)
    }
}

/// Resolves the policy once per invocation: `--no-color` or a `NO_COLOR`
/// environment variable with any value disables color; otherwise color is
/// automatic and limited to terminals.
pub fn resolve(no_color_flag: bool) -> ColorPolicy {
    resolve_with(no_color_flag, std::env::var_os("NO_COLOR").is_some())
}

fn resolve_with(no_color_flag: bool, no_color_env: bool) -> ColorPolicy {
    if no_color_flag || no_color_env {
        ColorPolicy::Never
    } else {
        ColorPolicy::Auto
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_flag_and_env_both_force_never() {
        assert_eq!(resolve_with(false, false), ColorPolicy::Auto);
        assert_eq!(resolve_with(true, false), ColorPolicy::Never);
        assert_eq!(resolve_with(false, true), ColorPolicy::Never);
        assert_eq!(resolve_with(true, true), ColorPolicy::Never);
    }

    #[test]
    fn forced_on_paints_and_never_stays_plain() {
        assert_eq!(
            ColorPolicy::ForcedOn.severity(Severity::High, "high"),
            "\u{1b}[31mhigh\u{1b}[0m"
        );
        assert_eq!(
            ColorPolicy::ForcedOn.severity(Severity::Moderate, "moderate"),
            "\u{1b}[33mmoderate\u{1b}[0m"
        );
        assert_eq!(
            ColorPolicy::ForcedOn.severity(Severity::Low, "low"),
            "\u{1b}[36mlow\u{1b}[0m"
        );
        assert_eq!(
            ColorPolicy::ForcedOn.severity(Severity::None, "healthy"),
            "\u{1b}[32mhealthy\u{1b}[0m"
        );
        assert_eq!(ColorPolicy::Never.severity(Severity::High, "high"), "high");
        assert_eq!(ColorPolicy::ForcedOn.bold("x"), "\u{1b}[1mx\u{1b}[0m");
        assert_eq!(ColorPolicy::Never.bold("x"), "x");
    }
}
