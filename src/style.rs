//! Shared presentation helpers for compact hunt text and the watch TUI.
//!
//! Color never carries meaning by itself: severity labels remain in the text.
//! ANSI is applied only when the caller enables color (TTY, no `--no-color`,
//! no `NO_COLOR`).

use std::time::Duration;

use crate::analysis::{Confidence, Severity};

pub const BAR_WIDTH: usize = 10;

pub fn color_enabled(no_color: bool) -> bool {
    if no_color {
        return false;
    }
    match std::env::var_os("NO_COLOR") {
        Some(value) if !value.is_empty() => false,
        _ => std::io::IsTerminal::is_terminal(&std::io::stdout()),
    }
}

pub fn unicode_enabled() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}

pub fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::None => "none",
        Severity::Low => "low",
        Severity::Moderate => "moderate",
        Severity::High => "high",
        Severity::Severe => "severe",
    }
}

pub fn severity_abbrev(severity: Severity) -> &'static str {
    match severity {
        Severity::None => "none",
        Severity::Low => "LOW",
        Severity::Moderate => "MOD",
        Severity::High => "HIGH",
        Severity::Severe => "SEV",
    }
}

pub fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

pub fn pressure_bar(fraction: f64, unicode: bool) -> String {
    let fraction = fraction.clamp(0.0, 1.0);
    let filled = ((fraction * BAR_WIDTH as f64).round() as usize).min(BAR_WIDTH);
    if unicode {
        format!("{}{}", "█".repeat(filled), "░".repeat(BAR_WIDTH - filled))
    } else {
        format!("[{}{}]", "#".repeat(filled), "-".repeat(BAR_WIDTH - filled))
    }
}

pub fn paint_severity(label: &str, severity: Severity, color: bool) -> String {
    if !color {
        return label.to_owned();
    }
    use crossterm::style::{Color, Stylize};
    match severity {
        Severity::None => label.to_owned(),
        Severity::Low => format!("{}", label.with(Color::Cyan)),
        Severity::Moderate => format!("{}", label.with(Color::Yellow)),
        Severity::High => format!("{}", label.with(Color::Red)),
        Severity::Severe => format!("{}", label.bold().with(Color::Red)),
    }
}

pub fn ratatui_severity_color(severity: Severity) -> Option<ratatui::style::Color> {
    match severity {
        Severity::None => None,
        Severity::Low => Some(ratatui::style::Color::Cyan),
        Severity::Moderate => Some(ratatui::style::Color::Yellow),
        Severity::High => Some(ratatui::style::Color::LightRed),
        Severity::Severe => Some(ratatui::style::Color::Red),
    }
}

pub fn human_duration(duration_ms: u64) -> String {
    human_duration_from_duration(Duration::from_millis(duration_ms))
}

pub fn human_duration_from_duration(duration: Duration) -> String {
    if duration.is_zero() {
        return "0ms".to_owned();
    }
    let nanoseconds = duration.as_nanos();
    if nanoseconds != 0 && nanoseconds < 1_000 {
        return format!("{nanoseconds}ns");
    }
    if nanoseconds != 0 && nanoseconds < 1_000_000 {
        return decimal_duration(nanoseconds / 1_000, nanoseconds % 1_000, "µs");
    }
    if nanoseconds < 1_000_000_000 {
        return decimal_duration(
            nanoseconds / 1_000_000,
            (nanoseconds % 1_000_000) / 1_000,
            "ms",
        );
    }
    let milliseconds = duration.as_millis();
    if milliseconds % 60_000 == 0 {
        format!("{}m", milliseconds / 60_000)
    } else if milliseconds % 1_000 == 0 {
        format!("{}s", milliseconds / 1_000)
    } else if milliseconds >= 1_000 {
        let seconds = milliseconds / 1_000;
        let fractional_milliseconds = milliseconds % 1_000;
        let fraction = format!("{fractional_milliseconds:03}")
            .trim_end_matches('0')
            .to_owned();
        format!("{seconds}.{fraction}s")
    } else {
        format!("{milliseconds}ms")
    }
}

fn decimal_duration(whole: u128, fractional: u128, unit: &str) -> String {
    if fractional == 0 {
        return format!("{whole}{unit}");
    }
    let fraction = format!("{fractional:03}").trim_end_matches('0').to_owned();
    format!("{whole}.{fraction}{unit}")
}

pub fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

pub fn terminal_name(name: &str) -> String {
    const MAX_CHARS: usize = 48;
    let mut rendered = String::new();
    for character in name.chars().take(MAX_CHARS) {
        if character.is_control() {
            rendered.push('\u{fffd}');
        } else {
            rendered.push(character);
        }
    }
    if name.chars().count() > MAX_CHARS {
        rendered.push('…');
    }
    if rendered.is_empty() {
        "<unnamed>".to_owned()
    } else {
        rendered
    }
}

pub fn psi_percent(fraction: f64) -> String {
    format!("{:.2}%", fraction * 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_bar_rounds_to_ten_cells() {
        assert_eq!(pressure_bar(0.0, false), "[----------]");
        assert_eq!(pressure_bar(0.2, false), "[##--------]");
        assert_eq!(pressure_bar(1.0, false), "[##########]");
        assert_eq!(pressure_bar(1.5, false), "[##########]");
    }

    #[test]
    fn submillisecond_durations_preserve_precision() {
        assert_eq!(human_duration_from_duration(Duration::ZERO), "0ms");
        assert_eq!(
            human_duration_from_duration(Duration::from_nanos(999)),
            "999ns"
        );
        assert_eq!(
            human_duration_from_duration(Duration::from_nanos(1_500)),
            "1.5µs"
        );
        assert_eq!(
            human_duration_from_duration(Duration::from_micros(999)),
            "999µs"
        );
        assert_eq!(
            human_duration_from_duration(Duration::from_micros(1_500)),
            "1.5ms"
        );
        assert_eq!(
            human_duration_from_duration(Duration::from_micros(1_999)),
            "1.999ms"
        );
    }
}
