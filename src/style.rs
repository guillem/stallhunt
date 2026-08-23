//! Shared terminal and vocabulary helpers used by every renderer.
//!
//! This module is the single place that decides how severity, confidence,
//! and lifecycle vocabulary are labeled, and how terminal color/width are
//! resolved. Renderers consume these instead of re-deriving labels or
//! probing the terminal themselves, so pipe output and any styled surface
//! stay in agreement.

use crate::analysis::{Confidence, Severity};
use crate::watch::{LifecycleState, ObservationStatus};

/// Whether ANSI color may be emitted. Layout (compact vs. legacy) is a
/// separate decision from color; `Never` still renders the compact layout,
/// just without escape codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Never,
    Always,
}

/// Resolve the color mode from the `--no-color` flag, the `NO_COLOR`
/// environment variable (any non-empty value disables color, per the
/// https://no-color.org convention), and TTY detection.
pub fn resolve_color(no_color_flag: bool, is_tty: bool) -> ColorMode {
    let no_color_env = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
    if no_color_flag || no_color_env || !is_tty {
        ColorMode::Never
    } else {
        ColorMode::Always
    }
}

const DEFAULT_TERMINAL_WIDTH: usize = 80;
const MIN_TERMINAL_WIDTH: usize = 60;

/// Terminal width in columns, falling back to 80 when it cannot be
/// determined. Queries the real terminal size via `crossterm`; a `COLUMNS`
/// environment variable (not exported to child processes by most shells,
/// but honored by scripts/tests that set it explicitly) takes precedence
/// when present, matching common CLI convention.
pub fn terminal_width() -> usize {
    let columns_env = std::env::var("COLUMNS").ok();
    let queried = crossterm::terminal::size().ok().map(|(width, _)| width);
    parse_terminal_width(columns_env.as_deref(), queried)
}

/// Char-count truncation to at most `width` characters, appending `…` when
/// truncated. Consistent with `render::terminal_name`'s approach: no
/// unicode-width dependency, a simple upper bound on rendered length.
pub fn truncate_ellipsis(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let char_count = text.chars().count();
    if char_count <= width {
        return text.to_owned();
    }
    let keep = width.saturating_sub(1).max(1);
    let mut truncated: String = text.chars().take(keep).collect();
    truncated.push('…');
    truncated
}

fn parse_terminal_width(columns_env: Option<&str>, queried: Option<u16>) -> usize {
    columns_env
        .and_then(|value| value.parse::<usize>().ok())
        .or(queried.map(|width| width as usize))
        .map(|width| width.max(MIN_TERMINAL_WIDTH))
        .unwrap_or(DEFAULT_TERMINAL_WIDTH)
}

pub const fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::None => "none",
        Severity::Low => "low",
        Severity::Moderate => "moderate",
        Severity::High => "high",
        Severity::Severe => "severe",
    }
}

pub const fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

pub const fn state_label(state: LifecycleState) -> &'static str {
    match state {
        LifecycleState::New => "NEW",
        LifecycleState::Persistent => "PERSISTENT",
        LifecycleState::Resolved => "RESOLVED",
    }
}

pub const fn status_label(status: ObservationStatus) -> &'static str {
    match status {
        ObservationStatus::Pressure => "pressure",
        ObservationStatus::Healthy => "healthy",
        ObservationStatus::Unconfirmed => "unconfirmed",
    }
}

/// Layout parameters for the compact hunt/replay report. Renderers take this
/// explicitly rather than probing the terminal or environment themselves, so
/// tests can pin deterministic values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportLayout {
    pub width: usize,
    pub color: ColorMode,
    pub verbose: bool,
}

/// A supporting color signal for a severity level. Never the only carrier of
/// the severity word itself — `paint` always leaves the plain word intact
/// and only wraps it in escape codes when `ColorMode::Always`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeverityTone {
    None,
    Low,
    Moderate,
    High,
    Severe,
}

pub const fn severity_tone(severity: Severity) -> SeverityTone {
    match severity {
        Severity::None => SeverityTone::None,
        Severity::Low => SeverityTone::Low,
        Severity::Moderate => SeverityTone::Moderate,
        Severity::High => SeverityTone::High,
        Severity::Severe => SeverityTone::Severe,
    }
}

const fn sgr_code(tone: SeverityTone) -> &'static str {
    match tone {
        SeverityTone::None => "2", // dim
        SeverityTone::Low => "32",
        SeverityTone::Moderate => "33",
        SeverityTone::High => "31",
        SeverityTone::Severe => "1;31", // bold red
    }
}

const SGR_RESET: &str = "\x1b[0m";

/// Wrap `text` in the SGR escape codes for `tone` when `mode` is `Always`;
/// otherwise return it unchanged. `text` itself is never altered, so the
/// plain word is always present regardless of color mode.
pub fn paint(text: &str, tone: SeverityTone, mode: ColorMode) -> String {
    match mode {
        ColorMode::Never => text.to_owned(),
        ColorMode::Always => format!("\x1b[{}m{text}{SGR_RESET}", sgr_code(tone)),
    }
}

/// The same severity-to-visual-weight vocabulary as [`paint`], expressed as
/// a `ratatui` style for the watch TUI. `SeverityTone`/`severity_tone` is
/// the single source of truth for which severity gets which visual weight;
/// this and `paint` are just two backends (ANSI text, ratatui widgets) for
/// that one mapping, so the compact report and the TUI can never drift
/// apart on what "high" or "severe" looks like.
pub fn severity_ratatui_style(tone: SeverityTone, mode: ColorMode) -> ratatui::style::Style {
    use ratatui::style::{Color, Modifier, Style};
    if mode == ColorMode::Never {
        return Style::default();
    }
    match tone {
        SeverityTone::None => Style::default().add_modifier(Modifier::DIM),
        SeverityTone::Low => Style::default().fg(Color::Green),
        SeverityTone::Moderate => Style::default().fg(Color::Yellow),
        SeverityTone::High => Style::default().fg(Color::Red),
        SeverityTone::Severe => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_flag_forces_never() {
        assert_eq!(resolve_color(true, true), ColorMode::Never);
    }

    #[test]
    fn non_tty_forces_never() {
        assert_eq!(resolve_color(false, false), ColorMode::Never);
    }

    #[test]
    fn tty_without_no_color_allows_color_unless_no_color_env_is_set() {
        // NO_COLOR may be set in the ambient test environment; only assert
        // the relationship, not an absolute mode.
        let no_color_env = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
        let expected = if no_color_env {
            ColorMode::Never
        } else {
            ColorMode::Always
        };
        assert_eq!(resolve_color(false, true), expected);
    }

    #[test]
    fn terminal_width_has_a_sane_default_and_minimum() {
        assert_eq!(parse_terminal_width(None, None), 80);
        assert_eq!(parse_terminal_width(Some("not a number"), None), 80);
        assert_eq!(parse_terminal_width(Some("10"), None), 60);
        assert_eq!(parse_terminal_width(Some("120"), None), 120);
        assert_eq!(
            parse_terminal_width(None, Some(200)),
            200,
            "a queried real terminal size is used when COLUMNS is unset"
        );
        assert_eq!(
            parse_terminal_width(Some("100"), Some(200)),
            100,
            "COLUMNS still takes precedence over a queried size when both are present"
        );
        assert_eq!(
            parse_terminal_width(None, Some(10)),
            60,
            "a queried size is still clamped to the minimum"
        );
    }
}
