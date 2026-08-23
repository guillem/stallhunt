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
///
/// Consumed starting with the compact hunt report; unused until then.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Never,
    Always,
}

/// Resolve the color mode from the `--no-color` flag, the `NO_COLOR`
/// environment variable (any non-empty value disables color, per the
/// https://no-color.org convention), and TTY detection.
///
/// Consumed starting with the compact hunt report; unused until then.
#[allow(dead_code)]
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
/// determined. Reads `COLUMNS` if set; a later phase replaces this with a
/// `crossterm::terminal::size()`-based implementation for real TTY queries.
///
/// Consumed starting with the compact hunt report; unused until then.
#[allow(dead_code)]
pub fn terminal_width() -> usize {
    parse_terminal_width(std::env::var("COLUMNS").ok().as_deref())
}

fn parse_terminal_width(columns_env: Option<&str>) -> usize {
    columns_env
        .and_then(|value| value.parse::<usize>().ok())
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
        assert_eq!(parse_terminal_width(None), 80);
        assert_eq!(parse_terminal_width(Some("not a number")), 80);
        assert_eq!(parse_terminal_width(Some("10")), 60);
        assert_eq!(parse_terminal_width(Some("120")), 120);
    }
}
