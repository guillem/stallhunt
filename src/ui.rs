//! Terminal presentation utilities shared by the renderers.
//!
//! Stallhunt is diagnosis-first, not a decoration exercise, so styling stays
//! deliberately small: a color policy (terminal + `--no-color` + `NO_COLOR`),
//! a tiny palette of ANSI styles, a severity-to-style mapping used by every
//! renderer so colors mean the same thing everywhere, block bars, and a
//! terminal-width probe.
//!
//! Styling must never be the only carrier of meaning: every styled element
//! keeps its textual label (`high`, `pressure`, `ok`, ...), and disabled
//! colors produce exactly the same text without escape sequences.

use std::io::IsTerminal;

/// The `--no-color`/automatic choice as expressed on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorMode {
    /// Enable color when stdout is a terminal and `NO_COLOR` is unset.
    #[default]
    Auto,
    /// Never emit ANSI sequences regardless of the terminal.
    Never,
}

/// The resolved decision used while rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorUse {
    Enabled,
    Disabled,
}

impl ColorUse {
    /// Resolve the CLI choice against the live stdout terminal and the
    /// `NO_COLOR` convention (set and non-empty disables color).
    pub fn resolve_stdout(mode: ColorMode) -> Self {
        Self::resolve(
            mode,
            std::io::stdout().is_terminal(),
            std::env::var_os("NO_COLOR"),
        )
    }

    /// Pure resolution used by tests and non-stdout renderers.
    ///
    /// `NO_COLOR` present and non-empty always disables color; an empty value
    /// is ignored, per the convention.
    pub fn resolve(
        mode: ColorMode,
        is_terminal: bool,
        no_color: Option<std::ffi::OsString>,
    ) -> Self {
        if mode == ColorMode::Never {
            return Self::Disabled;
        }
        if let Some(value) = no_color {
            if !value.is_empty() {
                return Self::Disabled;
            }
        }
        if is_terminal {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }

    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// The minimal palette. Named by role rather than by raw color so severity
/// mapping stays in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Dim,
    Bold,
    Green,
    Cyan,
    Yellow,
    BrightRed,
    BoldRed,
    Magenta,
}

impl Style {
    const fn sequence(self) -> &'static str {
        match self {
            Self::Dim => "\u{1b}[2m",
            Self::Bold => "\u{1b}[1m",
            Self::Green => "\u{1b}[32m",
            Self::Cyan => "\u{1b}[36m",
            Self::Yellow => "\u{1b}[33m",
            Self::BrightRed => "\u{1b}[91m",
            Self::BoldRed => "\u{1b}[1;31m",
            Self::Magenta => "\u{1b}[35m",
        }
    }
}

/// Wrap `text` in the style's SGR sequence when color is enabled.
pub fn paint(text: &str, style: Style, color: ColorUse) -> String {
    if color.is_enabled() && !text.is_empty() {
        format!("{}{}\u{1b}[0m", style.sequence(), text)
    } else {
        text.to_owned()
    }
}

/// A piece of visible text plus an optional style.
///
/// Frames compose rows from spans so alignment and truncation are computed on
/// visible characters while styling is applied last; escape sequences are
/// never measured or cut.
#[derive(Debug, Clone)]
pub struct Span {
    pub text: String,
    pub style: Option<Style>,
}

impl Span {
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            style: None,
        }
    }

    pub fn styled(text: impl Into<String>, style: Style) -> Self {
        Self {
            text: text.into(),
            style: Some(style),
        }
    }

    pub fn visible_width(&self) -> usize {
        self.text.chars().count()
    }

    pub fn render(&self, color: ColorUse) -> String {
        match self.style {
            Some(style) => paint(&self.text, style, color),
            None => self.text.clone(),
        }
    }
}

/// Style for a pressure severity. This is the single severity-color mapping
/// shared by the hunt and watch renderers.
pub const fn severity_style(severity: crate::analysis::Severity) -> Style {
    use crate::analysis::Severity;
    match severity {
        Severity::None => Style::Green,
        Severity::Low => Style::Cyan,
        Severity::Moderate => Style::Yellow,
        Severity::High => Style::BrightRed,
        Severity::Severe => Style::BoldRed,
    }
}

/// Style for observation statuses that are not a pressure severity.
pub const fn status_style(status: StatusWord) -> Style {
    match status {
        StatusWord::Ok => Style::Green,
        StatusWord::Unconfirmed => Style::Magenta,
        StatusWord::Unavailable => Style::Dim,
    }
}

/// The non-severity status vocabulary shared by renderers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusWord {
    Ok,
    Unconfirmed,
    Unavailable,
}

impl StatusWord {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Unconfirmed => "unconfirmed",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Plain horizontal block bar for a 0.0–1.0 fraction.
///
/// Filled cells use `█` and empty cells `░` so the bar stays readable without
/// color; callers add styling via [`Span`] or [`paint`]. `fraction` is
/// clamped; `width` of 0 yields an empty bar.
pub fn bar_text(fraction: f64, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let clamped = fraction.clamp(0.0, 1.0);
    let filled = ((clamped * width as f64).round() as usize).min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

pub const DEFAULT_WIDTH: usize = 80;
pub const MIN_WIDTH: usize = 60;
pub const MAX_WIDTH: usize = 160;

/// Terminal width of stdout when it is a terminal and reports a sane value.
pub fn terminal_width() -> Option<usize> {
    let winsize = rustix::termios::tcgetwinsize(std::io::stdout()).ok()?;
    if winsize.ws_col == 0 {
        return None;
    }
    Some(winsize.ws_col as usize)
}

/// Clamp a measured width into the supported layout range.
pub const fn clamp_width(width: usize) -> usize {
    if width < MIN_WIDTH {
        MIN_WIDTH
    } else if width > MAX_WIDTH {
        MAX_WIDTH
    } else {
        width
    }
}

/// Resolved TTY presentation parameters for one `watch` run.
///
/// `refresh` is true only for text output on an interactive terminal; piped
/// text and JSON always append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchDisplay {
    pub refresh: bool,
    pub color: ColorUse,
    pub width: usize,
}

impl WatchDisplay {
    /// Probe the real terminal once per `watch` run.
    pub fn probe(options: &crate::cli::WatchOptions) -> Self {
        let refresh =
            options.output == crate::cli::OutputFormat::Text && std::io::stdout().is_terminal();
        let width = if refresh {
            terminal_width().map(clamp_width).unwrap_or(DEFAULT_WIDTH)
        } else {
            DEFAULT_WIDTH
        };
        Self {
            refresh,
            color: ColorUse::resolve_stdout(options.color),
            width,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::Severity;

    fn no_color() -> Option<std::ffi::OsString> {
        None
    }

    #[test]
    fn color_requires_terminal_choice_and_env() {
        assert_eq!(
            ColorUse::resolve(ColorMode::Auto, true, no_color()),
            ColorUse::Enabled
        );
        assert_eq!(
            ColorUse::resolve(ColorMode::Auto, false, no_color()),
            ColorUse::Disabled
        );
        assert_eq!(
            ColorUse::resolve(ColorMode::Never, true, no_color()),
            ColorUse::Disabled
        );
    }

    #[test]
    fn no_color_env_disables_unless_empty() {
        assert_eq!(
            ColorUse::resolve(ColorMode::Auto, true, Some("1".into())),
            ColorUse::Disabled
        );
        assert_eq!(
            ColorUse::resolve(ColorMode::Auto, true, Some("".into())),
            ColorUse::Enabled
        );
        // The flag still wins when the environment is absent.
        assert_eq!(
            ColorUse::resolve(ColorMode::Never, true, Some("".into())),
            ColorUse::Disabled
        );
    }

    #[test]
    fn paint_is_identity_without_color() {
        assert_eq!(paint("high", Style::BrightRed, ColorUse::Disabled), "high");
        let styled = paint("high", Style::BrightRed, ColorUse::Enabled);
        assert_eq!(styled, "\u{1b}[91mhigh\u{1b}[0m");
        // Empty text is never wrapped, so alignment stays stable.
        assert_eq!(paint("", Style::Dim, ColorUse::Enabled), "");
    }

    #[test]
    fn severity_and_status_styles_rank_consistently() {
        assert_eq!(severity_style(Severity::None), Style::Green);
        assert_eq!(severity_style(Severity::Low), Style::Cyan);
        assert_eq!(severity_style(Severity::Moderate), Style::Yellow);
        assert_eq!(severity_style(Severity::High), Style::BrightRed);
        assert_eq!(severity_style(Severity::Severe), Style::BoldRed);
        assert_eq!(status_style(StatusWord::Ok), Style::Green);
        assert_eq!(status_style(StatusWord::Unavailable), Style::Dim);
    }

    #[test]
    fn bars_clamp_fraction_and_width() {
        assert_eq!(bar_text(0.5, 10), "█████░░░░░");
        assert_eq!(bar_text(2.0, 4), "████");
        assert_eq!(bar_text(-1.0, 4), "░░░░");
        assert_eq!(bar_text(0.5, 0), "");
        // Rounding keeps small-but-visible fractions represented.
        assert_eq!(bar_text(0.06, 10), "█░░░░░░░░░");
        assert_eq!(bar_text(0.04, 10), "░░░░░░░░░░");
        let colored = paint(&bar_text(1.0, 3), Style::BoldRed, ColorUse::Enabled);
        assert_eq!(colored, "\u{1b}[1;31m███\u{1b}[0m");
    }

    #[test]
    fn width_probing_clamps_into_the_layout_range() {
        assert_eq!(clamp_width(10), MIN_WIDTH);
        assert_eq!(clamp_width(80), 80);
        assert_eq!(clamp_width(4_000), MAX_WIDTH);
    }
}
