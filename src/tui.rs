//! Interactive `watch` interface (ratatui + crossterm) for terminals.
//!
//! Selected by `watch::run` only when stdout is a terminal, the output format
//! is text, and `--plain` was not given. The TUI consumes the same
//! `WatchWindow` data as the text and JSON paths; the per-process detail is
//! extracted from the observation before it is reduced to `WindowSignals`, so
//! neither the JSON contract nor the tracker changes.
//!
//! Causality language matches the rest of the tool: delayed tasks were
//! observed with runnable delay, suspects and activity candidates are
//! same-window correlations and are never presented as proven causes.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Gauge, Paragraph, Sparkline};
use ratatui::{Frame, Terminal};

use crate::analysis::{
    self, AssessmentKind, Confidence, IoAssessmentKind, MemoryAssessmentKind, Severity,
};
use crate::cli::WatchOptions;
use crate::color::ColorPolicy;
use crate::observe::{
    HuntObservation, observation_from_endpoints, read_end_endpoint, read_start_endpoint,
};
use crate::watch::{
    InterruptFlag, LifecycleState, ObservationStatus, ResourceSignal, WatchTracker, WatchWindow,
    format_ms, id_label, severity_name, state_label, status_label,
};

/// Event-poll slice during a window wait: short enough that keys feel
/// immediate, long enough to keep the loop cheap.
const POLL_SLICE: Duration = Duration::from_millis(100);
/// Below this size only a one-line notice is rendered.
const MIN_WIDTH: u16 = 40;
const MIN_HEIGHT: u16 = 12;
/// Narrow terminals drop sparklines first.
const SPARKLINE_MIN_WIDTH: u16 = 72;
/// Short terminals then drop the per-process detail panel.
const DETAIL_MIN_HEIGHT: u16 = 20;
const MAX_FINDINGS_HEIGHT: u16 = 12;
const MAX_CGROUP_ROWS: usize = 4;

/// Runs the interactive interface until the window count completes, a quit
/// key drains the in-flight window, or SIGINT interrupts.
pub fn run(options: &WatchOptions) -> io::Result<()> {
    let requested = Duration::from_millis(options.interval_ms);
    if requested.is_zero() {
        return Ok(());
    }

    // Bounded runs also get a handler so SIGINT restores the terminal;
    // unbounded runs keep the watch contract: first SIGINT drains the
    // in-flight window, second SIGINT restores the terminal and exits 130.
    let interrupt =
        InterruptFlag::install_restoring(options.count.is_none(), restore_terminal_best_effort);
    let mut terminal = TerminalGuard::enter()?;
    let colors = !matches!(crate::color::resolve(options.no_color), ColorPolicy::Never);
    let mut state = TuiState::new(options.interval_ms, colors);
    let mut tracker = WatchTracker::new();
    let mut start = read_start_endpoint();
    let mut completed = 0_u32;
    terminal.draw(&state)?;

    loop {
        if options.count == Some(completed) || interrupt.raised() {
            break;
        }
        // Wait out the requested interval in short event-poll slices so keys
        // respond immediately while window boundaries stay at the requested
        // interval. Endpoint collection order and contiguity match the text
        // loop: the end-of-window snapshot becomes the next window's start.
        let deadline = Instant::now() + requested;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            if remaining.is_zero() {
                break;
            }
            if interrupt.raised() {
                state.draining = true;
            }
            if event::poll(remaining.min(POLL_SLICE))? {
                match event::read()? {
                    Event::Key(key)
                        if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                    {
                        if state.apply_key(TuiKey::from_event(&key)) {
                            terminal.draw(&state)?;
                        }
                    }
                    Event::Resize(..) => terminal.draw(&state)?,
                    _ => {}
                }
            }
        }
        let end = read_end_endpoint();
        let observation = observation_from_endpoints(&start, &end, requested);
        start = end;
        completed = completed.saturating_add(1);
        let detail = WindowDetail::from_observation(&observation);
        let mut window = tracker.ingest(&observation);
        window.count = options.count;
        window.interval_ms = options.interval_ms;
        state.ingest(window, detail);
        if !state.paused {
            terminal.draw(&state)?;
        }
        if options.count == Some(completed) || state.draining || interrupt.raised() {
            break;
        }
    }
    Ok(())
}

/// Enters the alternate screen and restores the terminal on every exit path.
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        let terminal = (|| {
            let mut stdout = io::stdout();
            crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
            Terminal::new(CrosstermBackend::new(stdout))
        })();
        match terminal {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                restore_terminal_best_effort();
                Err(error)
            }
        }
    }

    fn draw(&mut self, state: &TuiState) -> io::Result<()> {
        self.terminal.draw(|frame| draw(frame, state))?;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal_best_effort();
    }
}

/// Best-effort restore shared by the Drop guard and the SIGINT handler (Drop
/// does not run on `process::exit`).
fn restore_terminal_best_effort() {
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = crossterm::execute!(io::stdout(), crossterm::terminal::LeaveAlternateScreen);
    let _ = io::stdout().flush();
}

/// Terminal keys, decoupled from crossterm so the state machine is testable
/// without terminal events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiKey {
    Quit,
    Help,
    Pause,
    Other,
}

impl TuiKey {
    fn from_event(event: &KeyEvent) -> Self {
        match event.code {
            KeyCode::Char('q') | KeyCode::Esc => Self::Quit,
            KeyCode::Char('c') if event.modifiers.contains(KeyModifiers::CONTROL) => Self::Quit,
            KeyCode::Char('?') => Self::Help,
            KeyCode::Char('p') | KeyCode::Char(' ') => Self::Pause,
            _ => Self::Other,
        }
    }
}

/// Bounded per-resource history of PSI `some` fractions for the sparklines,
/// scaled to basis points. Kept in the TUI layer so `WindowSignals` and the
/// watch JSON contract stay unchanged.
#[derive(Debug, Default)]
struct PsiHistory {
    samples: VecDeque<u64>,
}

impl PsiHistory {
    const CAPACITY: usize = 60;
    const SCALE: u64 = 10_000;

    fn push(&mut self, fraction: Option<f64>) {
        let value = fraction.map_or(0, |fraction| {
            (fraction.clamp(0.0, 1.0) * Self::SCALE as f64).round() as u64
        });
        self.samples.push_back(value);
        while self.samples.len() > Self::CAPACITY {
            self.samples.pop_front();
        }
    }

    fn samples(&self) -> Vec<u64> {
        self.samples.iter().copied().collect()
    }
}

/// Per-process and mechanism detail of the current window, extracted from the
/// observation before it is reduced to `WindowSignals`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WindowDetail {
    delayed: Vec<String>,
    consumers: Vec<String>,
    memory_mechanism: Option<String>,
    io_candidates: Vec<String>,
}

impl WindowDetail {
    fn from_observation(observation: &HuntObservation) -> Self {
        let mut detail = Self::default();

        let cpu =
            analysis::analyze_cpu(observation.psi.as_ref().ok(), observation.cpu.as_ref().ok());
        if let Some(finding) = cpu.findings.first() {
            if finding.kind == AssessmentKind::CpuContention {
                detail.delayed = finding
                    .victims
                    .iter()
                    .take(5)
                    .map(|victim| {
                        format!(
                            "{} [{}] {:.0}% delay",
                            terminal_safe_name(&victim.name),
                            victim.key.pid,
                            victim.runnable_delay_fraction * 100.0
                        )
                    })
                    .collect();
                detail.consumers = finding
                    .suspects
                    .iter()
                    .take(3)
                    .map(|suspect| {
                        format!(
                            "{} [{}] {:.0}% cpu",
                            terminal_safe_name(&suspect.name),
                            suspect.key.pid,
                            suspect.cpu_fraction_of_one * 100.0
                        )
                    })
                    .collect();
            }
        }

        if let Some(memory) = observation.memory.as_ref() {
            let memory_analysis =
                analysis::analyze_memory(memory.psi.as_ref().ok(), memory.context.as_ref().ok());
            if let Some(finding) = memory_analysis.findings.first() {
                if matches!(
                    finding.kind,
                    MemoryAssessmentKind::Pressure
                        | MemoryAssessmentKind::ReclaimPressure
                        | MemoryAssessmentKind::SwapPressure
                        | MemoryAssessmentKind::PossibleThrashing
                ) {
                    detail.memory_mechanism = Some(match finding.mechanism_confidence {
                        Some(confidence) => format!(
                            "{} (confidence {}; same-window counters)",
                            memory_mechanism_label(finding.kind),
                            confidence_name(confidence)
                        ),
                        None => memory_mechanism_label(finding.kind).to_owned(),
                    });
                }
            }
        }

        if let Some(io) = observation.io.as_ref() {
            let io_analysis = analysis::analyze_io(
                io.psi.as_ref().ok(),
                io.diskstats.as_ref().ok(),
                io.processes.as_ref().ok(),
            );
            if let Some(finding) = io_analysis.findings.first() {
                if finding.kind == IoAssessmentKind::Pressure {
                    let mut candidates: Vec<String> = finding
                        .device_candidates
                        .iter()
                        .take(3)
                        .map(|device| {
                            format!(
                                "{} ({}:{})",
                                terminal_safe_name(&device.name),
                                device.key.major,
                                device.key.minor
                            )
                        })
                        .collect();
                    candidates.extend(
                        finding
                            .process_suspects
                            .iter()
                            .take(3_usize.saturating_sub(candidates.len()))
                            .map(|process| {
                                format!(
                                    "{} [{}]",
                                    terminal_safe_name(&process.name),
                                    process.key.pid
                                )
                            }),
                    );
                    detail.io_candidates = candidates;
                }
            }
        }

        detail
    }
}

/// Interactive state: the latest window plus display-only flags and history.
struct TuiState {
    interval_ms: u64,
    colors: bool,
    paused: bool,
    help_open: bool,
    draining: bool,
    window: Option<WatchWindow>,
    detail: WindowDetail,
    psi_history: [PsiHistory; 3],
}

impl TuiState {
    fn new(interval_ms: u64, colors: bool) -> Self {
        Self {
            interval_ms,
            colors,
            paused: false,
            help_open: false,
            draining: false,
            window: None,
            detail: WindowDetail::default(),
            psi_history: Default::default(),
        }
    }

    fn ingest(&mut self, window: WatchWindow, detail: WindowDetail) {
        self.psi_history[0].push(window.current.cpu.psi_some_fraction);
        self.psi_history[1].push(window.current.memory.psi_some_fraction);
        self.psi_history[2].push(window.current.io.psi_some_fraction);
        self.window = Some(window);
        self.detail = detail;
    }

    /// Applies a key. Returns true when the screen should be redrawn.
    fn apply_key(&mut self, key: TuiKey) -> bool {
        match key {
            TuiKey::Quit => {
                // Drain: the in-flight window still completes and renders
                // before the loop exits, matching the first-SIGINT contract.
                self.draining = true;
                true
            }
            TuiKey::Help => {
                self.help_open = !self.help_open;
                true
            }
            TuiKey::Pause => {
                self.paused = !self.paused;
                true
            }
            TuiKey::Other => false,
        }
    }

    fn header_text(&self) -> String {
        let window_label = self.window.as_ref().map_or_else(
            || "collecting window 1".to_owned(),
            |window| match window.count {
                Some(count) => format!("window {}/{}", window.index, count),
                None => format!("window {}", window.index),
            },
        );
        format!(
            "stallhunt watch · {window_label} · interval {} · q quit · ? help · p pause",
            format_ms(self.interval_ms)
        )
    }

    fn footer_text(&self) -> String {
        let mut footer = String::from("q quit · ? help · p pause");
        if self.paused {
            footer.push_str(" · paused");
        }
        if self.draining {
            footer.push_str(" · draining");
        }
        footer
    }

    fn detail_lines(&self) -> Vec<String> {
        if self.window.is_none() {
            return vec!["collecting the first window…".to_owned()];
        }
        let mut lines = Vec::new();
        if !self.detail.delayed.is_empty() {
            lines.push(format!(
                "delayed (observed runnable delay): {}",
                self.detail.delayed.join(" · ")
            ));
        }
        if !self.detail.consumers.is_empty() {
            lines.push(format!(
                "suspects (same window, not proven causal): {}",
                self.detail.consumers.join(" · ")
            ));
        }
        if let Some(mechanism) = &self.detail.memory_mechanism {
            lines.push(format!("memory mechanism: {mechanism}"));
        }
        if !self.detail.io_candidates.is_empty() {
            lines.push(format!(
                "I/O activity candidates (same window, not proven causal): {}",
                self.detail.io_candidates.join(" · ")
            ));
        }
        if lines.is_empty() {
            lines.push("(no per-process detail for this window)".to_owned());
        }
        lines
    }
}

/// Maps severity to a color unless `--no-color`/`NO_COLOR` asked for a
/// monochrome palette. Status and severity words remain in the text, so
/// color is never the only carrier of meaning.
#[derive(Debug, Clone, Copy)]
struct Palette {
    colors: bool,
}

impl Palette {
    fn severity(self, severity: Severity) -> Style {
        if !self.colors {
            return Style::default();
        }
        let color = match severity {
            Severity::Severe | Severity::High => Color::Red,
            Severity::Moderate => Color::Yellow,
            Severity::Low => Color::Cyan,
            Severity::None => Color::Green,
        };
        Style::default().fg(color)
    }

    fn title(self) -> Style {
        if self.colors {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        }
    }
}

fn draw(frame: &mut Frame, state: &TuiState) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        frame.render_widget(
            Paragraph::new(format!(
                "terminal too small for stallhunt watch; resize to at least {MIN_WIDTH}x{MIN_HEIGHT}"
            )),
            area,
        );
        return;
    }

    let palette = Palette {
        colors: state.colors,
    };
    let sparklines = area.width >= SPARKLINE_MIN_WIDTH;
    let detail_lines = state.detail_lines();
    let detail_height = if area.height >= DETAIL_MIN_HEIGHT {
        detail_lines.len() as u16 + 2
    } else {
        0
    };
    let lifecycle_rows = state
        .window
        .as_ref()
        .map_or(1, |window| window.lifecycle.len().max(1));
    let findings_height = (lifecycle_rows as u16 + 2).min(MAX_FINDINGS_HEIGHT);
    let cgroup_rows = state.window.as_ref().map_or(0, |window| {
        window
            .current
            .cgroups
            .iter()
            .filter(|(_, signal)| signal.status == ObservationStatus::Pressure)
            .take(MAX_CGROUP_ROWS)
            .count()
    });
    let cgroup_height = if cgroup_rows == 0 {
        0
    } else {
        cgroup_rows as u16 + 2
    };

    // Clamp the fixed panels against the area, findings first, so a short
    // terminal degrades the lower panels instead of pushing the footer
    // off-screen. Panels that cannot hold a bordered block (title + one row)
    // are dropped entirely.
    let mut height_budget = area.height.saturating_sub(2); // header + footer
    let pressure_height = 5.min(height_budget);
    height_budget = height_budget.saturating_sub(pressure_height);
    let findings_height = findings_height.min(height_budget);
    height_budget = height_budget.saturating_sub(findings_height);
    let detail_height = detail_height.min(height_budget);
    height_budget = height_budget.saturating_sub(detail_height);
    let cgroup_height = cgroup_height.min(height_budget);
    let detail_height = if detail_height >= 3 { detail_height } else { 0 };
    let cgroup_height = if cgroup_height >= 3 { cgroup_height } else { 0 };

    let mut constraints = vec![
        Constraint::Length(1),
        Constraint::Length(pressure_height),
        Constraint::Length(findings_height),
    ];
    if detail_height > 0 {
        constraints.push(Constraint::Length(detail_height));
    }
    if cgroup_height > 0 {
        constraints.push(Constraint::Length(cgroup_height));
    }
    constraints.push(Constraint::Min(1));
    constraints.push(Constraint::Length(1));
    let chunks = Layout::vertical(constraints).split(area);

    frame.render_widget(
        Paragraph::new(state.header_text()).style(palette.title()),
        chunks[0],
    );
    draw_pressure(frame, chunks[1], state, palette, sparklines);
    draw_findings(frame, chunks[2], state, palette);

    let mut next = 3;
    if detail_height > 0 {
        let block = Block::bordered().title("Current window detail");
        let inner = block.inner(chunks[next]);
        frame.render_widget(block, chunks[next]);
        frame.render_widget(Paragraph::new(detail_lines.join("\n")), inner);
        next += 1;
    }
    if cgroup_height > 0 {
        draw_cgroups(frame, chunks[next], state, palette);
    }
    frame.render_widget(
        Paragraph::new(state.footer_text()),
        chunks[chunks.len() - 1],
    );

    if state.help_open {
        draw_help(frame, palette);
    }
}

fn draw_pressure(
    frame: &mut Frame,
    area: Rect,
    state: &TuiState,
    palette: Palette,
    sparklines: bool,
) {
    let block = Block::bordered().title("Pressure (PSI some)");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::vertical([Constraint::Length(1); 3]).split(inner);
    let signals: [Option<&ResourceSignal>; 3] = match &state.window {
        Some(window) => [
            Some(&window.current.cpu),
            Some(&window.current.memory),
            Some(&window.current.io),
        ],
        None => [None, None, None],
    };
    let labels = ["CPU", "Memory", "I/O"];
    for (row, ((label, signal), history)) in labels
        .iter()
        .zip(signals.iter())
        .zip(state.psi_history.iter())
        .enumerate()
    {
        draw_pressure_row(
            frame, rows[row], label, *signal, history, palette, sparklines,
        );
    }
}

fn draw_pressure_row(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    signal: Option<&ResourceSignal>,
    history: &PsiHistory,
    palette: Palette,
    sparkline: bool,
) {
    let constraints = if sparkline {
        vec![
            Constraint::Length(8),
            Constraint::Length(22),
            Constraint::Min(20),
            Constraint::Length(16),
        ]
    } else {
        vec![
            Constraint::Length(8),
            Constraint::Length(22),
            Constraint::Min(0),
        ]
    };
    let cells = Layout::horizontal(constraints).split(area);
    frame.render_widget(Paragraph::new(label), cells[0]);
    let (ratio, gauge_label, status_text, style) = match signal {
        Some(signal) => (
            signal.psi_some_fraction.unwrap_or(0.0).clamp(0.0, 1.0),
            signal.psi_some_fraction.map_or_else(
                || "n/a".to_owned(),
                |value| format!("{:.2}%", value * 100.0),
            ),
            format!(
                "{}  severity {} · confidence {}",
                status_label(signal.status),
                severity_name(signal.severity),
                confidence_name(signal.confidence)
            ),
            palette.severity(signal.severity),
        ),
        None => (
            0.0,
            "…".to_owned(),
            "collecting…".to_owned(),
            Style::default(),
        ),
    };
    frame.render_widget(
        Gauge::default()
            .gauge_style(style)
            .ratio(ratio)
            .label(gauge_label),
        cells[1],
    );
    frame.render_widget(Paragraph::new(status_text), cells[2]);
    if sparkline {
        let data = history.samples();
        frame.render_widget(
            Sparkline::default().data(&data).max(PsiHistory::SCALE),
            cells[3],
        );
    }
}

fn draw_findings(frame: &mut Frame, area: Rect, state: &TuiState, palette: Palette) {
    let block = Block::bordered().title("Findings");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(window) = &state.window else {
        frame.render_widget(Paragraph::new("(collecting the first window…)"), inner);
        return;
    };
    if window.lifecycle.is_empty() {
        frame.render_widget(Paragraph::new("(no pressure findings this window)"), inner);
        return;
    }
    for (row, finding) in window
        .lifecycle
        .iter()
        .take(inner.height as usize)
        .enumerate()
    {
        let state_text = match finding.state {
            LifecycleState::Persistent => {
                format!("PERSISTENT ×{}", finding.consecutive_windows)
            }
            LifecycleState::New | LifecycleState::Resolved => state_label(finding.state).to_owned(),
        };
        let line = Line::from(vec![
            Span::styled(
                format!("{state_text:<14}"),
                palette.severity(finding.severity),
            ),
            Span::raw(format!(
                "{}  {}  severity {}",
                id_label(&finding.id),
                finding.kind,
                severity_name(finding.severity)
            )),
        ]);
        frame.render_widget(
            Paragraph::new(line),
            Rect {
                x: inner.x,
                y: inner.y + row as u16,
                width: inner.width,
                height: 1,
            },
        );
    }
}

fn draw_cgroups(frame: &mut Frame, area: Rect, state: &TuiState, palette: Palette) {
    let block = Block::bordered().title("Scoped cgroup pressure");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(window) = &state.window else {
        return;
    };
    for (row, (id, signal)) in window
        .current
        .cgroups
        .iter()
        .filter(|(_, signal)| signal.status == ObservationStatus::Pressure)
        .take(MAX_CGROUP_ROWS)
        .enumerate()
    {
        let line = Line::from(vec![
            Span::styled(id_label(id), palette.severity(signal.severity)),
            Span::raw(format!(
                "  {}  severity {}",
                signal.kind,
                severity_name(signal.severity)
            )),
        ]);
        frame.render_widget(
            Paragraph::new(line),
            Rect {
                x: inner.x,
                y: inner.y + row as u16,
                width: inner.width,
                height: 1,
            },
        );
    }
}

fn draw_help(frame: &mut Frame, palette: Palette) {
    let area = centered_rect(80, 80, frame.area());
    frame.render_widget(Clear, area);
    let lines = vec![
        Line::from("PSI some    share of wall time with at least one task stalled"),
        Line::from("PSI full    share of wall time with all tasks stalled (memory, I/O)"),
        Line::from("severity    PSI-some-derived band: none, low, moderate, high, severe"),
        Line::from("confidence  strength of the evidence behind the verdict"),
        Line::from("delayed     tasks observed with runnable delay in this window"),
        Line::from("suspects    heaviest consumers in the same window, not proven causal"),
        Line::from("lifecycle   NEW first seen · PERSISTENT ×N seen N windows in a row ·"),
        Line::from("            RESOLVED no longer observed; missing data does not resolve"),
        Line::from(""),
        Line::from(
            "q / Esc / Ctrl-C  finish the current window, then quit (SIGINT twice exits now)",
        ),
        Line::from("?                 toggle this help"),
        Line::from("p / Space         pause screen refresh (collection continues)"),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title("Help — ? to close"))
            .style(palette.title()),
        area,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1])[1]
}

fn memory_mechanism_label(kind: MemoryAssessmentKind) -> &'static str {
    match kind {
        MemoryAssessmentKind::ReclaimPressure => "direct reclaim",
        MemoryAssessmentKind::SwapPressure => "swap",
        MemoryAssessmentKind::PossibleThrashing => "possible thrashing",
        _ => "not established",
    }
}

const fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

/// Same policy as the text renderers: control characters are replaced so an
/// adversarial process name cannot inject terminal escapes, and names are
/// truncated to a bounded length.
fn terminal_safe_name(name: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watch::{FindingId, WindowSignals};
    use ratatui::backend::TestBackend;
    use std::collections::BTreeSet;

    fn pressure(kind: &'static str, severity: Severity, psi: f64) -> ResourceSignal {
        ResourceSignal {
            status: ObservationStatus::Pressure,
            severity,
            confidence: Confidence::High,
            kind,
            summary: format!("{kind} {:.2}%", psi * 100.0),
            psi_some_fraction: Some(psi),
        }
    }

    fn healthy(kind: &'static str) -> ResourceSignal {
        ResourceSignal {
            status: ObservationStatus::Healthy,
            severity: Severity::None,
            confidence: Confidence::High,
            kind,
            summary: format!("{kind} healthy"),
            psi_some_fraction: Some(0.001),
        }
    }

    fn host_signals(
        cpu: ResourceSignal,
        memory: ResourceSignal,
        io: ResourceSignal,
    ) -> WindowSignals {
        WindowSignals {
            cpu,
            memory,
            io,
            cgroups: Vec::new(),
            observed_cgroup_paths: BTreeSet::new(),
            ranking_omitted_cgroup_ids: BTreeSet::new(),
            cgroup_tracking_capped: false,
        }
    }

    fn pressured_state() -> TuiState {
        let mut tracker = WatchTracker::new();
        let mut window = tracker.ingest_signals(host_signals(
            pressure("cpu_scheduling_contention", Severity::High, 0.2),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        window.count = Some(3);
        window.interval_ms = 2_000;
        let mut state = TuiState::new(2_000, false);
        state.ingest(
            window,
            WindowDetail {
                delayed: vec!["reader [42] 40% delay".to_owned()],
                consumers: vec!["stress [7] 95% cpu".to_owned()],
                memory_mechanism: None,
                io_candidates: Vec::new(),
            },
        );
        state
    }

    fn render_text(state: &TuiState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| draw(frame, state))
            .expect("test draw");
        let buffer = terminal.backend().buffer();
        let area = buffer.area;
        let mut text = String::new();
        for y in area.top()..area.bottom() {
            for x in area.left()..area.right() {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    #[test]
    fn key_state_machine_toggles_quit_help_and_pause() {
        let mut state = TuiState::new(2_000, false);
        assert!(!state.apply_key(TuiKey::Other));
        assert!(!state.paused && !state.help_open && !state.draining);

        assert!(state.apply_key(TuiKey::Pause));
        assert!(state.paused);
        assert!(state.apply_key(TuiKey::Pause));
        assert!(!state.paused);

        assert!(state.apply_key(TuiKey::Help));
        assert!(state.help_open);
        assert!(state.apply_key(TuiKey::Help));
        assert!(!state.help_open);

        assert!(state.apply_key(TuiKey::Quit));
        assert!(state.draining);
        assert!(state.apply_key(TuiKey::Quit));
        assert!(state.draining);
    }

    #[test]
    fn crossterm_events_map_to_tui_keys() {
        assert_eq!(
            TuiKey::from_event(&KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)),
            TuiKey::Quit
        );
        assert_eq!(
            TuiKey::from_event(&KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            TuiKey::Quit
        );
        assert_eq!(
            TuiKey::from_event(&KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            TuiKey::Quit
        );
        assert_eq!(
            TuiKey::from_event(&KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE)),
            TuiKey::Help
        );
        assert_eq!(
            TuiKey::from_event(&KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE)),
            TuiKey::Pause
        );
        assert_eq!(
            TuiKey::from_event(&KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE)),
            TuiKey::Pause
        );
        assert_eq!(
            TuiKey::from_event(&KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE)),
            TuiKey::Other
        );
    }

    #[test]
    fn psi_history_scales_fractions_and_stays_bounded() {
        let mut history = PsiHistory::default();
        history.push(Some(0.2));
        history.push(None);
        history.push(Some(1.5));
        assert_eq!(history.samples(), vec![2_000, 0, 10_000]);
        for _ in 0..(PsiHistory::CAPACITY + 10) {
            history.push(Some(0.01));
        }
        assert_eq!(history.samples().len(), PsiHistory::CAPACITY);
    }

    #[test]
    fn renders_header_pressure_rows_lifecycle_and_detail() {
        let state = pressured_state();
        let text = render_text(&state, 100, 30);
        assert!(text.contains("stallhunt watch · window 1/3 · interval 2s"));
        assert!(text.contains("Pressure (PSI some)"));
        assert!(text.contains("20.00%"));
        assert!(text.contains("pressure  severity high · confidence high"));
        assert!(text.contains("NEW"));
        assert!(text.contains("cpu_scheduling_contention"));
        assert!(text.contains("delayed (observed runnable delay): reader [42] 40% delay"));
        assert!(text.contains("suspects (same window, not proven causal): stress [7] 95% cpu"));
        assert!(text.contains("q quit · ? help · p pause"));
    }

    #[test]
    fn renders_healthy_window_without_findings() {
        let mut tracker = WatchTracker::new();
        let window = tracker.ingest_signals(host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        let mut state = TuiState::new(2_000, false);
        state.ingest(window, WindowDetail::default());
        let text = render_text(&state, 100, 30);
        assert!(text.contains("healthy  severity none · confidence high"));
        assert!(text.contains("(no pressure findings this window)"));
        assert!(text.contains("(no per-process detail for this window)"));
    }

    #[test]
    fn renders_scoped_cgroup_findings_panel() {
        let mut signals = host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        );
        signals.cgroups.push((
            FindingId::Cgroup {
                path: "/system.slice/app.service".to_owned(),
                resource: crate::analysis::CgroupResourceKind::Memory,
            },
            pressure("cgroup_memory_swap_pressure", Severity::High, 0.25),
        ));
        let mut tracker = WatchTracker::new();
        let window = tracker.ingest_signals(signals);
        let mut state = TuiState::new(2_000, false);
        state.ingest(window, WindowDetail::default());
        let text = render_text(&state, 100, 30);
        assert!(text.contains("Scoped cgroup pressure"));
        assert!(text.contains("/system.slice/app.service (memory)"));
        assert!(text.contains("cgroup_memory_swap_pressure"));
    }

    #[test]
    fn help_overlay_toggles_over_the_layout() {
        let mut state = pressured_state();
        state.apply_key(TuiKey::Help);
        let text = render_text(&state, 100, 30);
        assert!(text.contains("PSI some"));
        assert!(text.contains("PSI full"));
        assert!(text.contains("not proven causal"));
        assert!(text.contains("p / Space"));

        state.apply_key(TuiKey::Help);
        let text = render_text(&state, 100, 30);
        assert!(!text.contains("PSI full"));
    }

    #[test]
    fn paused_and_draining_indicators_render_in_the_footer() {
        let mut state = pressured_state();
        state.apply_key(TuiKey::Pause);
        let text = render_text(&state, 100, 30);
        assert!(text.contains("paused"));

        state.apply_key(TuiKey::Quit);
        let text = render_text(&state, 100, 30);
        assert!(text.contains("paused"));
        assert!(text.contains("draining"));
    }

    #[test]
    fn narrow_terminal_drops_sparklines_and_short_terminal_drops_detail() {
        let state = pressured_state();
        // Width below SPARKLINE_MIN_WIDTH still renders rows and detail.
        let text = render_text(&state, 60, 30);
        assert!(text.contains("20.00%"));
        assert!(text.contains("Current window detail"));
        // Height below DETAIL_MIN_HEIGHT drops only the detail panel.
        let text = render_text(&state, 100, 16);
        assert!(text.contains("Pressure (PSI some)"));
        assert!(!text.contains("Current window detail"));
    }

    #[test]
    fn tiny_terminal_shows_only_a_notice() {
        let state = pressured_state();
        let text = render_text(&state, 30, 8);
        assert!(text.contains("terminal too small"));
        assert!(!text.contains("Pressure (PSI some)"));
    }

    #[test]
    fn tall_findings_list_is_clamped_to_a_short_terminal() {
        // Twelve findings on a 16-row terminal: the findings panel must shrink
        // and the footer must stay on screen instead of overflowing the buffer.
        let mut signals = host_signals(
            pressure("cpu_scheduling_contention", Severity::High, 0.2),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        );
        for n in 0..11 {
            signals.cgroups.push((
                FindingId::Cgroup {
                    path: format!("/slice/{n}.service"),
                    resource: crate::analysis::CgroupResourceKind::Cpu,
                },
                pressure("cgroup_cpu_pressure", Severity::Low, 0.02),
            ));
        }
        let mut tracker = WatchTracker::new();
        let window = tracker.ingest_signals(signals);
        assert_eq!(window.lifecycle.len(), 12);
        let mut state = TuiState::new(2_000, false);
        state.ingest(window, WindowDetail::default());
        let text = render_text(&state, 80, 16);
        assert!(text.contains("stallhunt watch · window 1 · interval 2s"));
        assert!(text.contains("Findings"));
        assert!(text.contains("/slice/0.service (cpu)"));
        // Clamped panel: not all twelve rows fit, but the footer is visible.
        assert!(text.contains("q quit · ? help · p pause"));
    }

    #[test]
    fn cgroup_panel_drops_when_it_cannot_fit() {
        let mut signals = host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        );
        signals.cgroups.push((
            FindingId::Cgroup {
                path: "/system.slice/app.service".to_owned(),
                resource: crate::analysis::CgroupResourceKind::Memory,
            },
            pressure("cgroup_memory_swap_pressure", Severity::High, 0.25),
        ));
        let mut tracker = WatchTracker::new();
        let window = tracker.ingest_signals(signals);
        let mut state = TuiState::new(2_000, false);
        state.ingest(window, WindowDetail::default());
        // 80x14: findings (1 row) and cgroup (1 row) compete for 7 rows.
        let text = render_text(&state, 80, 14);
        assert!(text.contains("Scoped cgroup pressure"));
        assert!(text.contains("q quit · ? help · p pause"));
        // At 80x12 only the findings panel keeps a bordered block.
        let text = render_text(&state, 80, 12);
        assert!(!text.contains("Scoped cgroup pressure"));
        assert!(text.contains("q quit · ? help · p pause"));
    }

    #[test]
    fn waiting_state_renders_before_the_first_window() {
        let state = TuiState::new(2_000, false);
        let text = render_text(&state, 100, 30);
        assert!(text.contains("collecting window 1"));
        assert!(text.contains("collecting…"));
        assert!(text.contains("(collecting the first window…)"));
    }

    #[test]
    fn detail_from_empty_observation_stays_empty() {
        let observation = crate::observe::empty_interval_observation();
        let detail = WindowDetail::from_observation(&observation);
        assert_eq!(detail, WindowDetail::default());
    }

    #[test]
    fn terminal_safe_name_replaces_control_characters() {
        assert_eq!(terminal_safe_name("ok"), "ok");
        assert_eq!(
            terminal_safe_name("bad\u{1b}[31mname"),
            "bad\u{fffd}[31mname"
        );
        assert_eq!(terminal_safe_name(""), "<unnamed>");
    }
}
