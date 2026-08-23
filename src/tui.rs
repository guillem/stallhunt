//! Full-screen watch presentation (ADR-0013).
//!
//! The TUI renders the same `WatchWindow` lifecycle data as the classic text
//! renderer: host pressure gauges, finding lifecycle, scoped cgroup pressure,
//! and bounded history. It introduces no collectors and no inference. Watch
//! tracking and collection stay in `watch.rs`; this module only presents
//! windows and handles terminal input.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Row, Sparkline, Table, Wrap},
};

use crate::analysis::Severity;
use crate::cli::WatchOptions;
use crate::observe::{observation_from_endpoints, read_end_endpoint, read_start_endpoint};
use crate::watch::{
    self, InterruptFlag, LifecycleState, ObservationStatus, ResourceSignal, WatchTracker,
    WatchWindow,
};

static TUI_ACTIVE: AtomicBool = AtomicBool::new(false);

const MIN_WIDTH: u16 = 36;
const MIN_HEIGHT: u16 = 10;
const POLL_SLICE: Duration = Duration::from_millis(100);

/// Runs the watch TUI. Returns `Ok(true)` when the TUI ran, `Ok(false)` when
/// the terminal could not host it (the caller falls back to classic text),
/// and `Err` for failures during an established session.
pub fn run(options: &WatchOptions) -> io::Result<bool> {
    if terminal::size().is_err() {
        return Ok(false);
    }
    if terminal::enable_raw_mode().is_err() {
        return Ok(false);
    }
    if execute!(io::stdout(), EnterAlternateScreen, cursor::Hide).is_err() {
        let _ = terminal::disable_raw_mode();
        return Ok(false);
    }
    TUI_ACTIVE.store(true, Ordering::SeqCst);
    let guard = TerminalGuard;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let requested = Duration::from_millis(options.interval_ms);
    let _interrupt = InterruptFlag::install(options.count.is_none(), || {
        if TUI_ACTIVE.load(Ordering::SeqCst) {
            restore_terminal();
        }
    });
    let mut model = TuiModel::new(options.interval_ms);

    if requested.is_zero() {
        drop(guard);
        return Ok(true);
    }

    let mut start = read_start_endpoint();
    let mut tracker = WatchTracker::new();
    let mut completed = 0_u32;
    let mut deadline = Instant::now() + requested;

    let outcome: io::Result<u32> = loop {
        terminal.draw(|frame| draw(frame, &model))?;
        if options.count == Some(completed) {
            break Ok(completed);
        }
        if _interrupt.raised() {
            model.draining = true;
        }
        let now = Instant::now();
        if now >= deadline {
            let end = read_end_endpoint();
            let observation = observation_from_endpoints(&start, &end, requested);
            start = end;
            completed = completed.saturating_add(1);
            let mut window = tracker.ingest(&observation);
            window.count = options.count;
            window.interval_ms = options.interval_ms;
            model.window = Some(window);
            if model.draining {
                terminal.draw(|frame| draw(frame, &model))?;
                break Ok(completed);
            }
            deadline = Instant::now() + requested;
            continue;
        }
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(POLL_SLICE);
        if event::poll(slice)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => break Ok(completed),
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if model.draining {
                                drop(guard);
                                std::process::exit(130);
                            }
                            model.draining = true;
                        }
                        KeyCode::Char('?') | KeyCode::Char('h') => {
                            model.show_help = !model.show_help;
                        }
                        KeyCode::Char('e') => model.show_details = !model.show_details,
                        KeyCode::Esc => model.show_help = false,
                        _ => {}
                    }
                }
            }
        }
    };

    drop(guard);
    let windows = outcome?;
    let mut stdout = io::stdout();
    let _ = writeln!(stdout, "stallhunt watch stopped after {windows} window(s).");
    let _ = stdout.flush();
    Ok(true)
}

fn restore_terminal() {
    let _ = terminal::disable_raw_mode();
    let _ = execute!(io::stdout(), cursor::Show, LeaveAlternateScreen);
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        TUI_ACTIVE.store(false, Ordering::SeqCst);
        restore_terminal();
    }
}

#[derive(Debug, Clone)]
struct TuiModel {
    interval_ms: u64,
    window: Option<WatchWindow>,
    draining: bool,
    show_help: bool,
    show_details: bool,
    color: bool,
}

impl TuiModel {
    fn new(interval_ms: u64) -> Self {
        Self {
            interval_ms,
            window: None,
            draining: false,
            show_help: false,
            show_details: false,
            color: std::env::var_os("NO_COLOR").is_none(),
        }
    }

    fn styled(&self, color: Color, bold: bool) -> Style {
        if !self.color {
            return Style::default();
        }
        let mut style = Style::default().fg(color);
        if bold {
            style = style.add_modifier(Modifier::BOLD);
        }
        style
    }
}

const fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::None => Color::Green,
        Severity::Low => Color::Cyan,
        Severity::Moderate => Color::Yellow,
        Severity::High => Color::Red,
        Severity::Severe => Color::Magenta,
    }
}

const fn signal_color(signal: &ResourceSignal) -> Color {
    match signal.status {
        ObservationStatus::Pressure => severity_color(signal.severity),
        ObservationStatus::Healthy => Color::Green,
        ObservationStatus::Unconfirmed => Color::DarkGray,
    }
}

fn draw(frame: &mut Frame, model: &TuiModel) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        frame.render_widget(
            Paragraph::new(
                "Terminal too small for the stallhunt watch TUI.\n\
                 Enlarge the window, or rerun with --no-tui for classic text.",
            )
            .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(5),
            Constraint::Min(3),
            Constraint::Length(4),
            Constraint::Length(1),
        ])
        .split(area);

    frame.render_widget(header_line(model), chunks[0]);
    frame.render_widget(gauge_panel(model, chunks[1]), chunks[1]);
    render_middle(frame, model, chunks[2]);
    render_bottom_row(frame, model, chunks[3]);
    frame.render_widget(footer_line(model), chunks[4]);

    if model.show_help {
        render_help(frame, area);
    }
}

fn header_line(model: &TuiModel) -> Paragraph<'static> {
    let mut spans = vec![
        Span::styled(
            format!("stallhunt {} · watch", env!("CARGO_PKG_VERSION")),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(" · "),
        Span::raw(match &model.window {
            Some(window) => match window.count {
                Some(count) => format!("window {}/{}", window.index, count),
                None => format!("window {}", window.index),
            },
            None => "collecting first window".to_owned(),
        }),
        Span::raw(" · "),
        Span::raw(format!("interval {}", watch::format_ms(model.interval_ms))),
    ];
    if model.draining {
        spans.push(Span::raw(" · "));
        spans.push(Span::styled(
            "draining: finishing the in-flight window, then exit",
            Style::default().add_modifier(Modifier::BOLD),
        ));
    }
    Paragraph::new(Line::from(spans))
}

fn gauge_panel(model: &TuiModel, area: Rect) -> Paragraph<'static> {
    let inner_width = area.width.saturating_sub(2);
    let mut lines = Vec::new();
    if let Some(window) = &model.window {
        for (label, signal) in [
            ("CPU", &window.current.cpu),
            ("Memory", &window.current.memory),
            ("I/O", &window.current.io),
        ] {
            lines.push(pressure_line(model, label, signal, inner_width));
        }
    } else {
        for label in ["CPU", "Memory", "I/O"] {
            lines.push(Line::from(format!("{label:<7} waiting for first window")));
        }
    }
    Paragraph::new(lines).block(Block::bordered().title("Pressure (exact-window PSI some)"))
}

fn pressure_line(
    model: &TuiModel,
    label: &str,
    signal: &ResourceSignal,
    width: u16,
) -> Line<'static> {
    let fraction = signal.psi_some_fraction.unwrap_or(0.0).clamp(0.0, 1.0);
    let right = format!(
        "{:>6.2}% {} {}",
        fraction * 100.0,
        watch::status_label(signal.status),
        watch::severity_name(signal.severity)
    );
    // The label renders padded to seven columns, then one space before the
    // bar and one space before the right-hand text.
    let bar_width = usize::from(width).saturating_sub(7 + 2 + right.len());
    let bar_width = bar_width.max(4);
    let filled = (fraction * bar_width as f64).round() as usize;
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(bar_width - filled));
    let color = signal_color(signal);
    Line::from(vec![
        Span::raw(format!("{label:<7}")),
        Span::styled(
            bar,
            model.styled(color, signal.status == ObservationStatus::Pressure),
        ),
        Span::raw(" "),
        Span::styled(right, model.styled(color, false)),
    ])
}

fn render_middle(frame: &mut Frame, model: &TuiModel, area: Rect) {
    if model.show_details {
        frame.render_widget(details_panel(model), area);
        return;
    }
    let empty_message = match &model.window {
        None => Some("waiting for first window"),
        Some(window) if window.lifecycle.is_empty() => Some("no pressure findings this window"),
        Some(_) => None,
    };
    match empty_message {
        Some(message) => frame.render_widget(
            Paragraph::new(message)
                .block(Block::bordered().title("Finding lifecycle (new / persistent / resolved)")),
            area,
        ),
        None => frame.render_widget(lifecycle_table(model), area),
    }
}

fn lifecycle_table(model: &TuiModel) -> Table<'static> {
    let mut rows = Vec::new();
    if let Some(window) = &model.window {
        for finding in &window.lifecycle {
            let mut windows = finding.consecutive_windows.to_string();
            if finding.state == LifecycleState::Persistent {
                if let Some(previous) = finding.previous_severity {
                    windows.push_str(&format!(" (was {})", watch::severity_name(previous)));
                }
                if !finding.confirmed {
                    windows.push_str(" unconfirmed");
                }
            }
            rows.push(Row::new(vec![
                Span::styled(
                    watch::state_label(finding.state),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(watch::id_label(&finding.id)),
                Span::raw(finding.kind.to_owned()),
                Span::styled(
                    watch::severity_name(finding.severity),
                    model.styled(severity_color(finding.severity), true),
                ),
                Span::raw(match finding.psi_some_fraction {
                    Some(fraction) => format!("{:.2}%", fraction * 100.0),
                    None => "—".to_owned(),
                }),
                Span::raw(windows),
            ]));
        }
    }
    let header = Row::new(vec![
        Span::styled("STATE", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled("SCOPE", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled("KIND", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled("SEVERITY", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled("PSI", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled("WINDOWS", Style::default().add_modifier(Modifier::BOLD)),
    ]);
    Table::new(
        rows,
        [
            Constraint::Length(11),
            Constraint::Percentage(26),
            Constraint::Percentage(26),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Min(16),
        ],
    )
    .header(header)
    .block(Block::bordered().title("Finding lifecycle (new / persistent / resolved)"))
    .column_spacing(1)
}

fn render_bottom_row(frame: &mut Frame, model: &TuiModel, area: Rect) {
    let halves = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(area);
    render_scoped(frame, model, halves[0]);
    frame.render_widget(history_panel(model), halves[1]);
}

fn render_scoped(frame: &mut Frame, model: &TuiModel, area: Rect) {
    let unavailable_reason = model
        .window
        .as_ref()
        .and_then(|window| window.current.cgroup_unavailable_reason);
    if let Some(reason) = unavailable_reason {
        frame.render_widget(
            Paragraph::new(format!("scoped cgroup assessment unavailable ({reason})"))
                .block(Block::bordered().title("Scoped cgroup pressure")),
            area,
        );
        return;
    }
    let pressured = model
        .window
        .as_ref()
        .map(|window| {
            window
                .current
                .cgroups
                .iter()
                .filter(|(_, signal)| signal.status == ObservationStatus::Pressure)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if pressured.is_empty() {
        frame.render_widget(
            Paragraph::new("no scoped pressure ranked this window")
                .block(Block::bordered().title("Scoped cgroup pressure")),
            area,
        );
        return;
    }
    let mut rows = Vec::new();
    for (id, signal) in pressured {
        rows.push(Row::new(vec![
            Span::raw(watch::id_label(id)),
            Span::raw(signal.kind.to_owned()),
            Span::styled(
                watch::severity_name(signal.severity),
                model.styled(severity_color(signal.severity), true),
            ),
            Span::raw(match signal.psi_some_fraction {
                Some(fraction) => format!("{:.2}%", fraction * 100.0),
                None => "—".to_owned(),
            }),
        ]));
    }
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Min(20),
                Constraint::Min(20),
                Constraint::Length(9),
                Constraint::Length(7),
            ],
        )
        .block(Block::bordered().title("Scoped cgroup pressure"))
        .column_spacing(1),
        area,
    );
}

fn history_panel(model: &TuiModel) -> Sparkline<'static> {
    let data: Vec<u64> = model
        .window
        .as_ref()
        .map(|window| {
            window
                .history
                .iter()
                .map(|entry| {
                    entry
                        .events
                        .iter()
                        .map(|event| u64::from(watch::severity_rank(event.severity)))
                        .max()
                        .unwrap_or(0)
                })
                .collect()
        })
        .unwrap_or_default();
    let windows = match data.len() {
        1 => "1 window".to_owned(),
        count => format!("{count} windows"),
    };
    let title = format!("History (max severity, last {windows})");
    Sparkline::default()
        .data(data)
        .style(model.styled(Color::Cyan, false))
        .block(Block::bordered().title(title))
}

fn details_panel(model: &TuiModel) -> Paragraph<'static> {
    let mut lines = Vec::new();
    if let Some(window) = &model.window {
        if window.lifecycle.is_empty() {
            lines.push(Line::from("No pressure findings this window."));
        }
        for finding in &window.lifecycle {
            lines.push(Line::from(format!(
                "[{}] {} · {} · severity {} · PSI {}",
                watch::state_label(finding.state),
                watch::id_label(&finding.id),
                finding.kind,
                watch::severity_name(finding.severity),
                match finding.psi_some_fraction {
                    Some(fraction) => format!("{:.2}%", fraction * 100.0),
                    None => "unavailable".to_owned(),
                },
            )));
            lines.push(Line::from(format!("    {}", finding.summary)));
        }
        lines.push(Line::from(""));
        lines.push(Line::from("Current window signals:"));
        for (label, signal) in [
            ("CPU", &window.current.cpu),
            ("Memory", &window.current.memory),
            ("I/O", &window.current.io),
        ] {
            lines.push(Line::from(format!(
                "  {label}: {} — {}",
                watch::status_label(signal.status),
                signal.summary
            )));
        }
        if window.current.cgroup_tracking_capped {
            lines.push(Line::from(
                "Cgroup tracking is capped; additional scoped pressure was not added to lifecycle.",
            ));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(
            "Lifecycle tracks pressure findings only. Healthy windows resolve a previous finding; missing data does not.",
        ));
    } else {
        lines.push(Line::from("Waiting for the first window."));
    }
    Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("Details (press e to return)"))
}

fn footer_line(model: &TuiModel) -> Paragraph<'static> {
    let mut text = "q quit · e details · ? help · Ctrl-C: 1st drains, 2nd exits now".to_owned();
    if model
        .window
        .as_ref()
        .is_some_and(|window| window.current.cgroup_tracking_capped)
    {
        text.push_str(" · cgroup tracking capped");
    }
    Paragraph::new(Line::from(Span::styled(
        text,
        Style::default().add_modifier(Modifier::DIM),
    )))
}

const HELP_TEXT: &str = "\
Keys
  q            quit now
  Ctrl-C       first: drain the in-flight window and exit; second: exit now (130)
  e            toggle the details pane (full per-finding summaries)
  ? or h       toggle this help; Esc closes it

Reading the screen
  Pressure gauges: exact-window PSI some per host resource. The bar and color
  track the pressure fraction; severity words are always shown too.
  Finding lifecycle: pressure findings classified as NEW, PERSISTENT, or
  RESOLVED across contiguous rolling windows. Unconfirmed rows lack a current
  observation (missing data never resolves a finding).
  Scoped cgroup pressure: per-cgroup PSI verdicts for the current window.
  History: maximum finding severity per window over the retained windows.

Meaning limits
  PSI verdicts are host-wide; scoped verdicts apply to that cgroup only.
  Watch does not attribute victims, map processes to devices, or prove
  causality. Run hunt (with --explain or --json) for evidence.";

fn render_help(frame: &mut Frame, area: Rect) {
    let width = 76.min(area.width.saturating_sub(4));
    let height = 24.min(area.height.saturating_sub(2));
    if width < 20 || height < 8 {
        return;
    }
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(HELP_TEXT)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title("stallhunt watch help")),
        popup,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::Confidence;
    use crate::watch::{FindingId, HistoryEntry, TrackedFinding, WindowSignals};
    use ratatui::backend::TestBackend;
    use std::collections::BTreeSet;

    fn signal(
        status: ObservationStatus,
        severity: Severity,
        kind: &'static str,
        psi: Option<f64>,
    ) -> ResourceSignal {
        ResourceSignal {
            status,
            severity,
            confidence: Confidence::High,
            kind,
            summary: format!("{kind} summary"),
            psi_some_fraction: psi,
        }
    }

    fn window_fixture() -> WatchWindow {
        WatchWindow {
            index: 3,
            count: Some(5),
            interval_ms: 2_000,
            lifecycle: vec![TrackedFinding {
                id: FindingId::Cpu,
                state: LifecycleState::Persistent,
                consecutive_windows: 3,
                confirmed: true,
                severity: Severity::High,
                previous_severity: Some(Severity::Moderate),
                confidence: Confidence::High,
                kind: "cpu_scheduling_contention",
                summary: "CPU scheduling contention observed.".to_owned(),
                psi_some_fraction: Some(0.2),
            }],
            current: WindowSignals {
                cpu: signal(
                    ObservationStatus::Pressure,
                    Severity::High,
                    "cpu_scheduling_contention",
                    Some(0.2),
                ),
                memory: signal(
                    ObservationStatus::Healthy,
                    Severity::None,
                    "memory_no_harmful_pressure",
                    Some(0.001),
                ),
                io: signal(
                    ObservationStatus::Healthy,
                    Severity::None,
                    "io_no_meaningful_contention",
                    Some(0.001),
                ),
                cgroups: vec![(
                    FindingId::Cgroup {
                        path: "/system.slice/app.service".into(),
                        resource: crate::analysis::CgroupResourceKind::Memory,
                    },
                    signal(
                        ObservationStatus::Pressure,
                        Severity::Moderate,
                        "cgroup_memory_reclaim_pressure",
                        Some(0.08),
                    ),
                )],
                observed_cgroup_paths: BTreeSet::new(),
                ranking_omitted_cgroup_ids: BTreeSet::new(),
                cgroup_tracking_capped: false,
                cgroup_unavailable_reason: None,
            },
            history: vec![HistoryEntry {
                window_index: 3,
                events: vec![],
            }],
        }
    }

    fn render(width: u16, height: u16, model: &TuiModel) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| draw(frame, model)).expect("draw");
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area().height {
            for x in 0..buffer.area().width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    fn model_with_window() -> TuiModel {
        TuiModel {
            window: Some(window_fixture()),
            ..TuiModel::new(2_000)
        }
    }

    #[test]
    fn tui_renders_gauges_lifecycle_scoped_history_and_footer() {
        let text = render(132, 32, &model_with_window());
        assert!(text.contains("stallhunt"), "{text}");
        assert!(text.contains("watch"), "{text}");
        assert!(text.contains("window 3/5"), "{text}");
        assert!(text.contains("interval 2s"), "{text}");
        assert!(text.contains("Pressure (exact-window PSI some)"), "{text}");
        assert!(text.contains("20.00% pressure high"), "{text}");
        assert!(text.contains("0.10% healthy none"), "{text}");
        assert!(text.contains("Finding lifecycle"), "{text}");
        assert!(text.contains("PERSISTENT"), "{text}");
        assert!(text.contains("cpu_scheduling_contention"), "{text}");
        assert!(text.contains("(was moderate)"), "{text}");
        assert!(text.contains("Scoped cgroup pressure"), "{text}");
        assert!(text.contains("/system.slice/app.service"), "{text}");
        assert!(text.contains("cgroup_memory_reclaim"), "{text}");
        assert!(
            text.contains("History (max severity, last 1 window)"),
            "{text}"
        );
        assert!(text.contains("q quit"), "{text}");
        assert!(!text.contains("wall"), "{text}");
    }

    #[test]
    fn tui_scoped_panel_marks_unavailable_collection_not_absence_of_pressure() {
        let mut window = window_fixture();
        window.current.cgroups.clear();
        window.current.cgroup_unavailable_reason =
            Some(crate::cgroup::cgroup_capability_explanation(
                crate::cgroup::CgroupCapability::Unsupported,
            ));
        let model = TuiModel {
            window: Some(window),
            ..TuiModel::new(2_000)
        };
        let text = render(132, 32, &model);
        assert!(
            text.contains("scoped cgroup assessment unavailable"),
            "{text}"
        );
        assert!(
            !text.contains("no scoped pressure ranked this window"),
            "{text}"
        );
    }

    #[test]
    fn tui_help_overlay_explains_keys_and_meaning_limits() {
        let mut model = model_with_window();
        model.show_help = true;
        let text = render(132, 32, &model);
        assert!(text.contains("stallhunt watch help"), "{text}");
        assert!(text.contains("q            quit now"), "{text}");
        assert!(text.contains("Meaning limits"), "{text}");
        assert!(text.contains("does not attribute victims"), "{text}");
    }

    #[test]
    fn tui_details_pane_shows_full_summaries() {
        let mut model = model_with_window();
        model.show_details = true;
        let text = render(132, 32, &model);
        assert!(text.contains("Details (press e to return)"), "{text}");
        assert!(
            text.contains("CPU scheduling contention observed."),
            "{text}"
        );
        assert!(
            text.contains("Healthy windows resolve a previous finding"),
            "{text}"
        );
    }

    #[test]
    fn tui_degrades_when_the_terminal_is_too_small() {
        let text = render(30, 6, &model_with_window());
        assert!(text.contains("Terminal too small"), "{text}");
        assert!(text.contains("--no-tui"), "{text}");
    }

    #[test]
    fn tui_first_window_state_and_healthy_lifecycle_are_explicit() {
        let empty = TuiModel::new(2_000);
        let text = render(132, 32, &empty);
        assert!(text.contains("collecting first window"), "{text}");
        assert!(text.contains("waiting for first window"), "{text}");

        let mut model = model_with_window();
        let mut window = window_fixture();
        window.lifecycle.clear();
        window.current.cgroups.clear();
        model.window = Some(window);
        let text = render(132, 32, &model);
        assert!(text.contains("no pressure findings this window"), "{text}");
        assert!(
            text.contains("no scoped pressure ranked this window"),
            "{text}"
        );
    }
}
