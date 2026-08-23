//! Findings-first watch TUI. Not a process or utilization monitor.
//!
//! The tracker and collectors are unchanged. This module only presents
//! `WatchWindow` plus the current window's observation for a detail pane.

use std::io::{self, Stdout, stdout};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Row, Table};
use ratatui::{Frame, Terminal};

use crate::analysis::{
    self, AssessmentKind, CgroupAssessmentKind, Confidence, IoAssessmentKind, MemoryAssessmentKind,
    Severity,
};
use crate::cli::WatchOptions;
use crate::observe::{
    HuntObservation, observation_from_endpoints, read_end_endpoint, read_start_endpoint,
};
use crate::style::{
    human_duration, psi_percent, ratatui_severity_color, severity_abbrev, terminal_name,
};
use crate::watch::{FindingId, LifecycleState, ObservationStatus, WatchTracker, WatchWindow};

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen);
}

struct App {
    options: WatchOptions,
    tracker: WatchTracker,
    window: Option<WatchWindow>,
    observation: Option<HuntObservation>,
    selected: usize,
    help: bool,
    expanded: bool,
    collecting: bool,
    drain: Arc<AtomicBool>,
}

impl App {
    fn selected_id(&self) -> Option<FindingId> {
        self.window.as_ref().and_then(|window| {
            window
                .lifecycle
                .get(self.selected)
                .map(|finding| finding.id.clone())
        })
    }

    fn clamp_selection(&mut self) {
        let len = self
            .window
            .as_ref()
            .map(|window| window.lifecycle.len())
            .unwrap_or(0);
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }
}

pub fn run(options: &WatchOptions) -> io::Result<()> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    let _guard = TerminalGuard;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    let drain = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&drain);
    let _ = ctrlc::set_handler(move || {
        if handler_flag.swap(true, Ordering::SeqCst) {
            restore_terminal();
            std::process::exit(130);
        }
    });

    let mut app = App {
        options: *options,
        tracker: WatchTracker::new(),
        window: None,
        observation: None,
        selected: 0,
        help: false,
        expanded: true,
        collecting: true,
        drain,
    };

    let requested = Duration::from_millis(options.interval_ms);
    if requested.is_zero() {
        return Ok(());
    }
    let mut start = read_start_endpoint();
    let mut completed = 0_u32;
    terminal.draw(|frame| draw(frame, &app))?;

    loop {
        if options.count == Some(completed)
            || app.drain.load(Ordering::SeqCst) && completed > 0 && !app.collecting
        {
            break;
        }
        app.collecting = true;
        terminal.draw(|frame| draw(frame, &app))?;
        let deadline = Instant::now() + requested;
        if !wait_for_window(&mut terminal, &mut app, deadline)? {
            break;
        }
        if app.drain.load(Ordering::SeqCst) && options.count.is_some() {
            restore_terminal();
            std::process::exit(130);
        }
        let end = read_end_endpoint();
        let observation = observation_from_endpoints(&start, &end, requested);
        start = end;
        completed = completed.saturating_add(1);
        let mut window = app.tracker.ingest(&observation);
        window.count = options.count;
        window.interval_ms = options.interval_ms;
        app.observation = Some(observation);
        app.window = Some(window);
        app.collecting = false;
        app.clamp_selection();
        terminal.draw(|frame| draw(frame, &app))?;
        if options.count == Some(completed) {
            break;
        }
        if app.drain.load(Ordering::SeqCst) {
            break;
        }
    }
    Ok(())
}

fn wait_for_window(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    deadline: Instant,
) -> io::Result<bool> {
    loop {
        if app.drain.load(Ordering::SeqCst) && app.window.is_some() {
            return Ok(true);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(true);
        }
        if event::poll(remaining.min(Duration::from_millis(250)))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        app.drain.store(true, Ordering::SeqCst);
                        return Ok(app.window.is_some());
                    }
                    KeyCode::Char('?') => {
                        app.help = !app.help;
                        terminal.draw(|frame| draw(frame, app))?;
                    }
                    KeyCode::Esc => {
                        app.help = false;
                        terminal.draw(|frame| draw(frame, app))?;
                    }
                    KeyCode::Enter | KeyCode::Char('l') => {
                        app.expanded = !app.expanded;
                        terminal.draw(|frame| draw(frame, app))?;
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        let len = app
                            .window
                            .as_ref()
                            .map(|window| window.lifecycle.len())
                            .unwrap_or(0);
                        if len > 0 {
                            app.selected = (app.selected + 1) % len;
                        }
                        terminal.draw(|frame| draw(frame, app))?;
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        let len = app
                            .window
                            .as_ref()
                            .map(|window| window.lifecycle.len())
                            .unwrap_or(0);
                        if len > 0 {
                            app.selected = app.selected.checked_sub(1).unwrap_or(len - 1);
                        }
                        terminal.draw(|frame| draw(frame, app))?;
                    }
                    _ => {}
                },
                Event::Resize(_, _) => {
                    terminal.draw(|frame| draw(frame, app))?;
                }
                _ => {}
            }
        }
    }
}

fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(if app.expanded { 8 } else { 3 }),
            Constraint::Length(1),
        ])
        .split(frame.area());
    draw_header(frame, chunks[0], app);
    draw_findings(frame, chunks[1], app);
    draw_detail(frame, chunks[2], app);
    draw_footer(frame, chunks[3]);
    if app.help {
        draw_help(frame, app);
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let interval = human_duration(app.options.interval_ms);
    let (window_label, health) = match &app.window {
        Some(window) => (
            match window.count {
                Some(count) => format!("{}/{}", window.index, count),
                None => window.index.to_string(),
            },
            header_health(window),
        ),
        None => ("—".into(), "COLLECTING"),
    };
    let bars = match &app.window {
        Some(window) => format!(
            "CPU {} {}  MEM {} {}  I/O {} {}",
            resource_bar(window.current.cpu.psi_some_fraction),
            resource_status(
                &window.current.cpu.status,
                window.current.cpu.severity,
                window.current.cpu.psi_some_fraction
            ),
            resource_bar(window.current.memory.psi_some_fraction),
            resource_status(
                &window.current.memory.status,
                window.current.memory.severity,
                window.current.memory.psi_some_fraction
            ),
            resource_bar(window.current.io.psi_some_fraction),
            resource_status(
                &window.current.io.status,
                window.current.io.severity,
                window.current.io.psi_some_fraction
            ),
        ),
        None => "waiting for first window".into(),
    };
    let title = format!("stallhunt watch  interval {interval}  window {window_label}  {health}");
    let paragraph = Paragraph::new(vec![Line::from(bars)])
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(paragraph, area);
}

fn header_health(window: &WatchWindow) -> &'static str {
    let pressured = [
        &window.current.cpu,
        &window.current.memory,
        &window.current.io,
    ]
    .into_iter()
    .any(|signal| signal.status == ObservationStatus::Pressure)
        || window
            .current
            .cgroups
            .iter()
            .any(|(_, signal)| signal.status == ObservationStatus::Pressure);
    if pressured { "DEGRADED" } else { "HEALTHY" }
}

fn resource_bar(psi: Option<f64>) -> String {
    crate::style::pressure_bar(psi.unwrap_or(0.0), true)
}

fn resource_status(status: &ObservationStatus, severity: Severity, psi: Option<f64>) -> String {
    let psi = psi.map(psi_percent).unwrap_or_else(|| "--".into());
    format!(
        "{} {} {}",
        match status {
            ObservationStatus::Pressure => "pressure",
            ObservationStatus::Healthy => "healthy",
            ObservationStatus::Unconfirmed => "unconfirmed",
        },
        severity_abbrev(severity),
        psi
    )
}

fn draw_findings(frame: &mut Frame, area: Rect, app: &App) {
    let Some(window) = &app.window else {
        frame.render_widget(
            Paragraph::new("collecting first window…")
                .block(Block::default().borders(Borders::ALL).title("FINDINGS")),
            area,
        );
        return;
    };
    let rows: Vec<Row> = if window.lifecycle.is_empty() {
        vec![Row::new(vec![
            "",
            "no pressure findings this window",
            "",
            "",
            "",
        ])]
    } else {
        window
            .lifecycle
            .iter()
            .enumerate()
            .map(|(index, finding)| {
                let marker = if index == app.selected { "▶" } else { " " };
                let mut style = Style::default();
                if let Some(color) = ratatui_severity_color(finding.severity) {
                    style = style.fg(color);
                }
                if index == app.selected {
                    style = style.add_modifier(Modifier::REVERSED);
                }
                Row::new(vec![
                    marker.to_string(),
                    state_label(finding.state).to_string(),
                    id_label(&finding.id),
                    finding.kind.to_string(),
                    format!(
                        "{} {}",
                        severity_abbrev(finding.severity),
                        finding
                            .psi_some_fraction
                            .map(psi_percent)
                            .unwrap_or_default()
                    ),
                ])
                .style(style)
            })
            .collect()
    };
    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Length(6),
            Constraint::Length(18),
            Constraint::Min(20),
            Constraint::Length(16),
        ],
    )
    .block(Block::default().borders(Borders::ALL).title("FINDINGS"));
    frame.render_widget(table, area);
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &App) {
    let text = match (
        app.selected_id(),
        app.observation.as_ref(),
        app.window.as_ref(),
    ) {
        (Some(id), Some(observation), _) => detail_text(observation, &id, app.help),
        (_, _, Some(window)) if window.lifecycle.is_empty() => {
            "No pressure findings. Healthy bars are not a bottleneck.".into()
        }
        _ => "Detail appears after the first window.".into(),
    };
    let title = match app.selected_id() {
        Some(id) => format!("DETAIL  {}", id_label(&id)),
        None => "DETAIL".into(),
    };
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(ratatui::widgets::Wrap { trim: true }),
        area,
    );
}

fn draw_footer(frame: &mut Frame, area: Rect) {
    frame.render_widget(
        Paragraph::new("q quit   ? explain   j/k select   Enter expand   Esc close   JSON: stallhunt watch --json"),
        area,
    );
}

fn draw_help(frame: &mut Frame, app: &App) {
    let area = centered_rect(80, 70, frame.area());
    let text = match (app.selected_id(), app.observation.as_ref()) {
        (Some(id), Some(observation)) => {
            let mut body = detail_text(observation, &id, true);
            body.push_str("\n\nKeys: q quit, j/k move, Enter toggle detail, Esc close this overlay.\nWatch tracks finding lifecycle, not a process table.");
            body
        }
        _ => "No finding selected.\n\nWatch displays pressure findings as they appear, persist, or resolve.".into(),
    };
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("Explain"))
            .wrap(ratatui::widgets::Wrap { trim: true }),
        area,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn state_label(state: LifecycleState) -> &'static str {
    match state {
        LifecycleState::New => "NEW",
        LifecycleState::Persistent => "PERS",
        LifecycleState::Resolved => "RES",
    }
}

fn id_label(id: &FindingId) -> String {
    match id {
        FindingId::Cpu => "CPU".into(),
        FindingId::Memory => "Memory".into(),
        FindingId::Io => "I/O".into(),
        FindingId::Cgroup { path, resource } => {
            let resource = match resource {
                crate::analysis::CgroupResourceKind::Cpu => "cpu",
                crate::analysis::CgroupResourceKind::Memory => "memory",
                crate::analysis::CgroupResourceKind::Io => "io",
            };
            format!("{path} ({resource})")
        }
    }
}

fn detail_text(observation: &HuntObservation, id: &FindingId, explain: bool) -> String {
    match id {
        FindingId::Cpu => cpu_detail(observation, explain),
        FindingId::Memory => memory_detail(observation, explain),
        FindingId::Io => io_detail(observation, explain),
        FindingId::Cgroup { path, resource } => {
            cgroup_detail(observation, path, *resource, explain)
        }
    }
}

fn cpu_detail(observation: &HuntObservation, explain: bool) -> String {
    let analysis =
        analysis::analyze_cpu(observation.psi.as_ref().ok(), observation.cpu.as_ref().ok());
    let Some(finding) = analysis.findings.first() else {
        return "CPU assessment unavailable.".into();
    };
    let mut lines = vec![
        finding.summary.clone(),
        format!(
            "impact  PSI some {}  conf {}",
            psi_percent(finding.evidence.psi_some_fraction),
            match finding.resource_confidence {
                Confidence::Low => "low",
                Confidence::Medium => "medium",
                Confidence::High => "high",
            }
        ),
    ];
    if finding.kind == AssessmentKind::CpuContention {
        if finding.victims.is_empty() {
            lines.push("victims  unavailable or none".into());
        } else {
            let listed = finding
                .victims
                .iter()
                .map(|victim| format!("{} [{}]", terminal_name(&victim.name), victim.key.pid))
                .collect::<Vec<_>>()
                .join(" · ");
            lines.push(format!("victims  {listed}"));
        }
        if finding.suspects.is_empty() {
            lines.push("suspects  unavailable or none".into());
        } else {
            let listed = finding
                .suspects
                .iter()
                .map(|suspect| {
                    format!(
                        "{} [{}] {:.1}%",
                        terminal_name(&suspect.name),
                        suspect.key.pid,
                        suspect.cpu_fraction_of_one * 100.0
                    )
                })
                .collect::<Vec<_>>()
                .join(" · ");
            lines.push(format!("suspects  {listed}  (same-window; not causal)"));
        }
    }
    if explain {
        lines.push(String::new());
        for qualifier in &finding.qualifiers {
            lines.push(qualifier.message.to_string());
        }
    }
    lines.join("\n")
}

fn memory_detail(observation: &HuntObservation, explain: bool) -> String {
    let Some(memory) = observation.memory.as_ref() else {
        return "Memory was not observed.".into();
    };
    let analysis = analysis::analyze_memory(memory.psi.as_ref().ok(), memory.context.as_ref().ok());
    let Some(finding) = analysis.findings.first() else {
        return "Memory assessment unavailable.".into();
    };
    let mut lines = vec![
        finding.summary.clone(),
        format!(
            "impact  PSI some {}  {}",
            psi_percent(finding.evidence.psi_some_fraction),
            match finding.kind {
                MemoryAssessmentKind::NoHarmfulPressure => "no harmful pressure",
                MemoryAssessmentKind::ReclaimPressure => "reclaim",
                MemoryAssessmentKind::SwapPressure => "swap",
                MemoryAssessmentKind::PossibleThrashing => "possible thrashing",
                MemoryAssessmentKind::Pressure => "pressure",
                MemoryAssessmentKind::InsufficientObservation => "insufficient",
            }
        ),
        "attrib  unavailable (host-wide evidence only)".into(),
    ];
    if explain {
        lines.push(String::new());
        for qualifier in &finding.qualifiers {
            lines.push(qualifier.message.to_string());
        }
    }
    lines.join("\n")
}

fn io_detail(observation: &HuntObservation, explain: bool) -> String {
    let Some(io) = observation.io.as_ref() else {
        return "I/O was not observed.".into();
    };
    let analysis = analysis::analyze_io(
        io.psi.as_ref().ok(),
        io.diskstats.as_ref().ok(),
        io.processes.as_ref().ok(),
    );
    let Some(finding) = analysis.findings.first() else {
        return "I/O assessment unavailable.".into();
    };
    let mut lines = vec![
        finding.summary.clone(),
        format!(
            "impact  PSI some {}",
            psi_percent(finding.evidence.psi_some_fraction)
        ),
    ];
    if finding.kind == IoAssessmentKind::Pressure {
        if finding.device_candidates.is_empty() {
            lines.push("disks  unavailable".into());
        } else {
            let listed = finding
                .device_candidates
                .iter()
                .map(|candidate| terminal_name(&candidate.name))
                .collect::<Vec<_>>()
                .join(" · ");
            lines.push(format!("disks  {listed}  (activity, not mapped)"));
        }
        lines.push("victims  unavailable".into());
    }
    if explain {
        lines.push(String::new());
        for qualifier in &finding.qualifiers {
            lines.push(qualifier.message.to_string());
        }
    }
    lines.join("\n")
}

fn cgroup_detail(
    observation: &HuntObservation,
    path: &str,
    resource: crate::analysis::CgroupResourceKind,
    explain: bool,
) -> String {
    let Some(cgroup) = observation
        .cgroup
        .as_ref()
        .and_then(|cgroup| cgroup.observation.as_ref().ok())
    else {
        return "Cgroup assessment unavailable.".into();
    };
    let analysis = analysis::analyze_cgroups(Some(cgroup));
    let Some(finding) = analysis
        .findings
        .iter()
        .find(|finding| finding.path == path && finding.resource == resource)
    else {
        return format!("{path} not ranked this window.");
    };
    let mut lines = vec![
        finding.summary.clone(),
        format!(
            "{}  conf {}",
            match finding.kind {
                CgroupAssessmentKind::Pressure => "pressure",
                CgroupAssessmentKind::NoMeaningfulPressure => "healthy",
                CgroupAssessmentKind::InsufficientObservation => "insufficient",
            },
            match finding.resource_confidence {
                Confidence::Low => "low",
                Confidence::Medium => "medium",
                Confidence::High => "high",
            }
        ),
        "scoped only; not a host-cause claim".into(),
    ];
    if explain {
        lines.push(String::new());
        for qualifier in &finding.qualifiers {
            lines.push(qualifier.message.to_string());
        }
    }
    lines.join("\n")
}

#[cfg(test)]
fn render_test_frame(window: &WatchWindow, selected: usize, help: bool) -> String {
    let backend = ratatui::backend::TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    let app = App {
        options: WatchOptions {
            interval_ms: 2_000,
            count: Some(3),
            output: crate::cli::OutputFormat::Text,
            plain: false,
            style: crate::cli::TextStyle::default(),
        },
        tracker: WatchTracker::new(),
        window: Some(window.clone()),
        observation: None,
        selected,
        help,
        expanded: true,
        collecting: false,
        drain: Arc::new(AtomicBool::new(false)),
    };
    terminal
        .draw(|frame| draw(frame, &app))
        .expect("draw test frame");
    format!("{:?}", terminal.backend().buffer())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watch::{ResourceSignal, WindowSignals};
    use std::collections::BTreeSet;

    fn pressure() -> ResourceSignal {
        ResourceSignal {
            status: ObservationStatus::Pressure,
            severity: Severity::High,
            confidence: Confidence::High,
            kind: "cpu_scheduling_contention",
            summary: "CPU scheduling contention".into(),
            psi_some_fraction: Some(0.2),
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

    #[test]
    fn tui_frame_shows_lifecycle_not_a_process_table() {
        let mut tracker = WatchTracker::new();
        let mut window = tracker.ingest_signals(WindowSignals {
            cpu: pressure(),
            memory: healthy("memory_no_harmful_pressure"),
            io: healthy("io_no_meaningful_contention"),
            cgroups: Vec::new(),
            observed_cgroup_paths: BTreeSet::new(),
            ranking_omitted_cgroup_ids: BTreeSet::new(),
            cgroup_tracking_capped: false,
        });
        window.interval_ms = 2_000;
        window.count = Some(3);
        let rendered = render_test_frame(&window, 0, false);
        assert!(rendered.contains("FINDINGS"));
        assert!(rendered.contains("NEW") || rendered.contains("cpu_scheduling_contention"));
        assert!(!rendered.contains("Top process CPU consumers"));
        assert!(rendered.contains("q quit"));
        let help = render_test_frame(&window, 0, true);
        assert!(help.contains("Explain") || help.contains("lifecycle"));
    }
}
