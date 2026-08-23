//! Interactive diagnosis-first renderer for `watch`.

use std::io::{self, Stdout};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Sparkline, Wrap};

use crate::analysis::{Confidence, Severity};
use crate::cli::WatchOptions;
use crate::observe::{observation_from_endpoints, read_end_endpoint, read_start_endpoint};
use crate::presentation::{
    DiagnosisView, FindingView, OverallStatus, ResourceState, confidence_name, severity_name,
};
use crate::watch::{InterruptFlag, LifecycleState, WatchExit, WatchTracker, WatchWindow};

const TREND_WINDOWS: usize = 16;
const POLL_SLICE: Duration = Duration::from_millis(50);

pub(crate) enum TuiError {
    Init(io::Error),
    Runtime(io::Error),
}

impl TuiError {
    pub(crate) const fn is_init(&self) -> bool {
        matches!(self, Self::Init(_))
    }

    pub(crate) fn into_inner(self) -> io::Error {
        match self {
            Self::Init(error) | Self::Runtime(error) => error,
        }
    }
}

impl std::fmt::Display for TuiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init(error) => write!(formatter, "terminal initialization failed: {error}"),
            Self::Runtime(error) => write!(formatter, "terminal event loop failed: {error}"),
        }
    }
}

pub fn run(options: &WatchOptions) -> Result<WatchExit, TuiError> {
    let terminal = TerminalSession::new().map_err(TuiError::Init)?;
    run_active(terminal, options).map_err(TuiError::Runtime)
}

fn run_active(mut terminal: TerminalSession, options: &WatchOptions) -> io::Result<WatchExit> {
    let interrupt = InterruptFlag::install(true);
    let requested = Duration::from_millis(options.interval_ms);
    let mut start = read_start_endpoint();
    let mut deadline = Instant::now() + requested;
    let mut tracker = WatchTracker::new();
    let mut state = UiState::new(crate::cli::colors_enabled());
    terminal.draw(&state, options)?;

    loop {
        if bounded_interrupted(options, &interrupt) || interrupt.aborting() {
            return Ok(WatchExit::Interrupted);
        }
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(POLL_SLICE);
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => match state.handle_key(key, options, &interrupt) {
                    UiAction::Continue => terminal.draw(&state, options)?,
                    UiAction::Quit => return Ok(WatchExit::Completed),
                    UiAction::Interrupted => return Ok(WatchExit::Interrupted),
                },
                Event::Resize(_, _) => terminal.draw(&state, options)?,
                _ => {}
            }
        }
        if Instant::now() < deadline {
            if interrupt.draining() {
                state.draining = true;
                terminal.draw(&state, options)?;
            }
            continue;
        }

        let end = read_end_endpoint();
        let observation = observation_from_endpoints(&start, &end, requested);
        start = end;
        let mut window = tracker.ingest(&observation);
        window.count = options.count;
        window.interval_ms = options.interval_ms;
        if let Some(diagnosis) = window.diagnosis.as_mut() {
            diagnosis.requested_duration_ms = options.interval_ms;
        }
        state.update(window);
        terminal.draw(&state, options)?;

        if options.count == Some(state.completed_windows()) || interrupt.draining() {
            return Ok(WatchExit::Completed);
        }
        deadline += requested;
        if deadline <= Instant::now() {
            deadline = Instant::now() + requested;
        }
    }
}

fn bounded_interrupted(options: &WatchOptions, interrupt: &InterruptFlag) -> bool {
    options.count.is_some() && interrupt.draining()
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalSession {
    fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(error);
        }
        let backend = CrosstermBackend::new(stdout);
        match Terminal::new(backend) {
            Ok(mut terminal) => {
                terminal.hide_cursor()?;
                terminal.clear()?;
                Ok(Self { terminal })
            }
            Err(error) => {
                let mut stdout = io::stdout();
                let _ = execute!(stdout, LeaveAlternateScreen);
                let _ = disable_raw_mode();
                Err(error)
            }
        }
    }

    fn draw(&mut self, state: &UiState, options: &WatchOptions) -> io::Result<()> {
        self.terminal.draw(|frame| render(frame, state, options))?;
        Ok(())
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = self.terminal.show_cursor();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Overlay {
    Help,
    Details,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiAction {
    Continue,
    Quit,
    Interrupted,
}

#[derive(Default)]
struct Trends {
    cpu: Vec<u64>,
    memory: Vec<u64>,
    io: Vec<u64>,
}

struct UiState {
    window: Option<WatchWindow>,
    selected: usize,
    overlay: Option<Overlay>,
    detail_scroll: u16,
    trends: Trends,
    color: bool,
    draining: bool,
}

impl UiState {
    fn new(color: bool) -> Self {
        Self {
            window: None,
            selected: 0,
            overlay: None,
            detail_scroll: 0,
            trends: Trends::default(),
            color,
            draining: false,
        }
    }

    fn update(&mut self, window: WatchWindow) {
        push_trend(&mut self.trends.cpu, window.current.cpu.psi_some_fraction);
        push_trend(
            &mut self.trends.memory,
            window.current.memory.psi_some_fraction,
        );
        push_trend(&mut self.trends.io, window.current.io.psi_some_fraction);
        self.window = Some(window);
        let count = self.diagnosis().map_or(0, |value| value.findings.len());
        self.selected = self.selected.min(count.saturating_sub(1));
        self.detail_scroll = 0;
    }

    fn completed_windows(&self) -> u32 {
        self.window.as_ref().map_or(0, |window| window.index)
    }

    fn diagnosis(&self) -> Option<&DiagnosisView> {
        self.window.as_ref()?.diagnosis.as_ref()
    }

    fn selected_finding(&self) -> Option<&FindingView> {
        self.diagnosis()?.findings.get(self.selected)
    }

    fn handle_key(
        &mut self,
        key: KeyEvent,
        options: &WatchOptions,
        interrupt: &InterruptFlag,
    ) -> UiAction {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            if options.count.is_some() {
                return UiAction::Interrupted;
            }
            interrupt.request_drain();
            self.draining = true;
            return if interrupt.aborting() {
                UiAction::Interrupted
            } else {
                UiAction::Continue
            };
        }
        match key.code {
            KeyCode::Char('q') => UiAction::Quit,
            KeyCode::Char('?') => {
                self.overlay = Some(Overlay::Help);
                self.detail_scroll = 0;
                UiAction::Continue
            }
            KeyCode::Enter | KeyCode::Char('d') if self.selected_finding().is_some() => {
                self.overlay = Some(Overlay::Details);
                self.detail_scroll = 0;
                UiAction::Continue
            }
            KeyCode::Esc => {
                self.overlay = None;
                self.detail_scroll = 0;
                UiAction::Continue
            }
            KeyCode::Down | KeyCode::Char('j') if self.overlay.is_none() => {
                let count = self.diagnosis().map_or(0, |value| value.findings.len());
                self.selected = (self.selected + 1).min(count.saturating_sub(1));
                UiAction::Continue
            }
            KeyCode::Up | KeyCode::Char('k') if self.overlay.is_none() => {
                self.selected = self.selected.saturating_sub(1);
                UiAction::Continue
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::PageDown if self.overlay.is_some() => {
                self.detail_scroll = self
                    .detail_scroll
                    .saturating_add(if key.code == KeyCode::PageDown { 8 } else { 1 });
                UiAction::Continue
            }
            KeyCode::Up | KeyCode::Char('k') | KeyCode::PageUp if self.overlay.is_some() => {
                self.detail_scroll = self
                    .detail_scroll
                    .saturating_sub(if key.code == KeyCode::PageUp { 8 } else { 1 });
                UiAction::Continue
            }
            _ => UiAction::Continue,
        }
    }
}

fn push_trend(values: &mut Vec<u64>, fraction: Option<f64>) {
    values.push(fraction.map_or(0, |value| (value * 10_000.0).round() as u64));
    if values.len() > TREND_WINDOWS {
        values.remove(0);
    }
}

fn render(frame: &mut ratatui::Frame<'_>, state: &UiState, options: &WatchOptions) {
    let area = frame.area();
    if area.width < 70 || area.height < 18 {
        let message = Paragraph::new(vec![
            Line::from(Span::styled(
                "STALLHUNT",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from("Terminal too small for the diagnosis view."),
            Line::from(format!(
                "Current: {}×{} · minimum: 70×18",
                area.width, area.height
            )),
            Line::from("Sampling continues · q quit · ? help"),
        ])
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Resize terminal "),
        );
        frame.render_widget(message, area);
        if let Some(overlay) = state.overlay {
            render_overlay(frame, centered_rect(90, 90, area), state, overlay);
        }
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(7),
            Constraint::Min(6),
            Constraint::Length(1),
        ])
        .split(area);
    render_header(frame, rows[0], state, options);
    render_resources(frame, rows[1], state);
    render_body(
        frame,
        rows[2],
        area.width >= 100 && area.height >= 28,
        state,
    );
    render_footer(frame, rows[3], state);
    if let Some(overlay) = state.overlay {
        render_overlay(frame, centered_rect(80, 80, area), state, overlay);
    }
}

fn render_header(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &UiState,
    options: &WatchOptions,
) {
    let (status, window) = state.diagnosis().map_or(("SAMPLING", 0), |diagnosis| {
        (diagnosis.status.label(), state.completed_windows())
    });
    let status_style = state.diagnosis().map_or_else(Style::default, |diagnosis| {
        overall_style(diagnosis.status, state.color)
    });
    let stop = if state.draining {
        " · DRAINING FINAL WINDOW"
    } else {
        ""
    };
    let title = Line::from(vec![
        Span::styled(" STALLHUNT ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(status, status_style.add_modifier(Modifier::BOLD)),
        Span::raw(format!(
            " · window {window} · interval {}{} ",
            format_ms(options.interval_ms),
            stop
        )),
    ]);
    frame.render_widget(
        Paragraph::new(title).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn render_resources(frame: &mut ratatui::Frame<'_>, area: Rect, state: &UiState) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3); 3])
        .split(area);
    let empty = crate::presentation::ResourceView {
        name: "",
        state: ResourceState::Unavailable,
        severity: Severity::None,
        confidence: Confidence::Low,
        psi_some_fraction: None,
    };
    for (index, column) in columns.iter().enumerate() {
        let resource = state
            .diagnosis()
            .and_then(|diagnosis| diagnosis.resources.get(index))
            .unwrap_or(&empty);
        let trend = match index {
            0 => &state.trends.cpu,
            1 => &state.trends.memory,
            _ => &state.trends.io,
        };
        let title = if resource.name.is_empty() {
            ["CPU", "Memory", "I/O"][index]
        } else {
            resource.name
        };
        let label = format!(
            "{} · {} · confidence {} · {}",
            resource.state.label(),
            severity_name(resource.severity),
            confidence_name(resource.confidence),
            resource.psi_some_fraction.map_or_else(
                || "PSI —".into(),
                |value| format!("PSI {:.2}%", value * 100.0)
            )
        );
        let spark = Sparkline::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {title} ")),
            )
            .data(trend)
            .max(10_000)
            .style(resource_style(
                resource.state,
                resource.severity,
                state.color,
            ));
        frame.render_widget(spark, *column);
        let label_area = Rect {
            x: column.x.saturating_add(2),
            y: column.y.saturating_add(1),
            width: column.width.saturating_sub(4),
            height: 1,
        };
        frame.render_widget(Paragraph::new(label), label_area);
    }
}

fn render_body(frame: &mut ratatui::Frame<'_>, area: Rect, wide: bool, state: &UiState) {
    let chunks = Layout::default()
        .direction(if wide {
            Direction::Horizontal
        } else {
            Direction::Vertical
        })
        .constraints(if wide {
            vec![Constraint::Percentage(42), Constraint::Percentage(58)]
        } else {
            vec![Constraint::Percentage(48), Constraint::Percentage(52)]
        })
        .split(area);
    let findings = state
        .diagnosis()
        .map(|diagnosis| diagnosis.findings.as_slice())
        .unwrap_or(&[]);
    let items = if findings.is_empty() {
        vec![ListItem::new("No active pressure findings")]
    } else {
        findings
            .iter()
            .enumerate()
            .map(|(index, finding)| {
                let marker = if index == state.selected { "›" } else { " " };
                let lifecycle = lifecycle_for(state.window.as_ref(), finding);
                ListItem::new(format!(
                    "{marker} [{}] {} · {} · {}",
                    lifecycle,
                    finding.title,
                    severity_name(finding.severity),
                    finding.scope
                ))
                .style(if index == state.selected {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                })
            })
            .collect()
    };
    frame.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title(" Findings ")),
        chunks[0],
    );
    frame.render_widget(selected_summary(state), chunks[1]);
}

fn selected_summary(state: &UiState) -> Paragraph<'static> {
    let Some(finding) = state.selected_finding() else {
        return Paragraph::new(
            "No active finding selected. Resource cards still show the current pressure verdicts.",
        )
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title(" Diagnosis "));
    };
    let mut lines = vec![
        Line::from(Span::styled(
            finding.title.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "{} · severity {} · confidence {}",
            finding.scope,
            severity_name(finding.severity),
            confidence_name(finding.confidence)
        )),
    ];
    if let Some(evidence) = finding.evidence.first() {
        lines.push(Line::from(format!("Evidence: {evidence}")));
    }
    for candidate in finding.affected.iter().take(2) {
        lines.push(Line::from(format!(
            "Affected: {} · {}",
            candidate.name, candidate.metric
        )));
    }
    for candidate in finding.contributors.iter().take(2) {
        lines.push(Line::from(format!(
            "Candidate: {} · {}",
            candidate.name, candidate.metric
        )));
    }
    if !finding.qualifiers.is_empty() {
        lines.push(Line::from(format!(
            "{} limitation(s) · Enter/d for full explanation",
            finding.qualifiers.len()
        )));
    }
    if let Some(diagnosis) = state.diagnosis() {
        for chain in diagnosis.chains.iter().take(2) {
            lines.push(Line::from(format!(
                "Related: {} · confidence {}",
                chain.summary,
                confidence_name(chain.confidence)
            )));
        }
    }
    Paragraph::new(lines).wrap(Wrap { trim: true }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Selected diagnosis "),
    )
}

fn render_footer(frame: &mut ratatui::Frame<'_>, area: Rect, state: &UiState) {
    let text = if state.draining {
        "Finishing active window · Ctrl-C again aborts"
    } else {
        "↑↓/jk select · Enter/d details · ? help · q quit · Ctrl-C drain"
    };
    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), area);
}

fn render_overlay(frame: &mut ratatui::Frame<'_>, area: Rect, state: &UiState, overlay: Overlay) {
    frame.render_widget(Clear, area);
    let (title, lines) = match overlay {
        Overlay::Help => (
            " Help ",
            vec![
                Line::from("↑/↓ or j/k    select a finding or scroll an overlay"),
                Line::from("Enter or d    open the selected finding's full evidence"),
                Line::from("PageUp/Down   scroll full evidence"),
                Line::from("Esc           close this overlay"),
                Line::from("q             exit immediately with status 0"),
                Line::from("Ctrl-C        finish the active window; press again to abort"),
                Line::from(""),
                Line::from("Severity describes harm. Confidence describes evidence strength."),
                Line::from("Candidates are same-window evidence and are not causal proof."),
            ],
        ),
        Overlay::Details => (
            " Full evidence ",
            detail_lines(state.selected_finding(), state.diagnosis()),
        ),
    };
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((state.detail_scroll, 0))
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn detail_lines(
    finding: Option<&FindingView>,
    diagnosis: Option<&DiagnosisView>,
) -> Vec<Line<'static>> {
    let Some(finding) = finding else {
        return vec![Line::from("No active finding selected.")];
    };
    let mut lines = vec![
        Line::from(Span::styled(
            finding.title.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "Resource: {} · scope: {}",
            finding.resource, finding.scope
        )),
        Line::from(format!(
            "Severity: {} · confidence: {}",
            severity_name(finding.severity),
            confidence_name(finding.confidence)
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Evidence",
            Style::default().add_modifier(Modifier::BOLD),
        )),
    ];
    lines.extend(finding.evidence.iter().cloned().map(Line::from));
    if !finding.affected.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Affected candidates",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.extend(finding.affected.iter().map(|candidate| {
            Line::from(format!(
                "{} · {} · confidence {}",
                candidate.name,
                candidate.metric,
                confidence_name(candidate.confidence)
            ))
        }));
    }
    if !finding.contributors.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Contributor/activity candidates",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.extend(finding.contributors.iter().map(|candidate| {
            Line::from(format!(
                "{} · {} · confidence {}",
                candidate.name,
                candidate.metric,
                confidence_name(candidate.confidence)
            ))
        }));
    }
    if !finding.qualifiers.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Limitations",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.extend(finding.qualifiers.iter().cloned().map(Line::from));
    }
    if let Some(diagnosis) = diagnosis {
        if !diagnosis.chains.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Related evidence",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.extend(diagnosis.chains.iter().map(|chain| {
                Line::from(format!(
                    "{} · confidence {} · consistent with, not causal proof",
                    chain.summary,
                    confidence_name(chain.confidence)
                ))
            }));
        }
    }
    lines
}

fn lifecycle_for(window: Option<&WatchWindow>, finding: &FindingView) -> &'static str {
    let Some(window) = window else {
        return "CURRENT";
    };
    let lifecycle = window.lifecycle.iter().find(|item| match &item.id {
        crate::watch::FindingId::Cpu => finding.id == "host:cpu",
        crate::watch::FindingId::Memory => finding.id == "host:memory",
        crate::watch::FindingId::Io => finding.id == "host:io",
        crate::watch::FindingId::Cgroup { path, resource } => {
            finding.scope == *path
                && finding.resource
                    == match resource {
                        crate::analysis::CgroupResourceKind::Cpu => "CPU",
                        crate::analysis::CgroupResourceKind::Memory => "Memory",
                        crate::analysis::CgroupResourceKind::Io => "I/O",
                    }
        }
    });
    match lifecycle.map(|value| value.state) {
        Some(LifecycleState::New) => "NEW",
        Some(LifecycleState::Persistent) => "PERSISTENT",
        Some(LifecycleState::Resolved) => "RESOLVED",
        None => "CURRENT",
    }
}

fn overall_style(status: OverallStatus, color: bool) -> Style {
    if !color {
        return Style::default();
    }
    Style::default().fg(match status {
        OverallStatus::Healthy => Color::Green,
        OverallStatus::Degraded => Color::Red,
        OverallStatus::Incomplete => Color::Yellow,
    })
}

fn resource_style(state: ResourceState, severity: Severity, color: bool) -> Style {
    if !color {
        return Style::default();
    }
    let color = match state {
        ResourceState::Healthy => Color::Green,
        ResourceState::Inconclusive | ResourceState::Unavailable => Color::Yellow,
        ResourceState::Pressure => match severity {
            Severity::None => Color::Green,
            Severity::Low => Color::Cyan,
            Severity::Moderate => Color::Yellow,
            Severity::High => Color::LightRed,
            Severity::Severe => Color::Red,
        },
    };
    Style::default().fg(color)
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

fn format_ms(duration_ms: u64) -> String {
    if duration_ms >= 60_000 && duration_ms % 60_000 == 0 {
        format!("{}m", duration_ms / 60_000)
    } else if duration_ms % 1_000 == 0 {
        format!("{}s", duration_ms / 1_000)
    } else {
        format!("{duration_ms}ms")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ratatui::backend::TestBackend;

    use super::*;
    use crate::presentation::{CandidateView, ResourceView};
    use crate::watch::{ObservationStatus, ResourceSignal, WindowSignals};

    fn resource(
        name: &'static str,
        state: ResourceState,
        severity: Severity,
        psi: f64,
    ) -> ResourceView {
        ResourceView {
            name,
            state,
            severity,
            confidence: Confidence::High,
            psi_some_fraction: Some(psi),
        }
    }

    fn signal(status: ObservationStatus, severity: Severity, psi: f64) -> ResourceSignal {
        ResourceSignal {
            status,
            severity,
            confidence: Confidence::High,
            kind: "test",
            summary: "test".into(),
            psi_some_fraction: Some(psi),
        }
    }

    fn sample_window() -> WatchWindow {
        WatchWindow {
            index: 3,
            count: None,
            interval_ms: 2_000,
            lifecycle: Vec::new(),
            current: WindowSignals {
                cpu: signal(ObservationStatus::Pressure, Severity::High, 0.2),
                memory: signal(ObservationStatus::Healthy, Severity::None, 0.001),
                io: signal(ObservationStatus::Healthy, Severity::None, 0.001),
                cgroups: Vec::new(),
                observed_cgroup_paths: BTreeSet::new(),
                ranking_omitted_cgroup_ids: BTreeSet::new(),
                cgroup_tracking_capped: false,
            },
            history: Vec::new(),
            diagnosis: Some(DiagnosisView {
                status: OverallStatus::Degraded,
                requested_duration_ms: 2_000,
                resources: vec![
                    resource("CPU", ResourceState::Pressure, Severity::High, 0.2),
                    resource("Memory", ResourceState::Healthy, Severity::None, 0.001),
                    resource("I/O", ResourceState::Healthy, Severity::None, 0.001),
                ],
                findings: vec![FindingView {
                    id: "host:cpu".into(),
                    resource: "CPU",
                    scope: "host".into(),
                    title: "CPU scheduling contention observed".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    psi_some_fraction: Some(0.2),
                    affected: vec![CandidateView {
                        name: "postgres [42]".into(),
                        metric: "500ms runnable delay".into(),
                        confidence: Confidence::High,
                    }],
                    contributors: vec![CandidateView {
                        name: "rustc [84]".into(),
                        metric: "180% of one CPU".into(),
                        confidence: Confidence::Medium,
                    }],
                    evidence: vec!["CPU PSI some 20.00%".into()],
                    qualifiers: vec!["Same-window CPU use is not causal proof.".into()],
                }],
                chains: Vec::new(),
                limitations: Vec::new(),
            }),
        }
    }

    fn rendered(width: u16, height: u16, state: &UiState) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| {
                render(
                    frame,
                    state,
                    &WatchOptions {
                        interval_ms: 2_000,
                        count: None,
                        output: crate::cli::OutputFormat::Text,
                    },
                );
            })
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..height {
            for x in 0..width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    #[test]
    fn full_and_small_layouts_keep_diagnosis_and_recovery_controls_visible() {
        let mut state = UiState::new(false);
        state.update(sample_window());
        let full = rendered(120, 32, &state);
        assert!(full.contains("STALLHUNT"));
        assert!(full.contains("DEGRADED"));
        assert!(full.contains("CPU scheduling contention"));
        assert!(full.contains("postgres [42]"));
        assert!(full.contains("q quit"));

        let small = rendered(60, 12, &state);
        assert!(small.contains("Terminal too small"));
        assert!(small.contains("Sampling continues"));
        assert!(small.contains("q quit"));
    }

    #[test]
    fn details_help_navigation_and_trends_are_bounded() {
        let mut state = UiState::new(false);
        state.update(sample_window());
        for _ in 0..32 {
            push_trend(&mut state.trends.cpu, Some(0.5));
        }
        assert_eq!(state.trends.cpu.len(), TREND_WINDOWS);

        let interrupt = InterruptFlag::install(false);
        assert_eq!(
            state.handle_key(
                KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                &WatchOptions {
                    interval_ms: 2_000,
                    count: None,
                    output: crate::cli::OutputFormat::Text,
                },
                &interrupt,
            ),
            UiAction::Continue
        );
        assert_eq!(state.overlay, Some(Overlay::Details));
        let details = rendered(100, 28, &state);
        assert!(details.contains("Full evidence"));
        assert!(details.contains("Same-window CPU use is not causal proof"));

        state.handle_key(
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &WatchOptions {
                interval_ms: 2_000,
                count: None,
                output: crate::cli::OutputFormat::Text,
            },
            &interrupt,
        );
        state.handle_key(
            KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
            &WatchOptions {
                interval_ms: 2_000,
                count: None,
                output: crate::cli::OutputFormat::Text,
            },
            &interrupt,
        );
        assert!(rendered(100, 28, &state).contains("Severity describes harm"));
        assert_eq!(
            state.handle_key(
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &WatchOptions {
                    interval_ms: 2_000,
                    count: None,
                    output: crate::cli::OutputFormat::Text,
                },
                &interrupt,
            ),
            UiAction::Quit,
            "q exits even while an overlay is open"
        );

        let interrupt = InterruptFlag::install(false);
        let unlimited = WatchOptions {
            interval_ms: 2_000,
            count: None,
            output: crate::cli::OutputFormat::Text,
        };
        assert_eq!(
            state.handle_key(
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                &unlimited,
                &interrupt,
            ),
            UiAction::Continue
        );
        assert!(interrupt.draining());
        assert_eq!(
            state.handle_key(
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                &unlimited,
                &interrupt,
            ),
            UiAction::Interrupted
        );
    }
}
