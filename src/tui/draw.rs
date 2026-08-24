//! Pure rendering of `App` state into a ratatui `Frame`.
//!
//! `draw` never reads the clock, the environment, or anything but the
//! `App` it is given, so it is directly testable against
//! `ratatui::backend::TestBackend` (see the tests below) without a real
//! terminal.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::analysis::{
    ProcessCandidate, ProcessCandidateAvailability, ProcessCandidateEvidence, ProcessRole,
    ProcessRoleCompleteness, ProcessRoleList, ProcessScopeKind,
};
use crate::style::{self, ColorMode};
use crate::watch::{self, LifecycleState, ObservationStatus, ResourceSignal, WatchWindow};

use super::app::App;

const HISTORY_GLYPHS: [char; 5] = ['·', '▂', '▄', '▆', '█'];

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    if area.width >= 120 && area.height >= 30 {
        draw_wide(frame, area, app);
    } else {
        draw_compact(frame, area, app);
    }
    if app.help {
        draw_help_overlay(frame, area);
    }
}

/// The layout-derived maximum used by the event loop before it handles a
/// scrolling key.  It intentionally shares the exact pane geometry and text
/// builder used by `draw_detail`, including Unicode display-cell wrapping.
pub(super) fn detail_scroll_max(app: &App, width: u16, height: u16) -> u16 {
    if !app.detail_visible(width, height) {
        return 0;
    }
    let area = Rect::new(0, 0, width, height);
    let detail = detail_area(area);
    let inner = Block::default().borders(Borders::ALL).inner(detail);
    let visible = usize::from(inner.height);
    let wrapped = Paragraph::new(detail_lines(app, inner.width))
        .wrap(Wrap { trim: false })
        .line_count(inner.width);
    u16::try_from(wrapped.saturating_sub(visible)).unwrap_or(u16::MAX)
}

fn detail_area(area: Rect) -> Rect {
    if area.width >= 120 && area.height >= 30 {
        let body = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);
        let columns = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(body[1]);
        Layout::vertical([
            Constraint::Percentage(30),
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Min(7),
        ])
        .split(columns[0])[3]
    } else {
        Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(9),
            Constraint::Length(0),
            Constraint::Length(0),
            Constraint::Length(10),
            Constraint::Length(1),
        ])
        .split(area)[5]
    }
}

fn draw_wide(frame: &mut Frame, area: Rect, app: &App) {
    let body = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(area);
    draw_header(frame, body[0], app);
    let columns =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).split(body[1]);
    let left = Layout::vertical([
        Constraint::Percentage(30),
        Constraint::Length(5),
        Constraint::Length(3),
        Constraint::Min(7),
    ])
    .split(columns[0]);
    draw_lifecycle(frame, left[0], app);
    draw_current(frame, left[1], app);
    draw_history(frame, left[2], app);
    draw_detail(
        frame,
        left[3],
        app,
        app.detail_visible(area.width, area.height),
    );
    draw_role_grid(frame, columns[1], app);
    draw_footer(frame, body[2]);
}

fn draw_compact(frame: &mut Frame, area: Rect, app: &App) {
    let detail = app.detail_visible(area.width, area.height);
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(9),
        Constraint::Length(if detail { 0 } else { 5 }),
        Constraint::Length(if detail { 0 } else { 3 }),
        Constraint::Length(if detail { 10 } else { 0 }),
        Constraint::Length(1),
    ])
    .split(area);
    draw_header(frame, chunks[0], app);
    draw_lifecycle(frame, chunks[1], app);
    draw_compact_roles(frame, chunks[2], app);
    if !detail {
        draw_current(frame, chunks[3], app);
        draw_history(frame, chunks[4], app);
    }
    if detail {
        draw_detail(frame, chunks[5], app, true);
    }
    draw_footer(frame, chunks[6]);
}

fn role_title(role: ProcessRole) -> &'static str {
    match role {
        ProcessRole::CpuVictim => "CPU victim",
        ProcessRole::CpuSuspect => "CPU suspect",
        ProcessRole::MemoryVictim => "Memory victim",
        ProcessRole::MemorySuspect => "Memory suspect",
        ProcessRole::IoVictim => "I/O victim",
        ProcessRole::IoSuspect => "I/O suspect",
    }
}

fn selected_scope(app: &App) -> Option<&crate::analysis::ProcessScope> {
    let window = app.window.as_ref()?;
    match app.selected_finding().map(|finding| &finding.id) {
        Some(watch::FindingId::Cgroup { path, .. }) => window.current.process_scopes.iter().find(|scope| matches!(&scope.scope, ProcessScopeKind::Cgroup { path: candidate } if candidate == path)),
        Some(watch::FindingId::Cpu | watch::FindingId::Memory | watch::FindingId::Io) | None => window.current.process_scopes.iter().find(|scope| matches!(scope.scope, ProcessScopeKind::Host)),
    }
}

fn selected_role_list(app: &App, role: ProcessRole) -> Option<&ProcessRoleList> {
    let stale_for_selected_resource = app.selected_finding().and_then(|finding| {
        let belongs = match &finding.id {
            watch::FindingId::Cpu => {
                matches!(role, ProcessRole::CpuVictim | ProcessRole::CpuSuspect)
            }
            watch::FindingId::Memory => {
                matches!(role, ProcessRole::MemoryVictim | ProcessRole::MemorySuspect)
            }
            watch::FindingId::Io => matches!(role, ProcessRole::IoVictim | ProcessRole::IoSuspect),
            watch::FindingId::Cgroup { resource, .. } => matches!(
                (resource, role),
                (
                    crate::analysis::CgroupResourceKind::Cpu,
                    ProcessRole::CpuVictim | ProcessRole::CpuSuspect
                ) | (
                    crate::analysis::CgroupResourceKind::Memory,
                    ProcessRole::MemoryVictim | ProcessRole::MemorySuspect
                ) | (
                    crate::analysis::CgroupResourceKind::Io,
                    ProcessRole::IoVictim | ProcessRole::IoSuspect
                )
            ),
        };
        belongs
            .then(|| {
                finding
                    .process_role_lists
                    .iter()
                    .find(|list| list.role == role && list.stale)
            })
            .flatten()
    });
    if stale_for_selected_resource.is_some() {
        return stale_for_selected_resource;
    }
    selected_scope(app)
        .and_then(|scope| scope.roles.iter().find(|list| list.role == role))
        .or_else(|| {
            app.selected_finding().and_then(|finding| {
                finding
                    .process_role_lists
                    .iter()
                    .find(|list| list.role == role && list.stale)
            })
        })
}

fn scope_label(app: &App, width: usize) -> String {
    match selected_scope(app).map(|scope| &scope.scope) {
        Some(ProcessScopeKind::Host) => "host scope".to_owned(),
        Some(ProcessScopeKind::Cgroup { path }) => format!(
            "cgroup scope {}",
            crate::render::terminal_scope_identifier(path, width)
        ),
        None => match app.selected_finding().map(|finding| &finding.id) {
            Some(watch::FindingId::Cgroup { path, .. }) => format!(
                "cgroup scope {} (last observed)",
                crate::render::terminal_scope_identifier(path, width)
            ),
            _ => "selected scope unavailable".to_owned(),
        },
    }
}

fn role_state(list: &ProcessRoleList) -> &'static str {
    match (list.availability, list.completeness) {
        (_, ProcessRoleCompleteness::Unavailable)
        | (ProcessCandidateAvailability::UnavailableOrIncomplete, _) => "unavailable/incomplete",
        (ProcessCandidateAvailability::NotAssessed, _) => "not assessed (no pressure)",
        (_, ProcessRoleCompleteness::Partial) => "no candidates (partial)",
        _ => "no candidates observed",
    }
}

fn draw_role_grid(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(format!(
        " Process roles · {} ",
        scope_label(app, usize::from(area.width).saturating_sub(20))
    ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::vertical([
        Constraint::Percentage(33),
        Constraint::Percentage(34),
        Constraint::Percentage(33),
    ])
    .split(inner);
    for (row, (victim, suspect)) in [
        (ProcessRole::CpuVictim, ProcessRole::CpuSuspect),
        (ProcessRole::MemoryVictim, ProcessRole::MemorySuspect),
        (ProcessRole::IoVictim, ProcessRole::IoSuspect),
    ]
    .into_iter()
    .enumerate()
    {
        let cols = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[row]);
        draw_role_cell(frame, cols[0], app, victim);
        draw_role_cell(frame, cols[1], app, suspect);
    }
}

fn draw_compact_roles(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(format!(
        " Process roles · {} ",
        scope_label(app, usize::from(area.width).saturating_sub(20))
    ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::vertical([
        Constraint::Percentage(33),
        Constraint::Percentage(34),
        Constraint::Percentage(33),
    ])
    .split(inner);
    for (row, (victim, suspect)) in [
        (ProcessRole::CpuVictim, ProcessRole::CpuSuspect),
        (ProcessRole::MemoryVictim, ProcessRole::MemorySuspect),
        (ProcessRole::IoVictim, ProcessRole::IoSuspect),
    ]
    .into_iter()
    .enumerate()
    {
        let cols = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[row]);
        draw_role_summary(frame, cols[0], app, victim);
        draw_role_summary(frame, cols[1], app, suspect);
    }
}

fn draw_role_summary(frame: &mut Frame, area: Rect, app: &App, role: ProcessRole) {
    let text = match selected_role_list(app, role) {
        Some(list) if !list.candidates.is_empty() => format!(
            "{}{}: {} · {}",
            role_title(role),
            if list.stale { " (last observed)" } else { "" },
            list.candidates.len(),
            compact_candidate(&list.candidates[0], area.width.saturating_sub(2))
        ),
        Some(list) => format!("{}: {}", role_title(role), role_state(list)),
        None => format!("{}: unavailable", role_title(role)),
    };
    frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), area);
}

fn draw_role_cell(frame: &mut Frame, area: Rect, app: &App, role: ProcessRole) {
    let list = selected_role_list(app, role);
    let title = if list.is_some_and(|list| list.stale) {
        format!("{} (last observed)", role_title(role))
    } else {
        role_title(role).to_owned()
    };
    let lines = match list {
        Some(list) if !list.candidates.is_empty() => list
            .candidates
            .iter()
            .map(|candidate| Line::from(compact_candidate(candidate, area.width.saturating_sub(2))))
            .collect(),
        Some(list) => vec![Line::styled(
            role_state(list),
            Style::default().add_modifier(Modifier::DIM),
        )],
        None => vec![Line::styled(
            "unavailable",
            Style::default().add_modifier(Modifier::DIM),
        )],
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::RIGHT | Borders::BOTTOM)
                    .title(title),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

#[allow(dead_code)]
fn draw_processes(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Processes · current / last observed candidates ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let columns = Layout::horizontal([
        Constraint::Percentage(34),
        Constraint::Percentage(33),
        Constraint::Percentage(33),
    ])
    .split(inner);

    let current = app.window.as_ref().map(|window| &window.current);
    draw_process_column(
        frame,
        columns[0],
        "CPU victims",
        candidates_for_role(
            app,
            current.map(|current| &current.cpu),
            ProcessRole::CpuVictim,
        ),
        ProcessRole::CpuVictim,
    );
    draw_process_column(
        frame,
        columns[1],
        "CPU suspects",
        candidates_for_role(
            app,
            current.map(|current| &current.cpu),
            ProcessRole::CpuSuspect,
        ),
        ProcessRole::CpuSuspect,
    );
    draw_process_column(
        frame,
        columns[2],
        "I/O suspects",
        candidates_for_role(
            app,
            current.map(|current| &current.io),
            ProcessRole::IoSuspect,
        ),
        ProcessRole::IoSuspect,
    );
}

#[allow(dead_code)]
fn candidates_for_role<'a>(
    app: &'a App,
    signal: Option<&'a ResourceSignal>,
    role: ProcessRole,
) -> (Option<&'a ResourceSignal>, Vec<&'a ProcessCandidate>, bool) {
    let current = signal
        .map(|signal| {
            signal
                .process_candidates
                .iter()
                .filter(|candidate| candidate.role == role)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !current.is_empty() {
        return (signal, current, false);
    }
    let stale = app
        .selected_finding()
        .filter(|finding| finding.process_candidates_stale)
        .map(|finding| {
            finding
                .process_candidates
                .iter()
                .filter(|candidate| candidate.role == role)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let stale_present = !stale.is_empty();
    (signal, stale, stale_present)
}

#[allow(dead_code)]
fn draw_process_column<'a>(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    column: (Option<&'a ResourceSignal>, Vec<&'a ProcessCandidate>, bool),
    role: ProcessRole,
) {
    let (signal, candidates, stale) = column;
    let lines = if candidates.is_empty() {
        let state = match signal {
            None => "(waiting for window)",
            Some(signal) => match role_availability(signal, role)
                .unwrap_or(ProcessCandidateAvailability::NotAssessed)
            {
                ProcessCandidateAvailability::Available => "(no candidates observed)",
                ProcessCandidateAvailability::UnavailableOrIncomplete => {
                    "(unavailable/incomplete telemetry)"
                }
                ProcessCandidateAvailability::NotAssessed => "(unavailable: no pressure)",
            },
        };
        vec![Line::styled(
            state,
            Style::default().add_modifier(Modifier::DIM),
        )]
    } else {
        candidates
            .into_iter()
            .map(|candidate| Line::from(compact_candidate(candidate, area.width.saturating_sub(1))))
            .collect()
    };
    let title = if stale {
        match role {
            ProcessRole::CpuVictim => "CPU vic. (last observed)".to_owned(),
            ProcessRole::CpuSuspect => "CPU sus. (last observed)".to_owned(),
            ProcessRole::MemoryVictim => "Mem vic. (last observed)".to_owned(),
            ProcessRole::MemorySuspect => "Mem sus. (last observed)".to_owned(),
            ProcessRole::IoVictim => "I/O vic. (last observed)".to_owned(),
            ProcessRole::IoSuspect => "I/O sus. (last observed)".to_owned(),
        }
    } else {
        title.to_owned()
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::RIGHT))
            .wrap(Wrap { trim: true }),
        area,
    );
}

#[allow(dead_code)]
fn role_availability(
    signal: &ResourceSignal,
    role: ProcessRole,
) -> Option<ProcessCandidateAvailability> {
    signal
        .process_candidate_availability
        .iter()
        .find(|entry| entry.role == role)
        .map(|entry| entry.availability)
}

fn compact_candidate(candidate: &ProcessCandidate, width: u16) -> String {
    let evidence = compact_evidence(candidate);
    let confidence = short_confidence(candidate.confidence);
    let prefix = candidate.key.pid.to_string();
    let suffix = format!(" {evidence} {confidence}");
    let width = usize::from(width);
    let name_width = width.saturating_sub(prefix.width() + suffix.width() + 1);
    let name = terminal_safe_truncate(&terminal_safe_name(&candidate.name), name_width);
    if name.is_empty() {
        format!("{prefix}{suffix}")
    } else {
        format!("{prefix} {name}{suffix}")
    }
}

fn compact_evidence(candidate: &ProcessCandidate) -> String {
    match &candidate.evidence {
        ProcessCandidateEvidence::RunnableDelay {
            runnable_wait_ns, ..
        } => format_ns(*runnable_wait_ns),
        ProcessCandidateEvidence::CpuConsumption {
            cpu_fraction_of_one,
            ..
        } => format_percent(*cpu_fraction_of_one * 100.0, 0),
        ProcessCandidateEvidence::IoActivity {
            known_accounted_bytes,
            ..
        } => format_bytes(*known_accounted_bytes),
        ProcessCandidateEvidence::TaskstatsCpuDelay { cpu_delay_ns } => format_ns(*cpu_delay_ns),
        ProcessCandidateEvidence::MemoryDelay {
            largest_delay_ns, ..
        } => format_ns(*largest_delay_ns),
        ProcessCandidateEvidence::MajorFaults { major_faults } => {
            format_count(u128::from(*major_faults))
        }
        ProcessCandidateEvidence::RssGrowth { rss_growth_bytes } => {
            format_bytes(u128::from(*rss_growth_bytes))
        }
        ProcessCandidateEvidence::BlockIoDelay {
            block_io_delay_ns,
            procfs_block_io_delay_ticks,
        } => block_io_delay_ns.filter(|value| *value > 0).map_or_else(
            || format!("{} ticks", procfs_block_io_delay_ticks.unwrap_or(0)),
            format_ns,
        ),
    }
}

fn detail_candidate(candidate: &ProcessCandidate, width: u16) -> String {
    let confidence = short_confidence(candidate.confidence);
    let evidence = match &candidate.evidence {
        ProcessCandidateEvidence::RunnableDelay {
            runnable_wait_ns,
            runnable_delay_fraction,
            stable_task_count,
            ..
        } => format!(
            "wait {} · window {} · {stable_task_count} tasks",
            format_ns(*runnable_wait_ns),
            format_percent(runnable_delay_fraction * 100.0, 2)
        ),
        ProcessCandidateEvidence::CpuConsumption {
            cpu_fraction_of_one,
            cpu_ticks,
        } => format!(
            "CPU {} · {} ticks",
            format_percent(cpu_fraction_of_one * 100.0, 2),
            format_count(u128::from(*cpu_ticks))
        ),
        ProcessCandidateEvidence::IoActivity {
            read_bytes,
            write_bytes,
            cancelled_write_bytes,
            known_accounted_bytes,
        } => format!(
            "Σ{} r{} w{} c{}",
            format_bytes(*known_accounted_bytes),
            read_bytes.map_or_else(|| "n/a".into(), |value| format_bytes(u128::from(value))),
            write_bytes.map_or_else(|| "n/a".into(), |value| format_bytes(u128::from(value))),
            cancelled_write_bytes
                .map_or_else(|| "n/a".into(), |value| format_bytes(u128::from(value))),
        ),
        ProcessCandidateEvidence::TaskstatsCpuDelay { cpu_delay_ns } => {
            format!("taskstats CPU {}", format_ns(*cpu_delay_ns))
        }
        ProcessCandidateEvidence::MemoryDelay {
            largest_component,
            largest_delay_ns,
            ..
        } => format!("{largest_component} {}", format_ns(*largest_delay_ns)),
        ProcessCandidateEvidence::MajorFaults { major_faults } => {
            format!("{} major faults", format_count(u128::from(*major_faults)))
        }
        ProcessCandidateEvidence::RssGrowth { rss_growth_bytes } => {
            format!("RSS +{}", format_bytes(u128::from(*rss_growth_bytes)))
        }
        ProcessCandidateEvidence::BlockIoDelay {
            block_io_delay_ns,
            procfs_block_io_delay_ticks,
        } => block_io_delay_ns.filter(|value| *value > 0).map_or_else(
            || {
                format!(
                    "block I/O {} ticks",
                    procfs_block_io_delay_ticks.unwrap_or(0)
                )
            },
            |value| format!("block I/O {}", format_ns(value)),
        ),
    };
    let prefix = format!("PID {} ", candidate.key.pid);
    let suffix = format!(
        " · {} · {evidence} · {confidence}",
        role_label(candidate.role)
    );
    let name_width = usize::from(width).saturating_sub(prefix.width() + suffix.width());
    let name = terminal_safe_truncate(&terminal_safe_name(&candidate.name), name_width);
    format!("{prefix}{name}{suffix}")
}

const fn short_confidence(confidence: crate::analysis::Confidence) -> &'static str {
    match confidence {
        crate::analysis::Confidence::Low => "low",
        crate::analysis::Confidence::Medium => "med",
        crate::analysis::Confidence::High => "high",
    }
}

fn format_percent(value: f64, precision: usize) -> String {
    if value.abs() < 10_000.0 {
        format!("{value:.precision$}%")
    } else {
        format!("{value:.2e}%")
    }
}

const fn role_label(role: ProcessRole) -> &'static str {
    match role {
        ProcessRole::CpuVictim => "victim",
        ProcessRole::CpuSuspect => "suspect",
        ProcessRole::MemoryVictim => "memory victim",
        ProcessRole::MemorySuspect => "memory suspect",
        ProcessRole::IoVictim => "I/O victim",
        ProcessRole::IoSuspect => "I/O",
    }
}

fn terminal_safe_name(name: &str) -> String {
    name.chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect()
}

fn terminal_safe_truncate(value: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if value.width() <= width {
        return value.to_owned();
    }

    let content_width = width.saturating_sub('…'.width().unwrap_or(1));
    let mut used = 0;
    let prefix: String = value
        .chars()
        .take_while(|character| {
            let character_width = character.width().unwrap_or(0);
            if used + character_width > content_width {
                false
            } else {
                used += character_width;
                true
            }
        })
        .collect();
    format!("{prefix}…")
}

fn format_ns(nanoseconds: u64) -> String {
    const SECOND: u64 = 1_000_000_000;
    const MINUTE: u64 = SECOND * 60;
    const HOUR: u64 = MINUTE * 60;
    const DAY: u64 = HOUR * 24;
    const YEAR: u64 = DAY * 365;
    if nanoseconds >= YEAR {
        format!("{:.1}y", nanoseconds as f64 / YEAR as f64)
    } else if nanoseconds >= DAY {
        format!("{:.1}d", nanoseconds as f64 / DAY as f64)
    } else if nanoseconds >= HOUR {
        format!("{:.1}h", nanoseconds as f64 / HOUR as f64)
    } else if nanoseconds >= MINUTE {
        format!("{:.1}m", nanoseconds as f64 / MINUTE as f64)
    } else if nanoseconds >= SECOND {
        format!("{:.1}s", nanoseconds as f64 / 1_000_000_000.0)
    } else if nanoseconds >= 1_000_000 {
        format!("{:.1}ms", nanoseconds as f64 / 1_000_000.0)
    } else {
        format!("{:.0}µs", nanoseconds as f64 / 1_000.0)
    }
}

fn format_count(value: u128) -> String {
    if value < 1_000_000_000 {
        value.to_string()
    } else {
        format!("{:.2e}", value as f64)
    }
}

fn format_bytes(bytes: u128) -> String {
    const KIB: u128 = 1024;
    const MIB: u128 = KIB * 1024;
    const GIB: u128 = MIB * 1024;
    const TIB: u128 = GIB * 1024;
    const PIB: u128 = TIB * 1024;
    const EIB: u128 = PIB * 1024;
    if bytes >= EIB {
        format!("{:.1}EiB", bytes as f64 / EIB as f64)
    } else if bytes >= PIB {
        format!("{:.1}PiB", bytes as f64 / PIB as f64)
    } else if bytes >= TIB {
        format!("{:.1}TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1}GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1}MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let title = match &app.window {
        Some(window) => format!(
            "STALLHUNT WATCH · window {} · interval {}",
            watch::window_index_label(window),
            watch::format_ms(window.interval_ms)
        ),
        None => "STALLHUNT WATCH".to_owned(),
    };
    let line = Line::from(vec![
        Span::styled(title, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("  ·  "),
        Span::raw("q quit · ↑↓/jk select · enter detail · PgUp/PgDn scroll · h help"),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_lifecycle(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Lifecycle (pressure findings; healthy windows resolve, missing data not) ");
    let Some(window) = &app.window else {
        frame.render_widget(
            Paragraph::new("waiting for the first window…").block(block),
            area,
        );
        return;
    };
    if window.lifecycle.is_empty() {
        frame.render_widget(
            Paragraph::new("(no pressure findings this window)").block(block),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = window
        .lifecycle
        .iter()
        .enumerate()
        .map(|(index, finding)| lifecycle_line(finding, index == app.selected, app.color))
        .collect();
    let mut state = ListState::default();
    state.select(Some(app.selected.min(items.len().saturating_sub(1))));
    frame.render_stateful_widget(List::new(items).block(block), area, &mut state);
}

fn lifecycle_line(
    finding: &watch::TrackedFinding,
    selected: bool,
    color: ColorMode,
) -> ListItem<'static> {
    let marker = if selected { "▸ " } else { "  " };
    let tone = style::severity_tone(finding.severity);
    let mut spans = vec![
        Span::raw(marker),
        Span::raw(format!("{:<11} ", style::state_label(finding.state))),
        Span::raw(format!("{:<32} ", watch::id_label(&finding.id))),
        Span::raw(format!("{}  ", finding.kind)),
        Span::styled(
            style::severity_name(finding.severity).to_owned(),
            style::severity_ratatui_style(tone, color),
        ),
    ];
    if finding.state == LifecycleState::Persistent {
        spans.push(Span::raw(format!("  {}w", finding.consecutive_windows)));
        if let Some(previous) = finding.previous_severity {
            spans.push(Span::raw(format!(
                " (was {})",
                style::severity_name(previous)
            )));
        }
        if !finding.confirmed {
            spans.push(Span::styled(
                " unconfirmed",
                Style::default().add_modifier(Modifier::DIM),
            ));
        }
    }
    ListItem::new(Line::from(spans))
}

fn draw_current(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Current window ");
    let Some(window) = &app.window else {
        frame.render_widget(Paragraph::new("").block(block), area);
        return;
    };
    let lines = vec![
        resource_line("CPU", &window.current.cpu, app.color),
        resource_line("Memory", &window.current.memory, app.color),
        resource_line("I/O", &window.current.io, app.color),
        Line::from(format!(
            "Cgroup   {} scoped pressure ranked this window",
            window
                .current
                .cgroups
                .iter()
                .filter(|(_, signal)| signal.status == ObservationStatus::Pressure)
                .count()
        )),
    ];
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn resource_line(label: &str, signal: &ResourceSignal, color: ColorMode) -> Line<'static> {
    let tone = style::severity_tone(signal.severity);
    Line::from(vec![
        Span::raw(format!("{label:<8} ")),
        Span::raw(format!("{:<12} ", style::status_label(signal.status))),
        Span::styled(
            style::severity_name(signal.severity).to_owned(),
            style::severity_ratatui_style(tone, color),
        ),
        Span::raw(watch::psi_suffix(signal.psi_some_fraction)),
    ])
}

fn draw_history(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" History · last windows, oldest left ");
    let Some(window) = &app.window else {
        frame.render_widget(Paragraph::new("").block(block), area);
        return;
    };
    let cpu = history_strip(window, is_cpu);
    let memory = history_strip(window, is_memory);
    let io = history_strip(window, is_io);
    let line = Line::from(format!("CPU  {cpu}   Mem  {memory}   I/O  {io}"));
    frame.render_widget(Paragraph::new(line).block(block), area);
}

fn is_cpu(id: &watch::FindingId) -> bool {
    matches!(id, watch::FindingId::Cpu)
}
fn is_memory(id: &watch::FindingId) -> bool {
    matches!(id, watch::FindingId::Memory)
}
fn is_io(id: &watch::FindingId) -> bool {
    matches!(id, watch::FindingId::Io)
}

fn history_strip(window: &WatchWindow, matches_id: fn(&watch::FindingId) -> bool) -> String {
    window
        .history
        .iter()
        .map(|entry| {
            entry
                .events
                .iter()
                .find(|event| matches_id(&event.id))
                .map_or(HISTORY_GLYPHS[0], |event| {
                    let rank = watch::severity_rank(event.severity) as usize;
                    HISTORY_GLYPHS[rank.min(HISTORY_GLYPHS.len() - 1)]
                })
        })
        .collect()
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &App, shown: bool) {
    let title = match app.selected_finding() {
        Some(finding) => format!(
            " Detail: {} (Enter toggles · PgUp/PgDn/Home/End scroll) ",
            watch::id_label(&finding.id)
        ),
        None => " Detail ".to_owned(),
    };
    let block = Block::default().borders(Borders::ALL).title(title);
    if !shown {
        frame.render_widget(
            Paragraph::new("Detail explicitly hidden (Enter/Space shows it).")
                .block(block)
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let detail_width = block.inner(area).width;
    let lines = detail_lines(app, detail_width);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.detail_scroll.min(app.detail_max_scroll()), 0))
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

fn detail_lines(app: &App, detail_width: u16) -> Vec<Line<'static>> {
    let Some(finding) = app.selected_finding() else {
        return vec![Line::from("(no finding selected)")];
    };
    let mut lines = vec![Line::from(finding.summary.clone())];
    let stale_lists = finding.process_role_lists.iter().any(|list| list.stale);
    let role_lists: Vec<&ProcessRoleList> = if stale_lists {
        finding.process_role_lists.iter().collect()
    } else {
        selected_scope(app)
            .map(|scope| scope.roles.iter().collect())
            .unwrap_or_else(|| finding.process_role_lists.iter().collect())
    };
    lines.push(Line::styled(
        if stale_lists {
            "Last observed roles (finding unconfirmed or resolved):"
        } else {
            "Process roles from this scope:"
        },
        Style::default().add_modifier(Modifier::BOLD),
    ));
    for role in [
        ProcessRole::CpuVictim,
        ProcessRole::CpuSuspect,
        ProcessRole::MemoryVictim,
        ProcessRole::MemorySuspect,
        ProcessRole::IoVictim,
        ProcessRole::IoSuspect,
    ] {
        match role_lists.iter().find(|list| list.role == role) {
            Some(list) if !list.candidates.is_empty() => {
                lines.push(Line::styled(
                    format!(
                        "{}{}:",
                        role_title(role),
                        if list.stale { " (last observed)" } else { "" }
                    ),
                    Style::default().add_modifier(Modifier::BOLD),
                ));
                lines.extend(
                    list.candidates
                        .iter()
                        .map(|candidate| Line::from(detail_candidate(candidate, detail_width))),
                );
            }
            Some(list) => lines.push(Line::styled(
                format!("{}: {}", role_title(role), role_state(list)),
                Style::default().add_modifier(Modifier::DIM),
            )),
            None => lines.push(Line::styled(
                format!("{}: unavailable", role_title(role)),
                Style::default().add_modifier(Modifier::DIM),
            )),
        }
    }
    if finding.qualifiers.is_empty() {
        lines.push(Line::styled(
            "No additional context and limitations recorded for this finding.",
            Style::default().add_modifier(Modifier::DIM),
        ));
    } else {
        lines.push(Line::styled(
            "Context and limitations:",
            Style::default().add_modifier(Modifier::BOLD),
        ));
        for qualifier in &finding.qualifiers {
            lines.push(Line::from(format!(
                "  {}",
                terminal_safe_name(qualifier.message)
            )));
        }
    }
    lines
}

fn draw_footer(frame: &mut Frame, area: Rect) {
    let line = Line::styled(
        "Lifecycle tracks pressure findings only, not utilization. Second Ctrl-C exits immediately.",
        Style::default().add_modifier(Modifier::DIM),
    );
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_help_overlay(frame: &mut Frame, area: Rect) {
    let width = area.width.min(60);
    let height = area.height.min(12);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::from("q / Esc      quit"),
        Line::from("↑ / k        move selection up"),
        Line::from("↓ / j        move selection down"),
        Line::from("Enter/Space  toggle detail visibility"),
        Line::from("PgUp/PgDn/Home/End scroll detail"),
        Line::from("h / ?        toggle this help"),
        Line::from("Ctrl-C       drain and exit; twice exits immediately"),
        Line::from(""),
        Line::styled(
            "Watch shows finding lifecycle, not host utilization.",
            Style::default().add_modifier(Modifier::DIM),
        ),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help ")
        .style(Style::default().bg(Color::Reset));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .alignment(Alignment::Left),
        popup,
    );
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::watch::test_support::{sample_window, window_with_lifecycle_len};
    use std::sync::Arc;
    use std::sync::atomic::AtomicU8;

    fn new_app() -> App {
        App::new(ColorMode::Never, Arc::new(AtomicU8::new(0)))
    }

    fn draw_to_lines(app: &App) -> Vec<String> {
        draw_to_lines_at(app, 80, 24)
    }

    fn draw_to_lines_at(app: &App, width: u16, height: u16) -> Vec<String> {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal.draw(|frame| draw(frame, app)).expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(usize::from(width))
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect()
    }

    #[test]
    fn empty_lifecycle_renders_without_panicking_and_says_so() {
        let mut app = new_app();
        app.on_window(window_with_lifecycle_len(0));
        let lines = draw_to_lines(&app);
        let joined = lines.join("\n");
        assert!(joined.contains("no pressure findings this window"));
        assert!(joined.contains("Process roles"));
        assert!(joined.contains("unavailable"));
    }

    #[test]
    fn normal_view_shows_lifecycle_current_and_history_panels() {
        let mut app = new_app();
        app.on_window(sample_window());
        let lines = draw_to_lines(&app);
        let joined = lines.join("\n");
        assert!(joined.contains("Lifecycle"));
        assert!(joined.contains("NEW"));
        assert!(joined.contains("cpu_scheduling_contention"));
        assert!(joined.contains("high"));
        assert!(joined.contains("Current window"));
        assert!(joined.contains("Memory"));
        assert!(joined.contains("History"));
        assert!(joined.contains("Process roles"));
        assert!(joined.contains("CPU victim"));
        assert!(joined.contains("CPU suspect"));
        assert!(joined.contains("I/O suspect"));
        assert!(joined.contains("4812"));
        assert!(joined.contains("500.0ms high"));
        assert!(joined.contains("9231"));
        assert!(joined.contains("rustc"));
        assert!(joined.contains("7712"));
        assert!(joined.contains("6.0KiB med"));
        assert!(
            !joined.contains("Context and limitations"),
            "detail pane must be collapsed by default"
        );
    }

    #[test]
    fn expanded_detail_shows_full_qualifier_text() {
        let mut app = new_app();
        app.on_window(sample_window());
        app.detail_preference = crate::tui::app::DetailPreference::ExplicitShown;
        let lines = draw_to_lines(&app);
        let joined = lines.join("\n");
        assert!(joined.contains("Process roles from this scope:"));
        assert!(joined.contains("PID 4812"));
        assert!(joined.contains("wait 500.0ms · window 5.00% · 2 tasks · high"));
        assert!(joined.contains("PID 9231 rustc · suspect"));
        assert!(joined.contains("Memory victim"), "{joined}");
        // The compact screen intentionally scrolls the remaining role and
        // qualifier content; it is not silently discarded.
    }

    #[test]
    fn current_scope_lists_do_not_inherit_stale_state_from_a_different_fallback() {
        let mut app = new_app();
        let mut window = sample_window();
        window.current.cpu.process_candidates.clear();
        window.lifecycle[0].process_candidates_stale = true;
        app.on_window(window);

        let joined = draw_to_lines(&app).join("\n");
        assert!(!joined.contains("last observed"));
        assert!(joined.contains("4812"));
        assert!(joined.contains("9231"));
        assert!(joined.contains("rustc"));
    }

    #[test]
    fn processes_panel_distinguishes_missing_process_telemetry_from_an_empty_rank() {
        let mut app = new_app();
        let mut window = sample_window();
        window.current.cpu.process_candidates.clear();
        window.current.cpu.process_candidate_availability = vec![
            crate::watch::ProcessRoleAvailability {
                role: ProcessRole::CpuVictim,
                availability: ProcessCandidateAvailability::UnavailableOrIncomplete,
            },
            crate::watch::ProcessRoleAvailability {
                role: ProcessRole::CpuSuspect,
                availability: ProcessCandidateAvailability::UnavailableOrIncomplete,
            },
        ];
        app.on_window(window);

        let joined = draw_to_lines(&app).join("\n");
        assert!(joined.contains("CPU victim"));
    }

    #[test]
    fn terminal_safe_compact_candidates_truncate_to_the_column_width() {
        let candidate = &sample_window().current.cpu.process_candidates[0];
        let line = compact_candidate(candidate, 24);
        assert!(line.width() <= 24);
        assert!(line.contains('…'));
        assert!(line.contains("500.0ms"));
        assert!(line.ends_with("high"));
        assert!(!line.contains('\n'));
        assert!(!line.contains('\x1b'));
    }

    #[test]
    fn wide_process_names_yield_to_evidence_and_confidence() {
        let mut candidate = sample_window().current.cpu.process_candidates[0].clone();
        candidate.name = "界".repeat(20);

        let compact = compact_candidate(&candidate, 24);
        assert!(compact.width() <= 24, "{compact}");
        assert!(compact.contains("500.0ms"), "{compact}");
        assert!(compact.ends_with("high"), "{compact}");

        let detail = detail_candidate(&candidate, 78);
        assert!(detail.width() <= 78, "{detail}");
        assert!(detail.contains("wait 500.0ms"), "{detail}");
        assert!(detail.ends_with("high"), "{detail}");
    }

    #[test]
    fn detail_candidates_preserve_bounded_evidence_with_extreme_counters() {
        let mut candidates = sample_window().current.cpu.process_candidates;
        candidates.push(sample_window().current.io.process_candidates[0].clone());
        for candidate in &mut candidates {
            candidate.key.pid = u32::MAX;
            candidate.name = "very-long\nprocess-name-that-must-yield-to-evidence".repeat(3);
            match &mut candidate.evidence {
                ProcessCandidateEvidence::RunnableDelay {
                    runnable_wait_ns,
                    runnable_delay_fraction,
                    stable_task_count,
                    ..
                } => {
                    *runnable_wait_ns = u64::MAX;
                    *runnable_delay_fraction = f64::MAX;
                    *stable_task_count = u32::MAX;
                }
                ProcessCandidateEvidence::CpuConsumption {
                    cpu_fraction_of_one,
                    cpu_ticks,
                } => {
                    *cpu_fraction_of_one = f64::MAX;
                    *cpu_ticks = u64::MAX;
                }
                ProcessCandidateEvidence::IoActivity {
                    read_bytes,
                    write_bytes,
                    cancelled_write_bytes,
                    known_accounted_bytes,
                } => {
                    *read_bytes = Some(u64::MAX);
                    *write_bytes = Some(u64::MAX);
                    *cancelled_write_bytes = Some(u64::MAX);
                    *known_accounted_bytes = u128::from(u64::MAX) * 2;
                }
                ProcessCandidateEvidence::TaskstatsCpuDelay { .. }
                | ProcessCandidateEvidence::MemoryDelay { .. }
                | ProcessCandidateEvidence::MajorFaults { .. }
                | ProcessCandidateEvidence::RssGrowth { .. }
                | ProcessCandidateEvidence::BlockIoDelay { .. } => {}
            }
            let line = detail_candidate(candidate, 78);
            assert!(line.chars().count() <= 78, "{line}");
            assert!(
                line.ends_with(short_confidence(candidate.confidence)),
                "{line}"
            );
            assert!(!line.contains('\n'));
        }
    }

    #[test]
    fn help_overlay_lists_keys() {
        let mut app = new_app();
        app.on_window(sample_window());
        app.help = true;
        let lines = draw_to_lines(&app);
        let joined = lines.join("\n");
        assert!(joined.contains("quit"));
        assert!(joined.contains("toggle this help"));
    }

    #[test]
    fn responsive_wide_grid_keeps_detail_and_compact_falls_back_at_boundaries() {
        let mut app = new_app();
        app.on_window(sample_window());
        for (width, height) in [(120, 30), (160, 45)] {
            let joined = draw_to_lines_at(&app, width, height).join("\n");
            assert!(
                joined.contains("Process roles · host scope"),
                "{width}x{height}: {joined}"
            );
            assert!(joined.contains("Detail: CPU"), "{width}x{height}: {joined}");
            assert!(joined.contains("Current window"));
            assert!(joined.contains("History"));
        }
        for (width, height) in [(119, 29), (80, 24)] {
            let joined = draw_to_lines_at(&app, width, height).join("\n");
            assert!(
                joined.contains("Current window"),
                "{width}x{height}: {joined}"
            );
            assert!(
                !joined.contains("Detail: CPU"),
                "{width}x{height}: {joined}"
            );
        }
    }

    #[test]
    fn detail_scroll_reveals_later_role_content() {
        let mut app = new_app();
        app.on_window(sample_window());
        app.detail_preference = crate::tui::app::DetailPreference::ExplicitShown;
        app.detail_scroll = 8;
        let joined = draw_to_lines(&app).join("\n");
        assert!(
            joined.contains("I/O victim") || joined.contains("I/O suspect"),
            "{joined}"
        );
    }

    #[test]
    fn wide_grid_follows_selected_cgroup_path_instead_of_a_host_resource_row() {
        let mut app = new_app();
        let mut window = sample_window();
        window.current.process_scopes[0].roles = role_lists_with_candidates("host", 10_000);
        let roles = role_lists_with_candidates("cg", 20_000);
        window
            .current
            .process_scopes
            .push(crate::analysis::ProcessScope {
                scope: ProcessScopeKind::Cgroup {
                    path: "/system.slice/db.service".into(),
                },
                roles,
            });
        app.on_window(window);
        app.selected = 2; // fixture's cgroup I/O lifecycle finding
        let joined = draw_to_lines_at(&app, 120, 30).join("\n");
        assert!(joined.contains("cgroup scope /system.slice"), "{joined}");
        assert!(joined.contains("cg0c0"), "{joined}");
        assert!(!joined.contains("host0c0"), "{joined}");
    }

    #[test]
    fn compact_scope_heading_sanitizes_controls_and_respects_display_width() {
        let mut app = new_app();
        let mut window = sample_window();
        if let crate::watch::FindingId::Cgroup { path, .. } = &mut window.lifecycle[2].id {
            *path = "/界\u{1b}[31m/a-very-long-cgroup-name".into();
        }
        app.on_window(window);
        app.selected = 2;
        let joined = draw_to_lines_at(&app, 80, 24).join("\n");
        assert!(!joined.contains('\u{1b}'));
        assert!(joined.contains('�'));
    }

    #[test]
    fn wide_grid_renders_all_thirty_scoped_candidates_at_both_required_sizes() {
        let mut app = new_app();
        let mut window = sample_window();
        window.current.process_scopes[0].roles = role_lists_with_candidates("host", 10_000);
        app.on_window(window);
        for (width, height) in [(120, 30), (160, 45)] {
            let joined = draw_to_lines_at(&app, width, height).join("\n");
            for candidate in 0..30 {
                assert!(
                    joined.contains(&(10_000 + candidate).to_string()),
                    "{width}x{height} omitted PID {}: {joined}",
                    10_000 + candidate
                );
            }
        }
        for (width, height) in [(119, 29), (80, 24)] {
            let joined = draw_to_lines_at(&app, width, height).join("\n");
            assert!(
                joined.contains("Process roles"),
                "{width}x{height}: {joined}"
            );
            assert!(
                !joined.contains("host0c4"),
                "compact mode must be a summary rather than the wide grid"
            );
        }
    }

    #[test]
    fn layout_derived_scrolling_reaches_final_role_and_qualifier_on_wide_and_compact() {
        for (width, height) in [(120, 30), (80, 24)] {
            let mut app = new_app();
            let mut window = sample_window();
            window.current.process_scopes[0].roles = role_lists_with_candidates("scroll", 30_000);
            window.lifecycle[0].qualifiers = vec![
                crate::analysis::Qualifier {
                    kind: "test",
                    // Ratatui's WordWrapper leaves unused cells before moving
                    // the next word. The scroll bound must use that exact
                    // behavior rather than character-width division.
                    message: "123456 123456 123456",
                },
                crate::analysis::Qualifier {
                    kind: "test",
                    message: "final-qualifier-token",
                },
            ];
            app.on_window(window);
            app.detail_preference = crate::tui::app::DetailPreference::ExplicitShown;
            app.update_detail_scroll_max(detail_scroll_max(&app, width, height));
            assert!(app.detail_max_scroll() > 0, "{width}x{height}");
            app.handle_key(crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::End,
                crossterm::event::KeyModifiers::NONE,
            ));
            assert_eq!(app.detail_scroll, app.detail_max_scroll());
            let at_end = draw_to_lines_at(&app, width, height).join("\n");
            assert!(
                at_end.contains("final-qualifier-token"),
                "{width}x{height}: {at_end}"
            );

            let found_final_role = (0..=app.detail_max_scroll()).any(|offset| {
                app.detail_scroll = offset;
                draw_to_lines_at(&app, width, height)
                    .join("\n")
                    .contains("PID 30029")
            });
            assert!(
                found_final_role,
                "{width}x{height} final I/O suspect was unreachable"
            );
        }
    }

    #[test]
    fn lifecycle_stateful_list_keeps_the_nineteenth_selection_visible() {
        let mut app = new_app();
        app.on_window(window_with_lifecycle_len(19));
        app.selected = 18;
        let joined = draw_to_lines_at(&app, 80, 24).join("\n");
        assert!(joined.contains("/extra-9.scope"), "{joined}");
    }

    fn role_lists_with_candidates(prefix: &str, first_pid: u32) -> Vec<ProcessRoleList> {
        let template = sample_window().current.cpu.process_candidates[0].clone();
        [
            ProcessRole::CpuVictim,
            ProcessRole::CpuSuspect,
            ProcessRole::MemoryVictim,
            ProcessRole::MemorySuspect,
            ProcessRole::IoVictim,
            ProcessRole::IoSuspect,
        ]
        .into_iter()
        .enumerate()
        .map(|(role_index, role)| ProcessRoleList {
            role,
            availability: ProcessCandidateAvailability::Available,
            completeness: ProcessRoleCompleteness::Complete,
            stale: false,
            candidates: (0..5)
                .map(|candidate_index| {
                    let mut candidate = template.clone();
                    candidate.role = role;
                    candidate.key.pid = first_pid + (role_index * 5 + candidate_index) as u32;
                    candidate.name = format!("{prefix}{role_index}c{candidate_index}");
                    candidate
                })
                .collect(),
        })
        .collect()
    }
}
