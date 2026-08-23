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
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::style::{self, ColorMode};
use crate::watch::{
    self, LifecycleState, ObservationStatus, ProcessCandidate, ProcessCandidateAvailability,
    ProcessCandidateEvidence, ProcessRole, ResourceSignal, WatchWindow,
};

use super::app::App;

const HISTORY_GLYPHS: [char; 5] = ['·', '▂', '▄', '▆', '█'];

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    // Keep attribution visible in both modes. Detail borrows room from the
    // current/history summaries, not from the processes panel.
    let (current_height, history_height, detail_height) =
        if app.expanded { (0, 0, 12) } else { (5, 3, 0) };
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(7),
        Constraint::Length(current_height),
        Constraint::Length(history_height),
        Constraint::Length(detail_height),
        Constraint::Length(1),
    ])
    .split(area);

    draw_header(frame, chunks[0], app);
    draw_lifecycle(frame, chunks[1], app);
    draw_processes(frame, chunks[2], app);
    if !app.expanded {
        draw_current(frame, chunks[3], app);
    }
    if !app.expanded {
        draw_history(frame, chunks[4], app);
    }
    if app.expanded {
        draw_detail(frame, chunks[5], app);
    }
    draw_footer(frame, chunks[6]);

    if app.help {
        draw_help_overlay(frame, area);
    }
}

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
    }
}

fn detail_candidate(candidate: &ProcessCandidate, width: u16) -> String {
    let confidence = short_confidence(candidate.confidence);
    let evidence = match &candidate.evidence {
        ProcessCandidateEvidence::RunnableDelay {
            runnable_wait_ns,
            runnable_delay_fraction,
            stable_task_count,
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
        Span::raw("q quit · ↑↓/jk select · enter/space detail · h help"),
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
    frame.render_widget(List::new(items).block(block), area);
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

fn draw_detail(frame: &mut Frame, area: Rect, app: &App) {
    let title = match app.selected_finding() {
        Some(finding) => format!(
            " Detail: {} (enter/space toggles) ",
            watch::id_label(&finding.id)
        ),
        None => " Detail ".to_owned(),
    };
    let block = Block::default().borders(Borders::ALL).title(title);
    let detail_width = block.inner(area).width;
    let Some(finding) = app.selected_finding() else {
        frame.render_widget(Paragraph::new("(no finding selected)").block(block), area);
        return;
    };
    let mut lines = vec![Line::from(finding.summary.clone())];
    if finding.process_candidates.is_empty() {
        lines.push(Line::styled(
            "Process attribution: unavailable or no candidates observed.",
            Style::default().add_modifier(Modifier::DIM),
        ));
    } else {
        let heading = if finding.process_candidates_stale {
            "Last observed candidates (finding unconfirmed or resolved):"
        } else {
            "Process candidates from this confirmed window:"
        };
        lines.push(Line::styled(
            heading,
            Style::default().add_modifier(Modifier::BOLD),
        ));
        lines.extend(
            finding
                .process_candidates
                .iter()
                .map(|candidate| Line::from(detail_candidate(candidate, detail_width))),
        );
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
            lines.push(Line::from(format!("  {}", qualifier.message)));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
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
        Line::from("Enter/Space  toggle finding detail"),
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
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal.draw(|frame| draw(frame, app)).expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(80)
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
        assert!(joined.contains("Processes"));
        assert!(joined.contains("unavailable: no pressure"));
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
        assert!(joined.contains("Processes"));
        assert!(joined.contains("CPU victims"));
        assert!(joined.contains("CPU suspects"));
        assert!(joined.contains("I/O suspects"));
        assert!(joined.contains("4812"));
        assert!(joined.contains("500.0ms high"));
        assert!(joined.contains("9231 rustc 125% med"));
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
        app.expanded = true;
        let lines = draw_to_lines(&app);
        let joined = lines.join("\n");
        assert!(joined.contains("Process candidates from this confirmed window:"));
        assert!(joined.contains("PID 4812"));
        assert!(joined.contains("wait 500.0ms · window 5.00% · 2 tasks · high"));
        assert!(joined.contains("PID 9231 rustc · suspect"));
        assert!(joined.contains("Context and limitations"), "{joined}");
        assert!(
            joined.find("Process candidates").unwrap()
                < joined.find("Context and limitations").unwrap(),
            "candidate evidence must precede qualifiers"
        );
        // The qualifier text word-wraps across TestBackend rows, so assert
        // on fragments from each end rather than one contiguous substring
        // that could straddle a wrap point.
        assert!(joined.contains("does not prove"));
        assert!(joined.contains("causality."));
        assert!(
            joined.contains("Host CPU utilization was at least 90%"),
            "{joined}"
        );
    }

    #[test]
    fn processes_panel_marks_retained_lifecycle_candidates_as_last_observed() {
        let mut app = new_app();
        let mut window = sample_window();
        window.current.cpu.process_candidates.clear();
        window.lifecycle[0].process_candidates_stale = true;
        app.on_window(window);

        let joined = draw_to_lines(&app).join("\n");
        assert!(joined.contains("last observed"));
        assert!(joined.contains("4812"));
        assert!(joined.contains("9231 rustc 125% med"));
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
        assert!(joined.contains("unavailable/incomplete"));
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
    fn expanded_detail_keeps_all_eight_bounded_cpu_candidates_visible_at_80x24() {
        let mut app = new_app();
        let mut window = sample_window();
        let victim = window.current.cpu.process_candidates[0].clone();
        let suspect = window.current.cpu.process_candidates[1].clone();
        let mut candidates = Vec::new();
        for offset in 0..5 {
            let mut candidate = victim.clone();
            candidate.key.pid = 4_800 + offset;
            candidates.push(candidate);
        }
        for offset in 0..3 {
            let mut candidate = suspect.clone();
            candidate.key.pid = 9_200 + offset;
            candidates.push(candidate);
        }
        window.lifecycle[0].process_candidates = candidates;
        window.lifecycle[0].qualifiers.clear();
        app.on_window(window);
        app.expanded = true;

        let joined = draw_to_lines(&app).join("\n");
        assert!(joined.contains("PID 4800"));
        assert!(joined.contains("PID 9202"), "{joined}");
        assert!(joined.contains("125 ticks · med"), "{joined}");
    }

    #[test]
    fn expanded_stale_detail_keeps_all_eight_candidates_visible_at_80x24() {
        let mut app = new_app();
        let mut window = sample_window();
        let victim = window.current.cpu.process_candidates[0].clone();
        window.lifecycle[0].process_candidates = (0..8)
            .map(|offset| {
                let mut candidate = victim.clone();
                candidate.key.pid = 5_000 + offset;
                candidate
            })
            .collect();
        window.lifecycle[0].process_candidates_stale = true;
        window.lifecycle[0].qualifiers.clear();
        app.on_window(window);
        app.expanded = true;

        let joined = draw_to_lines(&app).join("\n");
        assert!(joined.contains("Last observed candidates"), "{joined}");
        assert!(joined.contains("PID 5007"), "{joined}");
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
}
