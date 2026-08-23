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
        .title(" Processes · same-window attribution ");
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
                ProcessCandidateAvailability::Unavailable => "(unavailable: telemetry)",
                ProcessCandidateAvailability::NotAssessed => "(unavailable: no pressure)",
            },
        };
        vec![Line::styled(
            state,
            Style::default().add_modifier(Modifier::DIM),
        )]
    } else {
        let mut lines = stale
            .then(|| {
                Line::styled(
                    "(last observed)",
                    Style::default().add_modifier(Modifier::DIM),
                )
            })
            .into_iter()
            .collect::<Vec<_>>();
        lines.extend(
            candidates
                .into_iter()
                .map(|candidate| Line::from(compact_candidate(candidate, area.width))),
        );
        lines
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
    let confidence = style::confidence_name(candidate.confidence);
    terminal_safe_truncate(
        &format!(
            "{} {} · {} · {confidence}",
            candidate.key.pid,
            terminal_safe_name(&candidate.name),
            evidence,
        ),
        usize::from(width.saturating_sub(2)),
    )
}

fn compact_evidence(candidate: &ProcessCandidate) -> String {
    match &candidate.evidence {
        ProcessCandidateEvidence::RunnableDelay {
            runnable_wait_ns,
            stable_task_count,
            ..
        } => format!(
            "wait {} · {stable_task_count} tasks",
            format_ns(*runnable_wait_ns)
        ),
        ProcessCandidateEvidence::CpuConsumption {
            cpu_fraction_of_one,
            ..
        } => format!("CPU {:.0}%", cpu_fraction_of_one * 100.0),
        ProcessCandidateEvidence::IoActivity {
            known_accounted_bytes,
            ..
        } => format!("I/O {}", format_bytes(*known_accounted_bytes)),
    }
}

fn detail_candidate(candidate: &ProcessCandidate) -> String {
    let name = terminal_safe_name(&candidate.name);
    let confidence = style::confidence_name(candidate.confidence);
    let evidence = match &candidate.evidence {
        ProcessCandidateEvidence::RunnableDelay {
            runnable_wait_ns,
            runnable_delay_fraction,
            stable_task_count,
        } => format!(
            "delay {}; {:.2}% of the observation window; {stable_task_count} tasks",
            format_ns(*runnable_wait_ns),
            runnable_delay_fraction * 100.0
        ),
        ProcessCandidateEvidence::CpuConsumption {
            cpu_fraction_of_one,
            cpu_ticks,
        } => format!(
            "CPU {:.2}% of one CPU; {cpu_ticks} ticks",
            cpu_fraction_of_one * 100.0
        ),
        ProcessCandidateEvidence::IoActivity {
            read_bytes,
            write_bytes,
            cancelled_write_bytes,
            known_accounted_bytes,
        } => format!(
            "known I/O {}; read {}; charged write {}; cancelled write {}",
            format_bytes(*known_accounted_bytes),
            read_bytes.map_or_else(
                || "unavailable".into(),
                |value| format_bytes(u128::from(value))
            ),
            write_bytes.map_or_else(
                || "unavailable".into(),
                |value| format_bytes(u128::from(value))
            ),
            cancelled_write_bytes.map_or_else(
                || "unavailable".into(),
                |value| format_bytes(u128::from(value))
            ),
        ),
    };
    format!(
        "  PID {} {name} · {} · {evidence} ({confidence})",
        candidate.key.pid,
        role_label(candidate.role),
    )
}

const fn role_label(role: ProcessRole) -> &'static str {
    match role {
        ProcessRole::CpuVictim => "victim",
        ProcessRole::CpuSuspect => "suspect",
        ProcessRole::IoSuspect => "I/O suspect",
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
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(width).collect();
    if chars.next().is_some() && width >= 2 {
        let prefix: String = truncated.chars().take(width - 1).collect();
        format!("{prefix}…")
    } else {
        truncated
    }
}

fn format_ns(nanoseconds: u64) -> String {
    if nanoseconds >= 1_000_000_000 {
        format!("{:.1}s", nanoseconds as f64 / 1_000_000_000.0)
    } else if nanoseconds >= 1_000_000 {
        format!("{:.1}ms", nanoseconds as f64 / 1_000_000.0)
    } else {
        format!("{:.0}µs", nanoseconds as f64 / 1_000.0)
    }
}

fn format_bytes(bytes: u128) -> String {
    const KIB: u128 = 1024;
    const MIB: u128 = KIB * 1024;
    const GIB: u128 = MIB * 1024;
    if bytes >= GIB {
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
            "Last observed process candidates (the current finding is unconfirmed or resolved):"
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
                .map(|candidate| Line::from(detail_candidate(candidate))),
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
        assert!(joined.contains("4812 postgres�worker"));
        assert!(joined.contains("9231 rustc"));
        assert!(joined.contains("7712 restic"));
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
        assert!(joined.contains("PID 4812 postgres�worker · victim"));
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
        assert!(joined.contains("4812 postgres�worker"));
        assert!(joined.contains("9231 rustc"));
    }

    #[test]
    fn processes_panel_distinguishes_missing_process_telemetry_from_an_empty_rank() {
        let mut app = new_app();
        let mut window = sample_window();
        window.current.cpu.process_candidates.clear();
        window.current.cpu.process_candidate_availability = vec![
            crate::watch::ProcessRoleAvailability {
                role: ProcessRole::CpuVictim,
                availability: ProcessCandidateAvailability::Unavailable,
            },
            crate::watch::ProcessRoleAvailability {
                role: ProcessRole::CpuSuspect,
                availability: ProcessCandidateAvailability::Unavailable,
            },
        ];
        app.on_window(window);

        let joined = draw_to_lines(&app).join("\n");
        assert!(joined.contains("unavailable: telemetry"));
    }

    #[test]
    fn terminal_safe_compact_candidates_truncate_to_the_column_width() {
        let candidate = &sample_window().current.cpu.process_candidates[0];
        let line = compact_candidate(candidate, 18);
        assert_eq!(line.chars().count(), 16);
        assert!(line.ends_with('…'));
        assert!(!line.contains('\n'));
        assert!(!line.contains('\x1b'));
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
