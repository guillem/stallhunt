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
use crate::watch::{self, LifecycleState, ObservationStatus, ResourceSignal, WatchWindow};

use super::app::App;

const HISTORY_GLYPHS: [char; 5] = ['·', '▂', '▄', '▆', '█'];

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let detail_height = if app.expanded { 10 } else { 0 };
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(4),
        Constraint::Length(5),
        Constraint::Length(3),
        Constraint::Length(detail_height),
        Constraint::Length(1),
    ])
    .split(area);

    draw_header(frame, chunks[0], app);
    draw_lifecycle(frame, chunks[1], app);
    draw_current(frame, chunks[2], app);
    draw_history(frame, chunks[3], app);
    if app.expanded {
        draw_detail(frame, chunks[4], app);
    }
    draw_footer(frame, chunks[5]);

    if app.help {
        draw_help_overlay(frame, area);
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
    if finding.qualifiers.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "No additional context and limitations recorded for this finding.",
            Style::default().add_modifier(Modifier::DIM),
        ));
    } else {
        lines.push(Line::from(""));
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
        assert!(
            lines
                .iter()
                .any(|line| line.contains("no pressure findings this window"))
        );
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
        assert!(joined.contains("Context and limitations"));
        // The qualifier text word-wraps across TestBackend rows, so assert
        // on fragments from each end rather than one contiguous substring
        // that could straddle a wrap point.
        assert!(joined.contains("does not prove"));
        assert!(joined.contains("causality."));
        assert!(joined.contains("Host CPU utilization was at least 90%"));
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
