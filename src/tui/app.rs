//! Pure application state for the watch TUI.
//!
//! `handle_key` and `on_window` never touch I/O or the terminal, so they are
//! directly unit-testable without a `Terminal`/backend. `tui::mod` owns the
//! event loop and terminal; this module only owns state transitions.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::style::ColorMode;
use crate::watch::WatchWindow;

/// Application state for one `watch` TUI session.
pub struct App {
    pub window: Option<WatchWindow>,
    pub selected: usize,
    pub expanded: bool,
    pub help: bool,
    pub quit: bool,
    pub color: ColorMode,
    /// Shared with the `ctrlc` handler installed by `tui::run` for external
    /// signals: incremented on the first interrupt (drain then exit 0) and
    /// the second (restore then exit 130), from whichever source — a
    /// keypress or an external signal — reaches it first.
    interrupt: Arc<AtomicU8>,
}

impl App {
    pub fn new(color: ColorMode, interrupt: Arc<AtomicU8>) -> Self {
        Self {
            window: None,
            selected: 0,
            expanded: false,
            help: false,
            quit: false,
            color,
            interrupt,
        }
    }

    /// Number of interrupts observed so far (0, 1, or saturating at 2+).
    pub fn interrupt_count(&self) -> u8 {
        self.interrupt.load(Ordering::SeqCst)
    }

    pub fn lifecycle_len(&self) -> usize {
        self.window
            .as_ref()
            .map_or(0, |window| window.lifecycle.len())
    }

    /// Replace the current window and keep the selection in bounds.
    pub fn on_window(&mut self, window: WatchWindow) {
        let len = window.lifecycle.len();
        self.window = Some(window);
        self.selected = if len == 0 {
            0
        } else {
            self.selected.min(len - 1)
        };
    }

    /// Handle one key event. Ignores non-press kinds (key repeat/release,
    /// where the platform reports them) so a single physical keypress never
    /// double-triggers a toggle.
    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.interrupt.fetch_add(1, Ordering::SeqCst);
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Enter | KeyCode::Char(' ') => self.expanded = !self.expanded,
            KeyCode::Char('h') | KeyCode::Char('?') => self.help = !self.help,
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: i64) {
        let len = self.lifecycle_len();
        if len == 0 {
            self.selected = 0;
            return;
        }
        let current = self.selected as i64;
        let next = (current + delta).clamp(0, len as i64 - 1);
        self.selected = next as usize;
    }

    pub fn selected_finding(&self) -> Option<&crate::watch::TrackedFinding> {
        self.window
            .as_ref()
            .and_then(|window| window.lifecycle.get(self.selected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl_c() -> KeyEvent {
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
    }

    fn new_app() -> App {
        App::new(ColorMode::Never, Arc::new(AtomicU8::new(0)))
    }

    #[test]
    fn quit_key_sets_quit() {
        let mut app = new_app();
        assert!(!app.quit);
        app.handle_key(key(KeyCode::Char('q')));
        assert!(app.quit);
    }

    #[test]
    fn esc_also_quits() {
        let mut app = new_app();
        app.handle_key(key(KeyCode::Esc));
        assert!(app.quit);
    }

    #[test]
    fn selection_does_not_panic_or_move_on_empty_lifecycle() {
        let mut app = new_app();
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.selected, 0);
        app.handle_key(key(KeyCode::Up));
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn selection_clamps_within_lifecycle_bounds() {
        let mut app = new_app();
        app.on_window(three_finding_window());
        assert_eq!(app.selected, 0);
        app.handle_key(key(KeyCode::Up));
        assert_eq!(app.selected, 0, "must not go negative");
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.selected, 2, "must clamp at the last index");
        app.handle_key(key(KeyCode::Char('j')));
        assert_eq!(app.selected, 2);
        app.handle_key(key(KeyCode::Char('k')));
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn on_window_reclamps_selection_when_lifecycle_shrinks() {
        let mut app = new_app();
        app.on_window(three_finding_window());
        app.selected = 2;
        app.on_window(empty_window());
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn enter_and_space_toggle_expanded() {
        let mut app = new_app();
        assert!(!app.expanded);
        app.handle_key(key(KeyCode::Enter));
        assert!(app.expanded);
        app.handle_key(key(KeyCode::Char(' ')));
        assert!(!app.expanded);
    }

    #[test]
    fn h_and_question_mark_toggle_help() {
        let mut app = new_app();
        app.handle_key(key(KeyCode::Char('h')));
        assert!(app.help);
        app.handle_key(key(KeyCode::Char('?')));
        assert!(!app.help);
    }

    #[test]
    fn ctrl_c_increments_the_shared_interrupt_counter_and_does_not_quit_directly() {
        let mut app = new_app();
        app.handle_key(ctrl_c());
        assert_eq!(app.interrupt_count(), 1);
        assert!(
            !app.quit,
            "the event loop decides what to do with the interrupt count, not handle_key"
        );
        app.handle_key(ctrl_c());
        assert_eq!(app.interrupt_count(), 2);
    }

    #[test]
    fn release_events_are_ignored() {
        let mut app = new_app();
        let mut release = key(KeyCode::Char('q'));
        release.kind = KeyEventKind::Release;
        app.handle_key(release);
        assert!(!app.quit);
    }

    fn three_finding_window() -> WatchWindow {
        crate::watch::test_support::window_with_lifecycle_len(3)
    }

    fn empty_window() -> WatchWindow {
        crate::watch::test_support::window_with_lifecycle_len(0)
    }
}
