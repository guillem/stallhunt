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
    /// User intent for the detail pane.  Automatic follows the responsive
    /// layout (shown on a wide terminal, hidden on a compact one); an
    /// explicit choice survives a resize.
    pub detail_preference: DetailPreference,
    /// First wrapped detail line to show.  Rendering clamps this naturally
    /// when a new finding/window has less content.
    pub detail_scroll: u16,
    /// Last layout-derived maximum detail offset.  The event loop refreshes
    /// this before dispatching a scroll key, so End and PageDown cannot move
    /// beyond content that the current viewport can actually show.
    detail_max_scroll: u16,
    viewport: (u16, u16),
    pub help: bool,
    pub quit: bool,
    pub color: ColorMode,
    /// Shared with the `ctrlc` handler installed by `tui::run` for external
    /// signals: incremented on the first interrupt (drain then exit 0) and
    /// the second (restore then exit 130), from whichever source — a
    /// keypress or an external signal — reaches it first.
    interrupt: Arc<AtomicU8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailPreference {
    Automatic,
    ExplicitShown,
    ExplicitHidden,
}

impl App {
    pub fn new(color: ColorMode, interrupt: Arc<AtomicU8>) -> Self {
        Self {
            window: None,
            selected: 0,
            detail_preference: DetailPreference::Automatic,
            detail_scroll: 0,
            detail_max_scroll: 0,
            viewport: (80, 24),
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
        let selected_id = self.selected_finding().map(|finding| finding.id.clone());
        let len = window.lifecycle.len();
        self.window = Some(window);
        self.selected = selected_id
            .as_ref()
            .and_then(|id| {
                self.window
                    .as_ref()?
                    .lifecycle
                    .iter()
                    .position(|finding| finding.id == *id)
            })
            .unwrap_or_else(|| {
                if len == 0 {
                    0
                } else {
                    self.selected.min(len - 1)
                }
            });
        if selected_id.is_none_or(|id| {
            self.selected_finding()
                .is_none_or(|finding| finding.id != id)
        }) {
            self.detail_scroll = 0;
            self.detail_max_scroll = 0;
        }
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
            KeyCode::Enter | KeyCode::Char(' ') => self.toggle_detail(),
            KeyCode::PageUp => self.detail_scroll = self.detail_scroll.saturating_sub(5),
            KeyCode::PageDown => {
                self.detail_scroll = self
                    .detail_scroll
                    .saturating_add(5)
                    .min(self.detail_max_scroll)
            }
            KeyCode::Home => self.detail_scroll = 0,
            KeyCode::End => self.detail_scroll = self.detail_max_scroll(),
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
        let next = next as usize;
        if next != self.selected {
            self.selected = next;
            self.detail_scroll = 0;
            self.detail_max_scroll = 0;
        }
    }

    pub const fn detail_visible(&self, width: u16, height: u16) -> bool {
        match self.detail_preference {
            DetailPreference::Automatic => width >= 120 && height >= 30,
            DetailPreference::ExplicitShown => true,
            DetailPreference::ExplicitHidden => false,
        }
    }

    pub fn set_viewport(&mut self, width: u16, height: u16) {
        self.viewport = (width, height);
    }

    fn toggle_detail(&mut self) {
        self.detail_preference = if self.detail_visible(self.viewport.0, self.viewport.1) {
            DetailPreference::ExplicitHidden
        } else {
            DetailPreference::ExplicitShown
        };
        self.detail_scroll = 0;
        self.detail_max_scroll = 0;
    }

    pub const fn detail_max_scroll(&self) -> u16 {
        self.detail_max_scroll
    }

    /// Accept the current renderer's actual wrapped-content bound.
    pub fn update_detail_scroll_max(&mut self, max_scroll: u16) {
        self.detail_max_scroll = max_scroll;
        self.detail_scroll = self.detail_scroll.min(max_scroll);
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
    fn on_window_preserves_selected_identity_across_reordering() {
        let mut app = new_app();
        let first = three_finding_window();
        let selected_id = first.lifecycle[2].id.clone();
        app.on_window(first);
        app.selected = 2;
        app.detail_scroll = 4;
        let mut reordered = three_finding_window();
        reordered.lifecycle.swap(0, 2);
        app.on_window(reordered);
        assert_eq!(
            app.selected_finding().map(|finding| &finding.id),
            Some(&selected_id)
        );
        assert_eq!(app.detail_scroll, 4);
    }

    #[test]
    fn enter_and_space_make_an_explicit_detail_choice() {
        let mut app = new_app();
        assert_eq!(app.detail_preference, DetailPreference::Automatic);
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.detail_preference, DetailPreference::ExplicitShown);
        app.handle_key(key(KeyCode::Char(' ')));
        assert_eq!(app.detail_preference, DetailPreference::ExplicitHidden);
    }

    #[test]
    fn automatic_detail_follows_terminal_size_but_explicit_choice_survives_resize() {
        let mut app = new_app();
        assert!(app.detail_visible(120, 30));
        assert!(!app.detail_visible(119, 30));
        app.handle_key(key(KeyCode::Enter));
        assert!(app.detail_visible(160, 45));
        app.handle_key(key(KeyCode::Enter));
        assert!(!app.detail_visible(80, 24));
    }

    #[test]
    fn detail_scroll_keys_scroll_and_reset_on_selection() {
        let mut app = new_app();
        app.on_window(three_finding_window());
        app.update_detail_scroll_max(9);
        app.handle_key(key(KeyCode::PageDown));
        assert_eq!(app.detail_scroll, 5);
        app.handle_key(key(KeyCode::PageDown));
        assert_eq!(
            app.detail_scroll, 9,
            "PageDown clamps to the rendered bound"
        );
        app.handle_key(key(KeyCode::End));
        assert_eq!(app.detail_scroll, 9);
        app.handle_key(key(KeyCode::Home));
        assert_eq!(app.detail_scroll, 0);
        app.handle_key(key(KeyCode::PageDown));
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.detail_scroll, 0);
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
