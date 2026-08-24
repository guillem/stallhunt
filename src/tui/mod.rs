//! Full-screen terminal UI for `watch` on a TTY.
//!
//! Piped text and `--json` never reach this module — `watch::run` only
//! calls [`run`] when the output format is `Text` and stdout is a
//! terminal (see `watch.rs`'s `run` function). This module owns the
//! raw-mode/alternate-screen terminal lifecycle and the interactive event
//! loop; `app` and `draw` stay pure so they are unit-testable without a
//! terminal.
//!
//! # Two-stage interrupt, without exiting from a signal-handler thread
//!
//! Once raw mode is active, a local keyboard Ctrl-C never reaches the
//! process as `SIGINT` — the terminal driver's `ISIG` handling is disabled
//! by raw mode, so it only ever arrives as a `crossterm` key event.
//! External `kill -INT <pid>` still reaches the process directly and is
//! caught by a `ctrlc` handler here, same as `watch::run_on`'s
//! `InterruptFlag`. Both sources feed one shared `AtomicU8` counter; unlike
//! `InterruptFlag`, the handler here never calls `std::process::exit`
//! itself, because `process::exit` skips `Drop` and would leave the
//! terminal in raw/alternate-screen state. Only the main loop — which owns
//! the terminal — restores it and exits, after observing the counter (it
//! wakes at least every 250ms via the event-poll timeout, so this adds no
//! meaningful latency versus a handler-side exit).

mod app;
mod draw;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event};

use crate::cli::WatchOptions;
use crate::observe::{observation_from_endpoints, read_end_endpoint, read_start_endpoint};
use crate::style;
use crate::watch::WatchTracker;

use app::App;
use draw::{detail_scroll_max, draw};

/// How often the event loop wakes up even with no input, so it notices an
/// external-signal interrupt and the next window's deadline promptly
/// without busy-looping ("stay cheap on a stressed system").
const POLL_TICK: Duration = Duration::from_millis(250);

/// RAII guard for the alternate screen / raw mode. `ratatui::try_init`
/// already installs a panic hook that restores the terminal before
/// re-raising, so a panic anywhere in the event loop or `draw` cannot leave
/// the terminal broken. `restore` is idempotent and safe to call before an
/// explicit `std::process::exit` (which skips `Drop`).
struct RestorationGuard<F: FnOnce()> {
    action: Option<F>,
}

impl<F: FnOnce()> RestorationGuard<F> {
    fn new(action: F) -> Self {
        Self {
            action: Some(action),
        }
    }

    fn restore(&mut self) {
        if let Some(action) = self.action.take() {
            action();
        }
    }
}

impl<F: FnOnce()> Drop for RestorationGuard<F> {
    fn drop(&mut self) {
        self.restore();
    }
}

struct TerminalGuard {
    terminal: Option<ratatui::DefaultTerminal>,
    restoration: RestorationGuard<Box<dyn FnOnce()>>,
}

impl TerminalGuard {
    fn new() -> io::Result<Self> {
        Ok(Self {
            terminal: Some(ratatui::try_init()?),
            restoration: RestorationGuard::new(Box::new(ratatui::restore)),
        })
    }

    fn terminal_mut(&mut self) -> &mut ratatui::DefaultTerminal {
        self.terminal
            .as_mut()
            .expect("TerminalGuard used after restore")
    }

    fn restore(&mut self) {
        if self.terminal.take().is_some() {
            self.restoration.restore();
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

pub fn run(options: &WatchOptions) -> io::Result<()> {
    let requested = Duration::from_millis(options.interval_ms);
    if requested.is_zero() {
        return Ok(());
    }

    // Unlike `watch::run_on`'s `InterruptFlag` (which only installs a
    // handler for unbounded runs, since a bounded legacy run has no
    // terminal state to protect and default SIGINT disposition is
    // harmless), this handler is installed unconditionally: once raw
    // mode/the alternate screen are active, an external `kill -INT` to a
    // `--count`-bounded TUI session must still restore the terminal before
    // the process exits, not fall through to default disposition. Local
    // keyboard Ctrl-C already reaches `App::handle_key` regardless of
    // `--count`; this only closes the external-signal gap for bounded
    // runs. It does not change normal bounded completion, which still
    // breaks on `options.count == Some(completed)` independent of the
    // interrupt counter.
    let interrupt = Arc::new(AtomicU8::new(0));
    let handler_flag = Arc::clone(&interrupt);
    ctrlc::set_handler(move || {
        handler_flag.fetch_add(1, Ordering::SeqCst);
    })
    .map_err(|error| io::Error::other(format!("install Ctrl-C handler: {error}")))?;

    let mut guard = TerminalGuard::new()?;
    let color = style::resolve_color(options.no_color, true);
    let mut app = App::new(color, Arc::clone(&interrupt));
    let size = guard.terminal_mut().size()?;
    app.set_viewport(size.width, size.height);
    app.update_detail_scroll_max(detail_scroll_max(&app, size.width, size.height));

    let mut start = read_start_endpoint();
    let mut tracker = WatchTracker::new();
    let mut completed = 0_u32;
    let mut deadline = Instant::now() + requested;
    let mut draining = false;

    loop {
        if app.interrupt_count() >= 2 {
            guard.restore();
            std::process::exit(130);
        }
        if app.quit {
            break;
        }
        if app.interrupt_count() >= 1 {
            draining = true;
        }
        if options.count == Some(completed) {
            break;
        }

        let now = Instant::now();
        let timeout = deadline.saturating_duration_since(now).min(POLL_TICK);
        if !timeout.is_zero() && event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => app.handle_key(key),
                Event::Resize(width, height) => app.set_viewport(width, height),
                _ => {}
            }
            let size = guard.terminal_mut().size()?;
            app.set_viewport(size.width, size.height);
            app.update_detail_scroll_max(detail_scroll_max(&app, size.width, size.height));
            guard.terminal_mut().draw(|frame| draw(frame, &app))?;
        }

        if Instant::now() >= deadline {
            let end = read_end_endpoint();
            let observation = observation_from_endpoints(&start, &end, requested);
            start = end;
            completed = completed.saturating_add(1);
            let mut window = tracker.ingest(&observation);
            window.count = options.count;
            window.interval_ms = options.interval_ms;
            app.on_window(window);
            let size = guard.terminal_mut().size()?;
            app.set_viewport(size.width, size.height);
            app.update_detail_scroll_max(detail_scroll_max(&app, size.width, size.height));
            guard.terminal_mut().draw(|frame| draw(frame, &app))?;
            deadline += requested;
            if draining {
                break;
            }
        }
    }

    guard.restore();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU8, Ordering};

    use super::RestorationGuard;

    #[test]
    fn restoration_guard_runs_once_on_explicit_restore_and_drop() {
        let calls = Arc::new(AtomicU8::new(0));
        let observed = Arc::clone(&calls);
        let mut guard = RestorationGuard::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
        });
        guard.restore();
        drop(guard);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn restoration_guard_runs_during_unwinding() {
        let calls = Arc::new(AtomicU8::new(0));
        let observed = Arc::clone(&calls);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = RestorationGuard::new(move || {
                observed.fetch_add(1, Ordering::SeqCst);
            });
            panic!("exercise unwind cleanup");
        }));
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
