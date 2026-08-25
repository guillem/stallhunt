//! The resident sampler: a background thread that keeps a rolling,
//! lifecycle-tracked view of host pressure so MCP tools can answer
//! "what has been constraining work recently?" instantly instead of
//! blocking on a fresh observation window.
//!
//! The loop mirrors `watch::run_on` but writes into shared state instead
//! of a terminal; it deliberately reuses only the public observation and
//! tracking seams so the analysis path stays identical to `stallhunt watch`.

use std::collections::VecDeque;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use crate::observe;
use crate::watch::{MAX_HISTORY_WINDOWS, WatchTracker, WatchWindow, WindowSignals};

/// One completed sampling window plus enough bookkeeping to describe the
/// sampler's coverage to an agent.
pub(crate) struct Snapshot {
    pub(crate) window: WatchWindow,
    pub(crate) completed_at: SystemTime,
    pub(crate) windows_completed: u64,
    /// Completion time of each retained window, aligned with the tracker's
    /// history ring; kept sampler-side so the shared watch types stay
    /// untouched.
    pub(crate) timestamps: VecDeque<(u32, SystemTime)>,
}

struct SamplerShared {
    latest: Mutex<Option<Snapshot>>,
    stop: AtomicBool,
}

pub(crate) struct Sampler {
    shared: Arc<SamplerShared>,
    handle: Option<JoinHandle<()>>,
    interval_ms: u64,
}

impl Sampler {
    /// Starts the sampler against live host telemetry.
    pub(crate) fn start(interval_ms: u64) -> Self {
        let interval = Duration::from_millis(interval_ms);
        let mut previous = observe::read_start_endpoint();
        let source = move || {
            let end = observe::read_end_endpoint();
            let observation = observe::observation_from_endpoints(&previous, &end, interval);
            previous = end;
            crate::watch::signals_from_observation(&observation)
        };
        Self::start_with_source(interval_ms, source)
    }

    /// Starts the sampler over an injected signal source; the seam unit
    /// tests use to drive deterministic windows without live telemetry.
    pub(crate) fn start_with_source(
        interval_ms: u64,
        mut source: impl FnMut() -> WindowSignals + Send + 'static,
    ) -> Self {
        let shared = Arc::new(SamplerShared {
            latest: Mutex::new(None),
            stop: AtomicBool::new(false),
        });
        let thread_shared = Arc::clone(&shared);
        let handle = std::thread::spawn(move || {
            let mut tracker = WatchTracker::new();
            let mut windows_completed = 0_u64;
            let mut timestamps: VecDeque<(u32, SystemTime)> = VecDeque::new();
            while sleep_unless_stopped(&thread_shared.stop, Duration::from_millis(interval_ms)) {
                // A panic inside `source()` or the tracker (e.g. a bug
                // triggered by an unusual host state) must not silently
                // freeze the sampler at its last snapshot forever with no
                // signal anything went wrong. Catch it, log it, and try
                // again next tick instead of letting the thread die —
                // `with_snapshot` callers have no way to detect a dead
                // thread short of this self-healing.
                let outcome = panic::catch_unwind(AssertUnwindSafe(&mut source));
                let signals = match outcome {
                    Ok(signals) => signals,
                    Err(payload) => {
                        eprintln!(
                            "stallhunt mcp: sampler tick panicked, skipping this window: {}",
                            panic_message(&payload)
                        );
                        continue;
                    }
                };
                let mut window = tracker.ingest_signals(signals);
                window.interval_ms = interval_ms;
                windows_completed = windows_completed.saturating_add(1);
                let completed_at = SystemTime::now();
                timestamps.push_back((window.index, completed_at));
                while timestamps.len() > MAX_HISTORY_WINDOWS {
                    timestamps.pop_front();
                }
                let snapshot = Snapshot {
                    window,
                    completed_at,
                    windows_completed,
                    timestamps: timestamps.clone(),
                };
                *lock_latest(&thread_shared.latest) = Some(snapshot);
            }
        });
        Self {
            shared,
            handle: Some(handle),
            interval_ms,
        }
    }

    pub(crate) fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    /// Runs `read` against the latest snapshot (None while warming up)
    /// under the lock, so callers never clone the window.
    pub(crate) fn with_snapshot<T>(&self, read: impl FnOnce(Option<&Snapshot>) -> T) -> T {
        read(lock_latest(&self.shared.latest).as_ref())
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            // A panicked sampler thread degrades to "no fresh snapshots";
            // the session itself keeps serving.
            let _ = handle.join();
        }
    }
}

/// Sleeps `interval` in short slices so a stop request is honored within
/// ~100ms even for long sampling windows. Returns false once stopped.
fn sleep_unless_stopped(stop: &AtomicBool, interval: Duration) -> bool {
    let mut remaining = interval;
    while !remaining.is_zero() {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let slice = remaining.min(Duration::from_millis(100));
        std::thread::sleep(slice);
        remaining = remaining.saturating_sub(slice);
    }
    !stop.load(Ordering::Relaxed)
}

/// A poisoned mutex only means a store was interrupted mid-write (e.g. by
/// the panic `catch_unwind` above already recovers from); the previous
/// snapshot is still the best answer available.
fn lock_latest(latest: &Mutex<Option<Snapshot>>) -> std::sync::MutexGuard<'_, Option<Snapshot>> {
    latest.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Best-effort extraction of a panic payload's message for the stderr log
/// line; panics conventionally carry a `&str` or `String`.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watch::test_support;
    use std::time::Instant;

    fn healthy_signals() -> WindowSignals {
        test_support::host_signals(
            test_support::healthy("cpu_no_harmful_pressure"),
            test_support::healthy("memory_no_harmful_pressure"),
            test_support::healthy("io_no_harmful_pressure"),
        )
    }

    fn wait_for_windows(sampler: &Sampler, at_least: u64) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let completed =
                sampler.with_snapshot(|snapshot| snapshot.map_or(0, |s| s.windows_completed));
            if completed >= at_least || Instant::now() > deadline {
                return completed;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn a_fresh_sampler_is_warming_up() {
        let sampler = Sampler::start_with_source(3_600_000, healthy_signals);
        assert!(sampler.with_snapshot(|snapshot| snapshot.is_none()));
    }

    #[test]
    fn snapshots_accumulate_and_bound_history_and_timestamps() {
        let sampler = Sampler::start_with_source(1, healthy_signals);
        let completed = wait_for_windows(&sampler, MAX_HISTORY_WINDOWS as u64 + 4);
        assert!(completed >= MAX_HISTORY_WINDOWS as u64 + 4);
        sampler.with_snapshot(|snapshot| {
            let snapshot = snapshot.expect("snapshot after ticks");
            assert!(snapshot.window.history.len() <= MAX_HISTORY_WINDOWS);
            assert!(snapshot.timestamps.len() <= MAX_HISTORY_WINDOWS);
            assert_eq!(snapshot.window.interval_ms, 1);
            assert_eq!(
                snapshot.timestamps.back().map(|(index, _)| *index),
                Some(snapshot.window.index)
            );
        });
    }

    #[test]
    fn a_panicking_tick_is_skipped_and_the_sampler_recovers_on_the_next_one() {
        // Regression test for review finding #1: a source() panic must not
        // silently freeze the sampler at a stale snapshot forever. Panic on
        // the first two calls, then succeed — the sampler should keep
        // ticking and eventually report a fresh snapshot despite the
        // panics (stderr carries the log line; this test only observes
        // that the thread is still alive and making progress).
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let source = {
            let calls = Arc::clone(&calls);
            move || {
                let count = calls.fetch_add(1, Ordering::SeqCst);
                if count < 2 {
                    panic!("synthetic sampler failure for test coverage");
                }
                healthy_signals()
            }
        };
        let previous_hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {})); // silence the panic backtrace in test output
        let sampler = Sampler::start_with_source(1, source);
        let completed = wait_for_windows(&sampler, 1);
        panic::set_hook(previous_hook);
        assert!(
            completed >= 1,
            "sampler should recover and complete a window after the panics"
        );
        assert!(calls.load(Ordering::SeqCst) >= 3);
    }

    #[test]
    fn dropping_a_long_interval_sampler_joins_promptly() {
        let sampler = Sampler::start_with_source(3_600_000, healthy_signals);
        let started = Instant::now();
        drop(sampler);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
