//! The resident sampler: a background thread that keeps a rolling,
//! lifecycle-tracked view of host pressure so MCP tools can answer
//! "what has been constraining work recently?" instantly instead of
//! blocking on a fresh observation window.
//!
//! The loop mirrors `watch::run_on` but writes into shared state instead
//! of a terminal; it deliberately reuses only the public observation and
//! tracking seams so the analysis path stays identical to `stallhunt watch`.

use std::collections::VecDeque;
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
                let signals = source();
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

/// A poisoned mutex only means the sampler thread panicked mid-store; the
/// previous snapshot is still the best answer available.
fn lock_latest(latest: &Mutex<Option<Snapshot>>) -> std::sync::MutexGuard<'_, Option<Snapshot>> {
    latest.lock().unwrap_or_else(PoisonError::into_inner)
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
    fn dropping_a_long_interval_sampler_joins_promptly() {
        let sampler = Sampler::start_with_source(3_600_000, healthy_signals);
        let started = Instant::now();
        drop(sampler);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
