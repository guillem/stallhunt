//! Opt-in real-host acceptance coverage. This is deliberately ignored: it
//! creates bounded CPU pressure and is not suitable for a default test gate.

use std::fs;
use std::io::{self, Read};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

const MAX_LOGICAL_CPUS: usize = 8;
const HUNT_TIMEOUT: Duration = Duration::from_secs(8);
const SLEEPING_THREAD_COUNT: usize = 64;
static ACCEPTANCE_LOCK: Mutex<()> = Mutex::new(());

struct ChildCleanup {
    children: Vec<Child>,
}

impl ChildCleanup {
    fn new() -> Self {
        Self {
            children: Vec::new(),
        }
    }

    fn spawn_busy_worker(&mut self) -> io::Result<()> {
        // The shell replaces no children here: killing this PID stops its
        // in-process busy loop. This keeps ownership and cleanup unambiguous.
        let child = Command::new("/bin/sh")
            .args(["-c", "while :; do :; done"])
            .spawn()?;
        self.children.push(child);
        Ok(())
    }
}

impl Drop for ChildCleanup {
    fn drop(&mut self) {
        for child in &mut self.children {
            match child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
}

struct ThreadCleanup {
    stop: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl ThreadCleanup {
    fn spawn_sleeping(count: usize) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let threads = (0..count)
            .map(|_| {
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        thread::sleep(Duration::from_millis(20));
                    }
                })
            })
            .collect();
        Self { stop, threads }
    }
}

impl Drop for ThreadCleanup {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

fn run_with_timeout(mut command: Command, timeout: Duration) -> io::Result<Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().expect("stdout pipe should be present");
    let stderr = child.stderr.take().expect("stderr pipe should be present");
    let stdout_reader = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut stdout = stdout;
        stdout.read_to_end(&mut bytes)?;
        Ok(bytes)
    });
    let stderr_reader = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut stderr = stderr;
        stderr.read_to_end(&mut bytes)?;
        Ok(bytes)
    });
    let deadline = Instant::now() + timeout;
    let (status, timed_out) = loop {
        if child.try_wait()?.is_some() {
            break (child.wait()?, false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break (child.wait()?, true);
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| io::Error::other("stdout reader thread panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| io::Error::other("stderr reader thread panicked"))??;
    if timed_out {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stallhunt hunt exceeded the acceptance-test timeout",
        ));
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[test]
#[ignore = "creates bounded synthetic CPU pressure; run with cargo test --test cpu_acceptance -- --ignored"]
fn oversubscribed_cpu_reports_a_contention_finding() {
    let _acceptance_guard = ACCEPTANCE_LOCK
        .lock()
        .expect("acceptance-test serialization lock should not be poisoned");
    if !cfg!(target_os = "linux") {
        eprintln!("skipping CPU acceptance: Linux is required");
        return;
    }
    if fs::read_to_string("/proc/pressure/cpu").is_err() {
        eprintln!("skipping CPU acceptance: CPU PSI is unavailable or unreadable");
        return;
    }

    let logical_cpus = match thread::available_parallelism() {
        Ok(count) => count.get(),
        Err(error) => {
            eprintln!("skipping CPU acceptance: cannot determine available CPUs: {error}");
            return;
        }
    };
    if logical_cpus > MAX_LOGICAL_CPUS {
        eprintln!(
            "skipping CPU acceptance: {logical_cpus} available CPUs exceeds safe cap {MAX_LOGICAL_CPUS}"
        );
        return;
    }

    let mut workers = ChildCleanup::new();
    for _ in 0..=logical_cpus {
        if let Err(error) = workers.spawn_busy_worker() {
            eprintln!("skipping CPU acceptance: cannot start bounded worker: {error}");
            return;
        }
    }
    thread::sleep(Duration::from_millis(150));

    let mut command = Command::new(env!("CARGO_BIN_EXE_stallhunt"));
    command.args(["hunt", "--duration", "1s", "--json"]);
    let controller_started = Instant::now();
    let output = run_with_timeout(command, HUNT_TIMEOUT)
        .expect("the bounded JSON hunt should complete before its timeout");
    let controller_wall = controller_started.elapsed();
    assert!(
        output.status.success(),
        "hunt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("hunt JSON should parse during synthetic CPU pressure");
    let psi_state = json["capabilities"]["cpu_psi"]["state"].as_str();
    if psi_state != Some("available") {
        eprintln!(
            "skipping CPU acceptance: CPU PSI capability is unavailable ({psi_state:?}): {}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }
    let contention_finding = json["findings"].as_array().and_then(|findings| {
        findings
            .iter()
            .find(|finding| finding["kind"] == "cpu_scheduling_contention")
    });
    let requested_us = 1_000_000_u64;
    let psi_duration_us = json["observation"]["psi_duration_us"].as_u64();
    let psi_skew_us = psi_duration_us.map(|actual| actual.abs_diff(requested_us));
    let psi_some_fraction = json["observation"]["cpu_psi"]["some_fraction"].as_f64();
    let cpu_duration_us = json["observation"]["cpu_duration_us"].as_u64();
    let loadavg_total_tasks = json["observation"]["loadavg"]["total_tasks"].as_u64();
    let schedstat_tasks_read =
        json["observation"]["schedstat_collection_issues"]["tasks_read"].as_u64();
    let severity = contention_finding
        .and_then(|finding| finding["severity"].as_str())
        .unwrap_or("unavailable");
    let victim_count = contention_finding
        .and_then(|finding| finding["victims"].as_array())
        .map(Vec::len);
    let suspect_count = contention_finding
        .and_then(|finding| finding["suspects"].as_array())
        .map(Vec::len);
    eprintln!(
        "cpu acceptance measurement: controller_wall_ms={} psi_duration_us={} psi_skew_us={} psi_some_fraction={} cpu_duration_us={} loadavg_total_tasks={} schedstat_tasks_read={} finding_severity={} victim_count={} suspect_count={}",
        controller_wall.as_millis(),
        psi_duration_us.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        psi_skew_us.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        psi_some_fraction.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        cpu_duration_us.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        loadavg_total_tasks.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        schedstat_tasks_read.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        severity,
        victim_count.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        suspect_count.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
    );
    assert!(
        contention_finding.is_some(),
        "an oversubscribed run with available CPU PSI must report CPU contention (top-level status may be incomplete when other CPU collection failed); output: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    if json["capabilities"]["process_stat"] == "available" {
        assert!(
            suspect_count.is_some_and(|count| count > 0),
            "complete process CPU collection should identify at least one same-window suspect"
        );
    }
    if json["capabilities"]["process_schedstat"]["state"] == "available" {
        assert!(
            victim_count.is_some_and(|count| count > 0),
            "available scheduler accounting should identify runnable-delay victim candidates"
        );
    }
}

#[test]
#[ignore = "creates 64 bounded sleeping threads; run with cargo test --test cpu_acceptance -- --ignored"]
fn sleeping_thread_fanout_is_visible_to_scheduler_sampling() {
    let _acceptance_guard = ACCEPTANCE_LOCK
        .lock()
        .expect("acceptance-test serialization lock should not be poisoned");
    if !cfg!(target_os = "linux") {
        eprintln!("skipping sleeping-thread acceptance: Linux is required");
        return;
    }
    if fs::read_to_string("/proc/pressure/cpu").is_err() {
        eprintln!("skipping sleeping-thread acceptance: CPU PSI is unavailable or unreadable");
        return;
    }

    let _threads = ThreadCleanup::spawn_sleeping(SLEEPING_THREAD_COUNT);
    thread::sleep(Duration::from_millis(100));
    let mut command = Command::new(env!("CARGO_BIN_EXE_stallhunt"));
    command.args(["hunt", "--duration", "1s", "--json"]);
    let controller_started = Instant::now();
    let output = run_with_timeout(command, HUNT_TIMEOUT)
        .expect("the sleeping-thread JSON hunt should complete before its timeout");
    let controller_wall = controller_started.elapsed();
    assert!(
        output.status.success(),
        "hunt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("hunt JSON should parse during sleeping-thread sampling");
    if json["capabilities"]["cpu_psi"]["state"].as_str() != Some("available") {
        eprintln!("skipping sleeping-thread acceptance: CPU PSI capability is unavailable");
        return;
    }

    let requested_us = 1_000_000_u64;
    let psi_duration_us = json["observation"]["psi_duration_us"].as_u64();
    let psi_fraction = json["observation"]["cpu_psi"]["some_fraction"].as_f64();
    let tasks_read = json["observation"]["schedstat_collection_issues"]["tasks_read"].as_u64();
    let stable_tasks = json["observation"]["schedstat_collection_issues"]["stable_tasks"].as_u64();
    eprintln!(
        "sleeping-thread acceptance measurement: controller_wall_ms={} psi_duration_us={} psi_skew_us={} cpu_psi_some_fraction={} rss=unavailable schedstat_tasks_read={} stable_tasks={}",
        controller_wall.as_millis(),
        psi_duration_us.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        psi_duration_us.map_or_else(
            || "unavailable".to_owned(),
            |value| value.abs_diff(requested_us).to_string()
        ),
        psi_fraction.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        tasks_read.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        stable_tasks.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
    );

    if let Some("available" | "partial") =
        json["capabilities"]["process_schedstat"]["state"].as_str()
    {
        assert!(
            tasks_read.is_some_and(|value| value >= SLEEPING_THREAD_COUNT as u64),
            "schedstat task reads should reflect the owned thread fan-out: {json}"
        );
        assert!(
            stable_tasks.is_some_and(|value| value >= SLEEPING_THREAD_COUNT as u64),
            "stable schedstat tasks should reflect the owned thread fan-out: {json}"
        );
    }

    let finding_kind = json["findings"]
        .as_array()
        .and_then(|findings| findings.first())
        .and_then(|finding| finding["kind"].as_str());
    let fraction =
        psi_fraction.expect("available CPU PSI should provide an exact interval fraction");
    if fraction < 0.01 {
        assert_eq!(
            finding_kind,
            Some("cpu_no_meaningful_contention"),
            "many sleeping threads must not turn into a CPU contention verdict"
        );
    } else {
        eprintln!(
            "sleeping-thread acceptance: host CPU interference observed ({:.2}% CPU PSI some); no no-contention verdict asserted",
            fraction * 100.0
        );
    }
}
