//! Opt-in live validation of host-memory PSI using a caller-owned cgroup-v2
//! parent. The test only creates and configures one generated child beneath
//! that parent; it never changes the parent's limits or membership.

use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HUNT_TIMEOUT: Duration = Duration::from_secs(5);
const STRESS_TIMEOUT_SECS: u64 = 8;
const MEMORY_MAX_BYTES: u64 = 256 * 1024 * 1024;
const MEMORY_HIGH_BYTES: u64 = 128 * 1024 * 1024;
const ALLOCATOR_BYTES: u64 = 192 * 1024 * 1024;
static ACCEPTANCE_LOCK: Mutex<()> = Mutex::new(());
static CHILD_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct OwnedCgroup {
    path: PathBuf,
}

impl OwnedCgroup {
    fn create(parent: &Path) -> io::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0..32 {
            let sequence = CHILD_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                "bottleneck-memory-acceptance-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique memory-acceptance cgroup",
        ))
    }
}

impl Drop for OwnedCgroup {
    fn drop(&mut self) {
        // stress-ng workers may outlive the dispatcher. Kill only tasks still
        // in this uniquely named child, then wait for the cgroup to empty.
        terminate_cgroup_members(&self.path);
        let _ = fs::remove_dir(&self.path);
    }
}

fn terminate_cgroup_members(path: &Path) {
    let procs = path.join("cgroup.procs");
    for _ in 0..100 {
        let Ok(contents) = fs::read_to_string(&procs) else {
            return;
        };
        let pids: Vec<&str> = contents.split_whitespace().collect();
        if pids.is_empty() {
            return;
        }
        for pid in pids {
            let _ = Command::new("kill")
                .args(["-KILL", "--", pid])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        thread::sleep(Duration::from_millis(20));
    }
}

struct ChildCleanup {
    child: Child,
}

impl ChildCleanup {
    fn still_running(&mut self) -> io::Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }
}

impl Drop for ChildCleanup {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

fn normalized_parent() -> Result<PathBuf, String> {
    let value = env::var("BOTTLENECK_MEMORY_ACCEPTANCE_PATH")
        .map_err(|_| "BOTTLENECK_MEMORY_ACCEPTANCE_PATH is unset".to_owned())?;
    let path = Path::new(&value);
    if !path.is_absolute() || value.contains("..") {
        return Err("configured parent path must be absolute and normalized".into());
    }
    path.canonicalize()
        .map_err(|error| format!("cannot resolve configured parent: {error}"))
}

fn has_memory_controller(parent: &Path) -> Result<(), String> {
    let controllers = fs::read_to_string(parent.join("cgroup.controllers"))
        .map_err(|error| format!("cannot read cgroup.controllers: {error}"))?;
    if !controllers
        .split_ascii_whitespace()
        .any(|name| name == "memory")
    {
        return Err("memory is unavailable in the delegated parent".into());
    }
    let enabled = fs::read_to_string(parent.join("cgroup.subtree_control"))
        .map_err(|error| format!("cannot read cgroup.subtree_control: {error}"))?;
    if !enabled
        .split_ascii_whitespace()
        .any(|name| name == "memory")
    {
        return Err("memory is not enabled for children of the delegated parent".into());
    }
    Ok(())
}

fn configure_child(child: &OwnedCgroup) -> io::Result<()> {
    if !child.path.join("memory.max").is_file() || !child.path.join("memory.high").is_file() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the child cgroup lacks memory controller files",
        ));
    }
    fs::write(child.path.join("memory.max"), MEMORY_MAX_BYTES.to_string())?;
    fs::write(
        child.path.join("memory.high"),
        MEMORY_HIGH_BYTES.to_string(),
    )
}

fn stress_ng_supports_vm_options() -> bool {
    let bytes = ALLOCATOR_BYTES.to_string();
    match Command::new("stress-ng")
        .args([
            "--dry-run",
            "--vm",
            "1",
            "--vm-bytes",
            &bytes,
            "--vm-keep",
            "--vm-populate",
            "--timeout",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => true,
        Ok(status) => {
            eprintln!(
                "skipping memory acceptance: stress-ng rejected required VM options ({status})"
            );
            false
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            eprintln!("skipping memory acceptance: stress-ng is not installed");
            false
        }
        Err(error) => {
            eprintln!("skipping memory acceptance: cannot preflight stress-ng: {error}");
            false
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
        if let Some(status) = child.try_wait()? {
            break (status, false);
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
            "bottleneck hunt exceeded the acceptance-test timeout",
        ));
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[test]
#[ignore = "creates bounded memory pressure in a caller-owned delegated cgroup; run with BOTTLENECK_MEMORY_ACCEPTANCE_PATH=/absolute/cgroup/path cargo test --test memory_acceptance -- --ignored"]
fn delegated_memory_pressure_reports_host_psi_finding() {
    let _acceptance_guard = ACCEPTANCE_LOCK
        .lock()
        .expect("acceptance-test serialization lock should not be poisoned");
    if !cfg!(target_os = "linux") {
        eprintln!("skipping memory acceptance: Linux is required");
        return;
    }
    if fs::read_to_string("/proc/pressure/memory").is_err() {
        eprintln!("skipping memory acceptance: host memory PSI is unavailable or unreadable");
        return;
    }
    let parent = match normalized_parent().and_then(|path| {
        has_memory_controller(&path)?;
        Ok(path)
    }) {
        Ok(path) => path,
        Err(reason) => {
            eprintln!("skipping memory acceptance: {reason}");
            return;
        }
    };
    if !stress_ng_supports_vm_options() {
        return;
    }
    let cgroup = match OwnedCgroup::create(&parent) {
        Ok(cgroup) => cgroup,
        Err(error) => {
            eprintln!("skipping memory acceptance: cannot create child cgroup: {error}");
            return;
        }
    };
    if let Err(error) = configure_child(&cgroup) {
        eprintln!("skipping memory acceptance: cannot configure child cgroup: {error}");
        return;
    }

    let stress_timeout = STRESS_TIMEOUT_SECS.to_string();
    let allocator_bytes = ALLOCATOR_BYTES.to_string();
    let child_path = cgroup.path.to_string_lossy().into_owned();
    let child = match Command::new("/bin/sh")
        .args([
            "-c",
            "printf '%s\\n' \"$$\" > \"$1/cgroup.procs\" || exit 125; exec stress-ng --vm 1 --vm-bytes \"$2\" --vm-keep --vm-populate --timeout \"$3\"",
            "memory-acceptance",
            &child_path,
            &allocator_bytes,
            &stress_timeout,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            eprintln!("skipping memory acceptance: cannot start controlled allocator: {error}");
            return;
        }
    };
    let mut stress = ChildCleanup { child };
    thread::sleep(Duration::from_millis(250));
    if !stress.still_running().unwrap_or(false) {
        eprintln!("skipping memory acceptance: allocator exited before sampling");
        return;
    }

    let mut command = Command::new(env!("CARGO_BIN_EXE_bottleneck"));
    command.args(["hunt", "--duration", "2s", "--json"]);
    let output = run_with_timeout(command, HUNT_TIMEOUT)
        .expect("the bounded memory JSON hunt should complete before its timeout");
    assert!(
        stress
            .still_running()
            .expect("allocator liveness should remain observable"),
        "the controlled allocator exited during the observation window"
    );
    assert!(
        output.status.success(),
        "hunt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("hunt JSON should parse");
    if json["capabilities"]["memory_psi"]["state"].as_str() != Some("available") {
        eprintln!("skipping memory acceptance: memory PSI became unavailable: {json}");
        return;
    }
    let finding = json["findings"].as_array().and_then(|findings| {
        findings.iter().find(|finding| {
            matches!(
                finding["kind"].as_str(),
                Some(
                    "memory_pressure"
                        | "memory_reclaim_pressure"
                        | "memory_swap_pressure"
                        | "memory_possible_thrashing"
                )
            )
        })
    });
    let psi_some_fraction = json["observation"]["memory_psi"]["some_fraction"].as_f64();
    eprintln!(
        "memory acceptance: psi_some_fraction={} psi_window_us={} finding_kind={}",
        psi_some_fraction.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        json["observation"]["memory_psi_duration_us"]
            .as_u64()
            .map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        finding
            .and_then(|value| value["kind"].as_str())
            .unwrap_or("unavailable"),
    );
    assert!(
        psi_some_fraction.is_some_and(|value| value >= 0.01),
        "controlled memory pressure must produce at least 1% exact host memory PSI some: {json}"
    );
    assert!(
        finding.is_some(),
        "controlled memory pressure must report a PSI-backed harmful-memory finding: {json}"
    );
}
