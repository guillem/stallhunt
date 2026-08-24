//! Rolling finding lifecycle for `watch`.
//!
//! Watch is not a generic resource monitor. It re-runs the existing analyzers
//! on contiguous rolling windows and classifies host/cgroup pressure findings
//! as new, persistent, or resolved. Healthy and insufficient observations do
//! not create tracked findings; missing data does not resolve an active one.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, IsTerminal, Write};
use std::thread;
use std::time::Duration;

use serde::Serialize;

use crate::analysis::{
    self, AssessmentKind, CgroupAssessmentKind, CgroupFinding, CgroupMechanism, CgroupResourceKind,
    Confidence, CpuFinding, IoAssessmentKind, IoFinding, MemoryAssessmentKind, MemoryFinding,
    ProcessCandidate, ProcessCandidateAvailability, ProcessCandidateEvidence, ProcessRole,
    ProcessRoleList, ProcessScope, Qualifier, Severity,
};
use crate::cli::{OutputFormat, WatchOptions};
#[cfg(test)]
use crate::cpu::ProcessKey;
use crate::cpu::sanitized_process_name;
use crate::observe::{
    HuntObservation, observation_from_endpoints, read_end_endpoint, read_start_endpoint,
};
use crate::style::{confidence_name, severity_name, state_label, status_label};

pub const MAX_HISTORY_WINDOWS: usize = 16;
pub const MAX_TRACKED_CGROUPS: usize = 16;
pub const WATCH_WINDOW_KIND: &str = "stallhunt.watch_window";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum FindingId {
    Cpu,
    Memory,
    Io,
    Cgroup {
        path: String,
        resource: CgroupResourceKind,
    },
}

impl FindingId {
    fn rank(&self) -> u8 {
        match self {
            Self::Cpu => 0,
            Self::Memory => 1,
            Self::Io => 2,
            Self::Cgroup { .. } => 3,
        }
    }

    fn is_cgroup(&self) -> bool {
        matches!(self, Self::Cgroup { .. })
    }
}

impl PartialOrd for FindingId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FindingId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank()
            .cmp(&other.rank())
            .then_with(|| match (self, other) {
                (
                    Self::Cgroup {
                        path: left_path,
                        resource: left_resource,
                    },
                    Self::Cgroup {
                        path: right_path,
                        resource: right_resource,
                    },
                ) => left_path.cmp(right_path).then_with(|| {
                    cgroup_resource_rank(*left_resource).cmp(&cgroup_resource_rank(*right_resource))
                }),
                _ => std::cmp::Ordering::Equal,
            })
    }
}

const fn cgroup_resource_rank(resource: CgroupResourceKind) -> u8 {
    match resource {
        CgroupResourceKind::Cpu => 0,
        CgroupResourceKind::Memory => 1,
        CgroupResourceKind::Io => 2,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    New,
    Persistent,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Pressure,
    Healthy,
    Unconfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessRoleAvailability {
    pub role: ProcessRole,
    pub availability: ProcessCandidateAvailability,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResourceSignal {
    pub status: ObservationStatus,
    pub severity: Severity,
    pub confidence: Confidence,
    pub kind: &'static str,
    pub summary: String,
    pub psi_some_fraction: Option<f64>,
    /// Candidates are only present for supported roles: CPU runnable-delay
    /// victims, CPU same-window consumers, and I/O same-window activity.
    /// Memory/cgroup roles and I/O victims deliberately remain unsupported.
    pub process_candidates: Vec<ProcessCandidate>,
    /// Additive machine-readable distinction between a supported empty role,
    /// incomplete telemetry, and a role not assessed outside pressure.
    pub process_candidate_availability: Vec<ProcessRoleAvailability>,
    /// Exact analyzer-owned lists for this resource's victim/suspect roles.
    pub process_role_lists: Vec<ProcessRoleList>,
    /// Full qualifier messages backing this signal, for the watch TUI's
    /// detail pane. Not part of the watch JSON stream contract (ADR-0008):
    /// that stream is a compact lifecycle document, not a full-evidence
    /// document, so this field is serialize-skipped.
    #[serde(skip_serializing)]
    pub qualifiers: Vec<Qualifier>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WindowSignals {
    pub cpu: ResourceSignal,
    pub memory: ResourceSignal,
    pub io: ResourceSignal,
    pub cgroups: Vec<(FindingId, ResourceSignal)>,
    pub observed_cgroup_paths: BTreeSet<String>,
    pub ranking_omitted_cgroup_ids: BTreeSet<FindingId>,
    pub cgroup_tracking_capped: bool,
    /// Exact analyzer-owned scoped role lists for this window.  The legacy
    /// flat candidate fields remain for compatibility only.
    pub process_scopes: Vec<ProcessScope>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrackedFinding {
    pub id: FindingId,
    pub state: LifecycleState,
    pub consecutive_windows: u32,
    pub confirmed: bool,
    pub severity: Severity,
    pub previous_severity: Option<Severity>,
    pub confidence: Confidence,
    pub kind: &'static str,
    pub summary: String,
    pub psi_some_fraction: Option<f64>,
    pub process_candidates: Vec<ProcessCandidate>,
    /// `true` means candidates were retained from the last confirmed pressure
    /// window because this finding is unconfirmed or resolved in this window.
    pub process_candidates_stale: bool,
    pub process_role_lists: Vec<ProcessRoleList>,
    /// Full qualifier messages, for the watch TUI's detail pane. Not part
    /// of the watch JSON stream contract — see `ResourceSignal::qualifiers`.
    #[serde(skip_serializing)]
    pub qualifiers: Vec<Qualifier>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryEvent {
    pub id: FindingId,
    pub state: LifecycleState,
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryEntry {
    pub window_index: u32,
    pub events: Vec<HistoryEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WatchWindow {
    pub index: u32,
    pub count: Option<u32>,
    pub interval_ms: u64,
    pub lifecycle: Vec<TrackedFinding>,
    pub current: WindowSignals,
    pub history: Vec<HistoryEntry>,
}

#[derive(Debug, Clone)]
struct ActiveRecord {
    consecutive_windows: u32,
    severity: Severity,
    confidence: Confidence,
    kind: &'static str,
    summary: String,
    psi_some_fraction: Option<f64>,
    process_candidates: Vec<ProcessCandidate>,
    process_role_lists: Vec<ProcessRoleList>,
    qualifiers: Vec<Qualifier>,
}

fn stale_role_lists(lists: &[ProcessRoleList]) -> Vec<ProcessRoleList> {
    lists
        .iter()
        .cloned()
        .map(|mut list| {
            list.stale = true;
            list
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WatchTracker {
    index: u32,
    active: BTreeMap<FindingId, ActiveRecord>,
    history: VecDeque<HistoryEntry>,
}

impl WatchTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest(&mut self, observation: &HuntObservation) -> WatchWindow {
        self.ingest_signals(signals_from_observation(observation))
    }

    pub fn ingest_signals(&mut self, signals: WindowSignals) -> WatchWindow {
        self.index = self.index.saturating_add(1);
        let mut current_pressure = BTreeMap::new();
        current_pressure.insert(FindingId::Cpu, signals.cpu.clone());
        current_pressure.insert(FindingId::Memory, signals.memory.clone());
        current_pressure.insert(FindingId::Io, signals.io.clone());
        for (id, signal) in &signals.cgroups {
            current_pressure.insert(id.clone(), signal.clone());
        }

        let mut lifecycle = Vec::new();
        let mut still_active = BTreeMap::new();

        for (id, record) in &self.active {
            match status_for(
                id,
                &current_pressure,
                &signals.observed_cgroup_paths,
                &signals.ranking_omitted_cgroup_ids,
            ) {
                ObservationStatus::Pressure => {
                    let signal = current_pressure
                        .get(id)
                        .expect("pressure status requires a current signal");
                    let consecutive_windows = record.consecutive_windows.saturating_add(1);
                    let previous_severity =
                        (signal.severity != record.severity).then_some(record.severity);
                    lifecycle.push(TrackedFinding {
                        id: id.clone(),
                        state: LifecycleState::Persistent,
                        consecutive_windows,
                        confirmed: true,
                        severity: signal.severity,
                        previous_severity,
                        confidence: signal.confidence,
                        kind: signal.kind,
                        summary: signal.summary.clone(),
                        psi_some_fraction: signal.psi_some_fraction,
                        process_candidates: signal.process_candidates.clone(),
                        process_candidates_stale: false,
                        process_role_lists: signal.process_role_lists.clone(),
                        qualifiers: signal.qualifiers.clone(),
                    });
                    still_active.insert(
                        id.clone(),
                        ActiveRecord {
                            consecutive_windows,
                            severity: signal.severity,
                            confidence: signal.confidence,
                            kind: signal.kind,
                            summary: signal.summary.clone(),
                            psi_some_fraction: signal.psi_some_fraction,
                            process_candidates: signal.process_candidates.clone(),
                            process_role_lists: signal.process_role_lists.clone(),
                            qualifiers: signal.qualifiers.clone(),
                        },
                    );
                }
                ObservationStatus::Unconfirmed => {
                    lifecycle.push(TrackedFinding {
                        id: id.clone(),
                        state: LifecycleState::Persistent,
                        consecutive_windows: record.consecutive_windows,
                        confirmed: false,
                        severity: record.severity,
                        previous_severity: None,
                        confidence: record.confidence,
                        kind: record.kind,
                        summary: record.summary.clone(),
                        psi_some_fraction: record.psi_some_fraction,
                        process_candidates: record.process_candidates.clone(),
                        process_candidates_stale: true,
                        process_role_lists: stale_role_lists(&record.process_role_lists),
                        qualifiers: record.qualifiers.clone(),
                    });
                    still_active.insert(id.clone(), record.clone());
                }
                ObservationStatus::Healthy => {
                    let signal = current_pressure.get(id);
                    lifecycle.push(TrackedFinding {
                        id: id.clone(),
                        state: LifecycleState::Resolved,
                        consecutive_windows: record.consecutive_windows,
                        confirmed: true,
                        severity: record.severity,
                        previous_severity: None,
                        confidence: signal
                            .map(|signal| signal.confidence)
                            .unwrap_or(record.confidence),
                        kind: record.kind,
                        summary: record.summary.clone(),
                        psi_some_fraction: signal.and_then(|signal| signal.psi_some_fraction),
                        process_candidates: record.process_candidates.clone(),
                        process_candidates_stale: true,
                        process_role_lists: stale_role_lists(&record.process_role_lists),
                        qualifiers: record.qualifiers.clone(),
                    });
                }
            }
        }

        let mut cgroup_tracking_capped = signals.cgroup_tracking_capped;
        for (id, signal) in &current_pressure {
            if signal.status != ObservationStatus::Pressure || self.active.contains_key(id) {
                continue;
            }
            if id.is_cgroup() {
                let live_cgroups = still_active.keys().filter(|id| id.is_cgroup()).count();
                if live_cgroups >= MAX_TRACKED_CGROUPS {
                    cgroup_tracking_capped = true;
                    continue;
                }
            }
            lifecycle.push(TrackedFinding {
                id: id.clone(),
                state: LifecycleState::New,
                consecutive_windows: 1,
                confirmed: true,
                severity: signal.severity,
                previous_severity: None,
                confidence: signal.confidence,
                kind: signal.kind,
                summary: signal.summary.clone(),
                psi_some_fraction: signal.psi_some_fraction,
                process_candidates: signal.process_candidates.clone(),
                process_candidates_stale: false,
                process_role_lists: signal.process_role_lists.clone(),
                qualifiers: signal.qualifiers.clone(),
            });
            still_active.insert(
                id.clone(),
                ActiveRecord {
                    consecutive_windows: 1,
                    severity: signal.severity,
                    confidence: signal.confidence,
                    kind: signal.kind,
                    summary: signal.summary.clone(),
                    psi_some_fraction: signal.psi_some_fraction,
                    process_candidates: signal.process_candidates.clone(),
                    process_role_lists: signal.process_role_lists.clone(),
                    qualifiers: signal.qualifiers.clone(),
                },
            );
        }

        lifecycle.sort_by(|left, right| {
            state_rank(left.state)
                .cmp(&state_rank(right.state))
                .then_with(|| left.id.cmp(&right.id))
        });

        let history_events = lifecycle
            .iter()
            .map(|finding| HistoryEvent {
                id: finding.id.clone(),
                state: finding.state,
                severity: finding.severity,
            })
            .collect();
        self.history.push_back(HistoryEntry {
            window_index: self.index,
            events: history_events,
        });
        while self.history.len() > MAX_HISTORY_WINDOWS {
            self.history.pop_front();
        }
        self.active = still_active;

        let mut current = signals;
        current.cgroup_tracking_capped = cgroup_tracking_capped;
        WatchWindow {
            index: self.index,
            count: None,
            interval_ms: 0,
            lifecycle,
            current,
            history: self.history.iter().cloned().collect(),
        }
    }
}

fn status_for(
    id: &FindingId,
    current: &BTreeMap<FindingId, ResourceSignal>,
    observed_cgroup_paths: &BTreeSet<String>,
    ranking_omitted_cgroup_ids: &BTreeSet<FindingId>,
) -> ObservationStatus {
    if let Some(signal) = current.get(id) {
        return signal.status;
    }
    if ranking_omitted_cgroup_ids.contains(id) {
        return ObservationStatus::Unconfirmed;
    }
    if let FindingId::Cgroup { path, .. } = id {
        if observed_cgroup_paths.contains(path) {
            return ObservationStatus::Healthy;
        }
    }
    ObservationStatus::Unconfirmed
}

const fn state_rank(state: LifecycleState) -> u8 {
    match state {
        LifecycleState::New => 0,
        LifecycleState::Persistent => 1,
        LifecycleState::Resolved => 2,
    }
}

/// Entry point for `watch`. A Text-format run on a terminal hands off to the
/// full-screen TUI (`crate::tui`); every other combination (piped text,
/// `--json` on or off a terminal) keeps the original append-only rendering,
/// unaffected by the TUI's existence.
pub fn run(options: &WatchOptions) -> io::Result<()> {
    let stdout = io::stdout();
    if options.output == OutputFormat::Text && stdout.is_terminal() {
        return crate::tui::run(options);
    }
    let mut writer = stdout.lock();
    run_on(&mut writer, options)
}

fn write_window(
    writer: &mut dyn Write,
    options: &WatchOptions,
    window: &WatchWindow,
) -> io::Result<()> {
    write!(writer, "{}", render_window(options, window)?)?;
    writer.flush()?;
    Ok(())
}

fn run_on(writer: &mut dyn Write, options: &WatchOptions) -> io::Result<()> {
    let requested = Duration::from_millis(options.interval_ms);
    if requested.is_zero() {
        return Ok(());
    }

    let interrupt = InterruptFlag::install(options.count.is_none());
    let mut start = read_start_endpoint();
    let mut tracker = WatchTracker::new();
    let mut completed = 0_u32;
    loop {
        if options.count == Some(completed) || interrupt.raised() {
            break;
        }
        thread::sleep(requested);
        let end = read_end_endpoint();
        let observation = observation_from_endpoints(&start, &end, requested);
        start = end;
        completed = completed.saturating_add(1);
        let mut window = tracker.ingest(&observation);
        window.count = options.count;
        window.interval_ms = options.interval_ms;
        write_window(writer, options, &window).or_else(|error| {
            if error.kind() == io::ErrorKind::BrokenPipe {
                Ok(())
            } else {
                Err(error)
            }
        })?;
        if options.count == Some(completed) {
            break;
        }
    }
    Ok(())
}

/// Cooperative SIGINT flag. When installed, the default SIGINT termination is
/// replaced by a flag so an in-flight `watch` window can complete and be
/// written before the loop exits. Without installation (bounded `--count`
/// runs), SIGINT keeps its default terminating behavior.
struct InterruptFlag {
    raised: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl InterruptFlag {
    fn install(enabled: bool) -> Self {
        let raised = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        if enabled {
            let handler_flag = std::sync::Arc::clone(&raised);
            let _ = ctrlc::set_handler(move || {
                if handler_flag.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    // `ctrlc` keeps this handler installed, so explicitly
                    // preserve the default shell-visible exit status when the
                    // operator interrupts a second time rather than waiting
                    // for a potentially five-minute window to drain.
                    std::process::exit(130);
                }
            });
        }
        Self { raised }
    }

    fn raised(&self) -> bool {
        self.raised.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Render one watch window for the piped-text/`--json` path. A Text-format
/// run on a terminal never reaches this function — `watch::run` hands off
/// to `crate::tui::run` before the collection loop starts.
pub fn render_window(
    options: &WatchOptions,
    window: &WatchWindow,
) -> Result<String, serde_json::Error> {
    match options.output {
        OutputFormat::Json => watch_json(window),
        OutputFormat::Text => Ok(watch_text(window)),
    }
}

fn watch_text(window: &WatchWindow) -> String {
    let mut output = String::new();
    output.push_str(&format!("--- window {} ---\n", window.index));
    output.push_str(&format!(
        "WATCH  window {}  interval {}\n\n",
        window_index_label(window),
        format_ms(window.interval_ms)
    ));
    output.push_str("Lifecycle\n");
    if window.lifecycle.is_empty() {
        output.push_str("  (no pressure findings this window)\n");
    } else {
        for finding in &window.lifecycle {
            output.push_str(&format!(
                "  {:<11} {}  {}  {}{}\n",
                state_label(finding.state),
                id_label(&finding.id),
                finding.kind,
                severity_name(finding.severity),
                psi_suffix(finding.psi_some_fraction)
            ));
            if finding.state == LifecycleState::Persistent {
                output.push_str(&format!(
                    "              {} consecutive window(s)",
                    finding.consecutive_windows
                ));
                if let Some(previous) = finding.previous_severity {
                    output.push_str(&format!("; was {}", severity_name(previous)));
                }
                if !finding.confirmed {
                    output.push_str("; unconfirmed this window");
                }
                output.push('\n');
            }
        }
    }
    if window.current.cgroup_tracking_capped {
        output.push_str(
            "  Cgroup tracking is capped; additional scoped pressure was not added to lifecycle.\n",
        );
    }
    output.push_str("\nCurrent window\n");
    output.push_str(&current_line("CPU", &window.current.cpu));
    output.push_str(&current_line("Memory", &window.current.memory));
    output.push_str(&current_line("I/O", &window.current.io));
    let cgroup_pressure: Vec<_> = window
        .current
        .cgroups
        .iter()
        .filter(|(_, signal)| signal.status == ObservationStatus::Pressure)
        .take(8)
        .collect();
    if cgroup_pressure.is_empty() {
        output.push_str("  Cgroup   no scoped pressure ranked this window\n");
    } else {
        for (id, signal) in cgroup_pressure {
            output.push_str(&format!(
                "  {:<8} {}  {}  {}{}\n",
                "Cgroup",
                id_label(id),
                signal.kind,
                severity_name(signal.severity),
                psi_suffix(signal.psi_some_fraction)
            ));
        }
    }
    output.push_str("\nProcesses\n");
    process_role_text(
        &mut output,
        "CPU victims",
        ProcessRole::CpuVictim,
        &window.current.cpu,
        "runnable-delay",
    );
    process_role_text(
        &mut output,
        "CPU suspects",
        ProcessRole::CpuSuspect,
        &window.current.cpu,
        "same-window CPU-consumption",
    );
    process_role_text(
        &mut output,
        "Memory victims",
        ProcessRole::MemoryVictim,
        &window.current.memory,
        "taskstats delay or major-fault fallback",
    );
    process_role_text(
        &mut output,
        "Memory suspects",
        ProcessRole::MemorySuspect,
        &window.current.memory,
        "positive RSS growth",
    );
    process_role_text(
        &mut output,
        "I/O victims",
        ProcessRole::IoVictim,
        &window.current.io,
        "taskstats/procfs block-I/O delay",
    );
    process_role_text(
        &mut output,
        "I/O suspects",
        ProcessRole::IoSuspect,
        &window.current.io,
        "same-window process-I/O",
    );
    output.push_str(
        "  Qualification: CPU and I/O suspects are same-window correlation; this does not prove causality. CPU victims are runnable-delay candidates, not confirmed harm.\n",
    );
    for finding in window
        .lifecycle
        .iter()
        .filter(|finding| finding.process_candidates_stale)
    {
        output.push_str(&format!(
            "  Last observed for {} ({}):\n",
            id_label(&finding.id),
            if finding.state == LifecycleState::Resolved {
                "resolved"
            } else {
                "unconfirmed"
            }
        ));
        for candidate in &finding.process_candidates {
            output.push_str(&format!("    {}\n", process_candidate_text(candidate)));
        }
        if finding.process_candidates.is_empty() {
            for list in &finding.process_role_lists {
                let state = match list.availability {
                    ProcessCandidateAvailability::Available => "no positive candidates",
                    ProcessCandidateAvailability::UnavailableOrIncomplete => {
                        "unavailable or incomplete"
                    }
                    ProcessCandidateAvailability::NotAssessed => "not assessed",
                };
                output.push_str(&format!("    {:?}: {state} (stale)\n", list.role));
            }
        }
    }
    output.push_str("\nRecent history (oldest first)\n");
    if window.history.is_empty() {
        output.push_str("  (none)\n");
    } else {
        for entry in &window.history {
            if entry.events.is_empty() {
                output.push_str(&format!(
                    "  #{:<3} (no pressure findings)\n",
                    entry.window_index
                ));
            } else {
                let events = entry
                    .events
                    .iter()
                    .map(|event| {
                        format!(
                            "{} {} {}",
                            id_label(&event.id),
                            state_label(event.state).to_ascii_lowercase(),
                            severity_name(event.severity)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" · ");
                output.push_str(&format!("  #{:<3} {events}\n", entry.window_index));
            }
        }
    }
    output.push_str(
        "\nLifecycle tracks pressure findings only. Healthy windows resolve a previous finding; missing data does not.\n",
    );
    output
}

fn process_role_text(
    output: &mut String,
    title: &str,
    role: ProcessRole,
    signal: &ResourceSignal,
    evidence: &str,
) {
    let candidates: Vec<_> = signal
        .process_candidates
        .iter()
        .filter(|candidate| candidate.role == role)
        .collect();
    if candidates.is_empty() {
        let availability = signal
            .process_candidate_availability
            .iter()
            .find(|value| value.role == role)
            .map(|value| value.availability)
            .unwrap_or_else(|| role_availability(signal.status, role, &signal.qualifiers));
        let state = match availability {
            ProcessCandidateAvailability::Available => "no positive candidates ranked",
            ProcessCandidateAvailability::UnavailableOrIncomplete => "unavailable or incomplete",
            ProcessCandidateAvailability::NotAssessed => {
                "not assessed (no current pressure finding)"
            }
        };
        output.push_str(&format!("  {title}: {state} ({evidence})\n"));
    } else {
        let partial = signal
            .process_role_lists
            .iter()
            .find(|list| list.role == role)
            .is_some_and(|list| {
                list.completeness == crate::analysis::ProcessRoleCompleteness::Partial
            });
        output.push_str(&format!(
            "  {title}{}:\n",
            if partial { " (partial)" } else { "" }
        ));
        for candidate in candidates {
            output.push_str(&format!("    {}\n", process_candidate_text(candidate)));
        }
    }
}

fn attribution_incomplete(role: ProcessRole, qualifiers: &[Qualifier]) -> bool {
    let kinds = match role {
        ProcessRole::CpuVictim => {
            ["attribution_unavailable", "victim_attribution_limited"].as_slice()
        }
        ProcessRole::CpuSuspect => {
            ["attribution_unavailable", "suspect_attribution_limited"].as_slice()
        }
        ProcessRole::MemoryVictim | ProcessRole::MemorySuspect | ProcessRole::IoVictim => {
            ["attribution_unavailable"].as_slice()
        }
        ProcessRole::IoSuspect => ["process_io_unavailable", "process_io_partial"].as_slice(),
    };
    qualifiers
        .iter()
        .any(|qualifier| kinds.contains(&qualifier.kind))
}

fn process_candidate_text(candidate: &ProcessCandidate) -> String {
    let name = sanitized_process_name(&candidate.name);
    let evidence = match candidate.evidence {
        ProcessCandidateEvidence::RunnableDelay {
            runnable_wait_ns,
            runnable_delay_fraction,
            stable_task_count,
            ..
        } => format!(
            "{runnable_wait_ns}ns runnable delay ({:.2}% of window; {stable_task_count} stable task(s))",
            runnable_delay_fraction * 100.0
        ),
        ProcessCandidateEvidence::CpuConsumption {
            cpu_fraction_of_one,
            cpu_ticks,
        } => format!(
            "{:.1}% of one CPU ({cpu_ticks} CPU ticks; same window only)",
            cpu_fraction_of_one * 100.0
        ),
        ProcessCandidateEvidence::IoActivity {
            read_bytes,
            write_bytes,
            cancelled_write_bytes,
            known_accounted_bytes,
        } => format!(
            "{known_accounted_bytes} accounted bytes (read {}; charged write {}; cancelled write {}; same window only)",
            optional_u64(read_bytes),
            optional_u64(write_bytes),
            optional_u64(cancelled_write_bytes)
        ),
        ProcessCandidateEvidence::TaskstatsCpuDelay { cpu_delay_ns } => {
            format!("{cpu_delay_ns}ns taskstats CPU delay")
        }
        ProcessCandidateEvidence::MemoryDelay {
            largest_component,
            largest_delay_ns,
            ..
        } => {
            format!("{largest_delay_ns}ns taskstats {largest_component} delay")
        }
        ProcessCandidateEvidence::MajorFaults { major_faults } => {
            format!("{major_faults} major faults")
        }
        ProcessCandidateEvidence::RssGrowth { rss_growth_bytes } => {
            format!("{rss_growth_bytes}B RSS growth")
        }
        ProcessCandidateEvidence::BlockIoDelay {
            block_io_delay_ns,
            procfs_block_io_delay_ticks,
        } => block_io_delay_ns
            .filter(|value| *value > 0)
            .map(|value| format!("{value}ns taskstats block-I/O delay"))
            .or_else(|| {
                procfs_block_io_delay_ticks
                    .filter(|value| *value > 0)
                    .map(|value| format!("{value} procfs block-I/O ticks"))
            })
            .unwrap_or_else(|| "block-I/O delay unavailable".into()),
    };
    format!(
        "{name} [{}] — {evidence} ({}; {})",
        candidate.key.pid,
        confidence_name(candidate.confidence),
        candidate.label
    )
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

fn current_line(label: &str, signal: &ResourceSignal) -> String {
    format!(
        "  {:<8} {:<12} {}{}\n",
        label,
        status_label(signal.status),
        severity_name(signal.severity),
        psi_suffix(signal.psi_some_fraction)
    )
}

fn watch_json(window: &WatchWindow) -> Result<String, serde_json::Error> {
    let current_cgroups: Vec<CgroupCurrentJson<'_>> = window
        .current
        .cgroups
        .iter()
        .filter(|(_, signal)| signal.status == ObservationStatus::Pressure)
        .map(|(id, signal)| CgroupCurrentJson { id, signal })
        .collect();
    let payload = WatchWindowJson {
        kind: WATCH_WINDOW_KIND,
        schema_version: 2,
        tool_version: env!("CARGO_PKG_VERSION"),
        window_index: window.index,
        window_count: window.count,
        interval_ms: window.interval_ms,
        lifecycle: &window.lifecycle,
        current: CurrentJson {
            cpu: &window.current.cpu,
            memory: &window.current.memory,
            io: &window.current.io,
            cgroups: current_cgroups,
            cgroup_tracking_capped: window.current.cgroup_tracking_capped,
        },
        history: &window.history,
        process_scopes: window.current.process_scopes.clone(),
    };
    Ok(format!("{}\n", serde_json::to_string(&payload)?))
}

#[derive(Serialize)]
struct WatchWindowJson<'a> {
    kind: &'static str,
    schema_version: u8,
    tool_version: &'a str,
    window_index: u32,
    window_count: Option<u32>,
    interval_ms: u64,
    lifecycle: &'a [TrackedFinding],
    current: CurrentJson<'a>,
    history: &'a [HistoryEntry],
    process_scopes: Vec<ProcessScope>,
}

#[derive(Serialize)]
struct CurrentJson<'a> {
    cpu: &'a ResourceSignal,
    memory: &'a ResourceSignal,
    io: &'a ResourceSignal,
    cgroups: Vec<CgroupCurrentJson<'a>>,
    cgroup_tracking_capped: bool,
}

#[derive(Serialize)]
struct CgroupCurrentJson<'a> {
    id: &'a FindingId,
    #[serde(flatten)]
    signal: &'a ResourceSignal,
}

pub(crate) fn window_index_label(window: &WatchWindow) -> String {
    match window.count {
        Some(count) => format!("{}/{}", window.index, count),
        None => window.index.to_string(),
    }
}

pub(crate) fn id_label(id: &FindingId) -> String {
    match id {
        FindingId::Cpu => "CPU".into(),
        FindingId::Memory => "Memory".into(),
        FindingId::Io => "I/O".into(),
        FindingId::Cgroup { path, resource } => {
            let resource = match resource {
                CgroupResourceKind::Cpu => "cpu",
                CgroupResourceKind::Memory => "memory",
                CgroupResourceKind::Io => "io",
            };
            format!("{path} ({resource})")
        }
    }
}

pub(crate) fn psi_suffix(fraction: Option<f64>) -> String {
    match fraction {
        Some(value) => format!("  PSI {:.2}%", value * 100.0),
        None => String::new(),
    }
}

pub(crate) fn format_ms(duration_ms: u64) -> String {
    if duration_ms % 60_000 == 0 && duration_ms >= 60_000 {
        format!("{}m", duration_ms / 60_000)
    } else if duration_ms % 1_000 == 0 {
        format!("{}s", duration_ms / 1_000)
    } else {
        format!("{duration_ms}ms")
    }
}

pub fn signals_from_observation(observation: &HuntObservation) -> WindowSignals {
    let mut cpu = cpu_signal(observation);
    let mut memory = memory_signal(observation);
    let mut io = io_signal(observation);
    let mut process_scopes = vec![analysis::host_process_scope(
        observation.cpu.as_ref().ok(),
        observation
            .io
            .as_ref()
            .and_then(|value| value.processes.as_ref().ok()),
        (cpu.status == ObservationStatus::Pressure).then_some(cpu.confidence),
        (memory.status == ObservationStatus::Pressure).then_some(memory.confidence),
        (io.status == ObservationStatus::Pressure).then_some(io.confidence),
    )];
    process_scopes.extend(analysis::cgroup_process_scopes(
        observation
            .cgroup
            .as_ref()
            .and_then(|value| value.observation.as_ref().ok()),
        observation.cpu.as_ref().ok(),
        observation
            .io
            .as_ref()
            .and_then(|value| value.processes.as_ref().ok()),
    ));
    let roles = &process_scopes[0].roles;
    cpu.process_role_lists =
        roles_for_resource(roles, ProcessRole::CpuVictim, ProcessRole::CpuSuspect);
    memory.process_role_lists =
        roles_for_resource(roles, ProcessRole::MemoryVictim, ProcessRole::MemorySuspect);
    io.process_role_lists =
        roles_for_resource(roles, ProcessRole::IoVictim, ProcessRole::IoSuspect);
    populate_role_candidates(&mut cpu);
    populate_role_candidates(&mut memory);
    populate_role_candidates(&mut io);
    let cgroup_signals = cgroup_signals(observation, &process_scopes);
    WindowSignals {
        cpu,
        memory,
        io,
        cgroups: cgroup_signals.pressured,
        observed_cgroup_paths: cgroup_signals.observed_cgroup_paths,
        ranking_omitted_cgroup_ids: cgroup_signals.ranking_omitted_cgroup_ids,
        cgroup_tracking_capped: cgroup_signals.capped,
        process_scopes,
    }
}

fn populate_role_candidates(signal: &mut ResourceSignal) {
    signal.process_candidates = signal
        .process_role_lists
        .iter()
        .flat_map(|list| list.candidates.iter().cloned())
        .collect();
    signal.process_candidate_availability = signal
        .process_role_lists
        .iter()
        .map(|list| ProcessRoleAvailability {
            role: list.role,
            availability: list.availability,
        })
        .collect();
}

fn roles_for_resource(
    roles: &[ProcessRoleList],
    first: ProcessRole,
    second: ProcessRole,
) -> Vec<ProcessRoleList> {
    roles
        .iter()
        .filter(|role| role.role == first || role.role == second)
        .cloned()
        .collect()
}

fn cpu_signal(observation: &HuntObservation) -> ResourceSignal {
    let analysis =
        analysis::analyze_cpu(observation.psi.as_ref().ok(), observation.cpu.as_ref().ok());
    match analysis.findings.first() {
        Some(finding) => cpu_finding_signal(finding),
        None => unconfirmed_signal("cpu_assessment_unavailable", "CPU PSI is unavailable."),
    }
}

fn cpu_finding_signal(finding: &CpuFinding) -> ResourceSignal {
    let status = match finding.kind {
        AssessmentKind::CpuContention => ObservationStatus::Pressure,
        AssessmentKind::CpuNoMeaningfulContention => ObservationStatus::Healthy,
        AssessmentKind::InsufficientObservation => ObservationStatus::Unconfirmed,
    };
    ResourceSignal {
        status,
        severity: finding.severity,
        confidence: finding.resource_confidence,
        kind: match finding.kind {
            AssessmentKind::CpuContention => "cpu_scheduling_contention",
            AssessmentKind::CpuNoMeaningfulContention => "cpu_no_meaningful_contention",
            AssessmentKind::InsufficientObservation => "insufficient_observation",
        },
        summary: finding.summary.clone(),
        psi_some_fraction: Some(finding.evidence.psi_some_fraction),
        process_candidates: cpu_candidates(finding),
        process_candidate_availability: cpu_role_availability(status, &finding.qualifiers),
        process_role_lists: Vec::new(),
        qualifiers: finding.qualifiers.clone(),
    }
}

fn cpu_candidates(finding: &CpuFinding) -> Vec<ProcessCandidate> {
    let mut candidates = Vec::with_capacity(finding.victims.len() + finding.suspects.len());
    candidates.extend(finding.victims.iter().map(|victim| ProcessCandidate {
        role: ProcessRole::CpuVictim,
        key: victim.key,
        name: victim.name.clone(),
        confidence: victim.confidence,
        label: victim.label,
        evidence: ProcessCandidateEvidence::RunnableDelay {
            runnable_wait_ns: victim.runnable_wait_ns,
            runnable_delay_fraction: victim.runnable_delay_fraction,
            stable_task_count: victim.stable_task_count,
            taskstats_cpu_delay_ns: None,
        },
    }));
    candidates.extend(finding.suspects.iter().map(|suspect| ProcessCandidate {
        role: ProcessRole::CpuSuspect,
        key: suspect.key,
        name: suspect.name.clone(),
        confidence: suspect.confidence,
        label: suspect.label,
        evidence: ProcessCandidateEvidence::CpuConsumption {
            cpu_fraction_of_one: suspect.cpu_fraction_of_one,
            cpu_ticks: suspect.cpu_ticks,
        },
    }));
    candidates
}

fn cpu_role_availability(
    status: ObservationStatus,
    qualifiers: &[Qualifier],
) -> Vec<ProcessRoleAvailability> {
    [ProcessRole::CpuVictim, ProcessRole::CpuSuspect]
        .into_iter()
        .map(|role| ProcessRoleAvailability {
            role,
            availability: role_availability(status, role, qualifiers),
        })
        .collect()
}

fn memory_signal(observation: &HuntObservation) -> ResourceSignal {
    let Some(memory) = observation.memory.as_ref() else {
        return unconfirmed_signal(
            "memory_assessment_unavailable",
            "Memory observation was not collected.",
        );
    };
    let analysis = analysis::analyze_memory(memory.psi.as_ref().ok(), memory.context.as_ref().ok());
    match analysis.findings.first() {
        Some(finding) => memory_finding_signal(finding),
        None => unconfirmed_signal(
            "memory_assessment_unavailable",
            "Memory PSI is unavailable.",
        ),
    }
}

fn memory_finding_signal(finding: &MemoryFinding) -> ResourceSignal {
    let status = match finding.kind {
        MemoryAssessmentKind::NoHarmfulPressure => ObservationStatus::Healthy,
        MemoryAssessmentKind::Pressure
        | MemoryAssessmentKind::ReclaimPressure
        | MemoryAssessmentKind::SwapPressure
        | MemoryAssessmentKind::PossibleThrashing => ObservationStatus::Pressure,
        MemoryAssessmentKind::InsufficientObservation => ObservationStatus::Unconfirmed,
    };
    ResourceSignal {
        status,
        severity: finding.severity,
        confidence: finding.resource_confidence,
        kind: memory_kind_name(finding.kind),
        summary: finding.summary.clone(),
        psi_some_fraction: Some(finding.evidence.psi_some_fraction),
        process_candidates: Vec::new(),
        process_candidate_availability: Vec::new(),
        process_role_lists: Vec::new(),
        qualifiers: finding.qualifiers.clone(),
    }
}

const fn memory_kind_name(kind: MemoryAssessmentKind) -> &'static str {
    match kind {
        MemoryAssessmentKind::NoHarmfulPressure => "memory_no_harmful_pressure",
        MemoryAssessmentKind::Pressure => "memory_pressure",
        MemoryAssessmentKind::ReclaimPressure => "memory_reclaim_pressure",
        MemoryAssessmentKind::SwapPressure => "memory_swap_pressure",
        MemoryAssessmentKind::PossibleThrashing => "memory_possible_thrashing",
        MemoryAssessmentKind::InsufficientObservation => "memory_insufficient_observation",
    }
}

fn io_signal(observation: &HuntObservation) -> ResourceSignal {
    let Some(io) = observation.io.as_ref() else {
        return unconfirmed_signal(
            "io_assessment_unavailable",
            "I/O observation was not collected.",
        );
    };
    let analysis = analysis::analyze_io(
        io.psi.as_ref().ok(),
        io.diskstats.as_ref().ok(),
        io.processes.as_ref().ok(),
    );
    match analysis.findings.first() {
        Some(finding) => io_finding_signal(finding),
        None => unconfirmed_signal("io_assessment_unavailable", "I/O PSI is unavailable."),
    }
}

fn io_finding_signal(finding: &IoFinding) -> ResourceSignal {
    let status = match finding.kind {
        IoAssessmentKind::Pressure => ObservationStatus::Pressure,
        IoAssessmentKind::NoMeaningfulContention => ObservationStatus::Healthy,
        IoAssessmentKind::InsufficientObservation => ObservationStatus::Unconfirmed,
    };
    ResourceSignal {
        status,
        severity: finding.severity,
        confidence: finding.resource_confidence,
        kind: match finding.kind {
            IoAssessmentKind::Pressure => "io_pressure",
            IoAssessmentKind::NoMeaningfulContention => "io_no_meaningful_contention",
            IoAssessmentKind::InsufficientObservation => "io_insufficient_observation",
        },
        summary: finding.summary.clone(),
        psi_some_fraction: Some(finding.evidence.psi_some_fraction),
        process_candidates: io_candidates(finding),
        process_candidate_availability: io_role_availability(status, &finding.qualifiers),
        process_role_lists: Vec::new(),
        qualifiers: finding.qualifiers.clone(),
    }
}

fn io_candidates(finding: &IoFinding) -> Vec<ProcessCandidate> {
    finding
        .process_suspects
        .iter()
        .map(|suspect| ProcessCandidate {
            role: ProcessRole::IoSuspect,
            key: suspect.key,
            name: suspect.name.clone(),
            confidence: suspect.confidence,
            label: suspect.label,
            evidence: ProcessCandidateEvidence::IoActivity {
                read_bytes: suspect.read_bytes,
                write_bytes: suspect.write_bytes,
                cancelled_write_bytes: suspect.cancelled_write_bytes,
                known_accounted_bytes: suspect.known_accounted_bytes,
            },
        })
        .collect()
}

fn io_role_availability(
    status: ObservationStatus,
    qualifiers: &[Qualifier],
) -> Vec<ProcessRoleAvailability> {
    vec![ProcessRoleAvailability {
        role: ProcessRole::IoSuspect,
        availability: role_availability(status, ProcessRole::IoSuspect, qualifiers),
    }]
}

fn role_availability(
    status: ObservationStatus,
    role: ProcessRole,
    qualifiers: &[Qualifier],
) -> ProcessCandidateAvailability {
    if status != ObservationStatus::Pressure {
        return ProcessCandidateAvailability::NotAssessed;
    }
    if attribution_incomplete(role, qualifiers) {
        ProcessCandidateAvailability::UnavailableOrIncomplete
    } else {
        ProcessCandidateAvailability::Available
    }
}

struct CgroupSignalBundle {
    pressured: Vec<(FindingId, ResourceSignal)>,
    observed_cgroup_paths: BTreeSet<String>,
    ranking_omitted_cgroup_ids: BTreeSet<FindingId>,
    capped: bool,
}

fn cgroup_signals(
    observation: &HuntObservation,
    process_scopes: &[ProcessScope],
) -> CgroupSignalBundle {
    let Some(cgroup) = observation.cgroup.as_ref() else {
        return CgroupSignalBundle {
            pressured: Vec::new(),
            observed_cgroup_paths: BTreeSet::new(),
            ranking_omitted_cgroup_ids: BTreeSet::new(),
            capped: false,
        };
    };
    let Ok(cgroup) = cgroup.observation.as_ref() else {
        return CgroupSignalBundle {
            pressured: Vec::new(),
            observed_cgroup_paths: BTreeSet::new(),
            ranking_omitted_cgroup_ids: BTreeSet::new(),
            capped: false,
        };
    };
    let observed_cgroup_paths = cgroup
        .groups
        .iter()
        .map(|group| group.path.clone())
        .collect();
    let analysis = analysis::analyze_cgroups(Some(cgroup));
    let mut pressured = analysis
        .findings
        .into_iter()
        .filter_map(|finding| cgroup_pressure_signal(finding, process_scopes))
        .collect::<Vec<_>>();
    pressured.sort_by(|left, right| {
        severity_rank(right.1.severity)
            .cmp(&severity_rank(left.1.severity))
            .then_with(|| left.0.cmp(&right.0))
    });
    let capped = pressured.len() > MAX_TRACKED_CGROUPS;
    let ranking_omitted_cgroup_ids = pressured
        .iter()
        .skip(MAX_TRACKED_CGROUPS)
        .map(|(id, _)| id.clone())
        .collect();
    pressured.truncate(MAX_TRACKED_CGROUPS);
    CgroupSignalBundle {
        pressured,
        observed_cgroup_paths,
        ranking_omitted_cgroup_ids,
        capped,
    }
}

fn cgroup_pressure_signal(
    finding: CgroupFinding,
    process_scopes: &[ProcessScope],
) -> Option<(FindingId, ResourceSignal)> {
    if finding.kind != CgroupAssessmentKind::Pressure {
        return None;
    }
    let roles = process_scopes
        .iter()
        .find(|scope| matches!(&scope.scope, crate::analysis::ProcessScopeKind::Cgroup { path } if path == &finding.path))
        .map(|scope| match finding.resource {
            CgroupResourceKind::Cpu => roles_for_resource(&scope.roles, ProcessRole::CpuVictim, ProcessRole::CpuSuspect),
            CgroupResourceKind::Memory => roles_for_resource(&scope.roles, ProcessRole::MemoryVictim, ProcessRole::MemorySuspect),
            CgroupResourceKind::Io => roles_for_resource(&scope.roles, ProcessRole::IoVictim, ProcessRole::IoSuspect),
        })
        .unwrap_or_default();
    let process_candidates = roles
        .iter()
        .flat_map(|list| list.candidates.iter().cloned())
        .collect();
    let process_candidate_availability = roles
        .iter()
        .map(|list| ProcessRoleAvailability {
            role: list.role,
            availability: list.availability,
        })
        .collect();
    Some((
        FindingId::Cgroup {
            path: finding.path,
            resource: finding.resource,
        },
        ResourceSignal {
            status: ObservationStatus::Pressure,
            severity: finding.severity,
            confidence: finding.resource_confidence,
            kind: cgroup_watch_kind(finding.resource, finding.mechanism),
            summary: finding.summary,
            psi_some_fraction: finding.evidence.psi_some_fraction,
            process_candidates,
            process_candidate_availability,
            process_role_lists: roles,
            qualifiers: finding.qualifiers,
        },
    ))
}

const fn cgroup_watch_kind(
    resource: CgroupResourceKind,
    mechanism: Option<CgroupMechanism>,
) -> &'static str {
    match (resource, mechanism) {
        (CgroupResourceKind::Memory, Some(CgroupMechanism::Reclaim)) => {
            "cgroup_memory_reclaim_pressure"
        }
        (CgroupResourceKind::Memory, Some(CgroupMechanism::Swap)) => "cgroup_memory_swap_pressure",
        (CgroupResourceKind::Memory, Some(CgroupMechanism::PossibleThrashing)) => {
            "cgroup_memory_possible_thrashing"
        }
        (CgroupResourceKind::Cpu, Some(CgroupMechanism::CpuQuotaThrottle)) => {
            "cgroup_cpu_quota_throttle_pressure"
        }
        (CgroupResourceKind::Cpu, _) => "cgroup_cpu_pressure",
        (CgroupResourceKind::Memory, _) => "cgroup_memory_pressure",
        (CgroupResourceKind::Io, _) => "cgroup_io_pressure",
    }
}

fn unconfirmed_signal(kind: &'static str, summary: &str) -> ResourceSignal {
    ResourceSignal {
        status: ObservationStatus::Unconfirmed,
        severity: Severity::None,
        confidence: Confidence::Low,
        kind,
        summary: summary.to_owned(),
        psi_some_fraction: None,
        process_candidates: Vec::new(),
        process_candidate_availability: Vec::new(),
        process_role_lists: Vec::new(),
        qualifiers: Vec::new(),
    }
}

pub(crate) const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::None => 0,
        Severity::Low => 1,
        Severity::Moderate => 2,
        Severity::High => 3,
        Severity::Severe => 4,
    }
}

/// Fixture builders shared by `watch`'s own tests and by `crate::tui`'s
/// tests (which build `App`/`WatchWindow` state without a terminal). Kept
/// `pub(crate)` — not just `#[cfg(test)]` `fn`s inside `mod tests` — so
/// other test modules in the crate can reuse them instead of re-deriving
/// fixture construction.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn pressure(kind: &'static str, severity: Severity, psi: f64) -> ResourceSignal {
        pressure_with_qualifiers(kind, severity, psi, Vec::new())
    }

    pub(crate) fn pressure_with_qualifiers(
        kind: &'static str,
        severity: Severity,
        psi: f64,
        qualifiers: Vec<Qualifier>,
    ) -> ResourceSignal {
        ResourceSignal {
            status: ObservationStatus::Pressure,
            severity,
            confidence: Confidence::High,
            kind,
            summary: format!("{kind} {:.2}%", psi * 100.0),
            psi_some_fraction: Some(psi),
            process_candidates: Vec::new(),
            process_candidate_availability: Vec::new(),
            process_role_lists: Vec::new(),
            qualifiers,
        }
    }

    pub(crate) fn healthy(kind: &'static str) -> ResourceSignal {
        ResourceSignal {
            status: ObservationStatus::Healthy,
            severity: Severity::None,
            confidence: Confidence::High,
            kind,
            summary: format!("{kind} healthy"),
            psi_some_fraction: Some(0.001),
            process_candidates: Vec::new(),
            process_candidate_availability: Vec::new(),
            process_role_lists: Vec::new(),
            qualifiers: Vec::new(),
        }
    }

    pub(crate) fn unconfirmed() -> ResourceSignal {
        unconfirmed_signal("insufficient_observation", "short window")
    }

    pub(crate) fn host_signals(
        cpu: ResourceSignal,
        memory: ResourceSignal,
        io: ResourceSignal,
    ) -> WindowSignals {
        WindowSignals {
            cpu,
            memory,
            io,
            cgroups: Vec::new(),
            observed_cgroup_paths: BTreeSet::new(),
            ranking_omitted_cgroup_ids: BTreeSet::new(),
            cgroup_tracking_capped: false,
            process_scopes: Vec::new(),
        }
    }

    pub(crate) fn decorate(window: &mut WatchWindow, interval_ms: u64, count: Option<u32>) {
        window.interval_ms = interval_ms;
        window.count = count;
    }

    /// A window with a NEW CPU-pressure finding (carrying two qualifiers,
    /// so the TUI detail pane has real text to show), a healthy memory/I/O
    /// pair, and one scoped cgroup pressure finding. Used by
    /// `crate::tui`'s draw/app tests.
    pub(crate) fn sample_window() -> WatchWindow {
        let mut tracker = WatchTracker::new();
        let qualifiers = vec![
            Qualifier {
                kind: "same_window_correlation",
                message: "Suspects consumed CPU in the same window; this correlation does not prove causality.",
            },
            Qualifier {
                kind: "high_utilization_context",
                message: "Host CPU utilization was at least 90%; this is supporting context, not the contention verdict.",
            },
        ];
        let mut cpu =
            pressure_with_qualifiers("cpu_scheduling_contention", Severity::High, 0.2, qualifiers);
        cpu.process_candidates = vec![
            ProcessCandidate {
                role: ProcessRole::CpuVictim,
                key: ProcessKey {
                    pid: 4812,
                    start_time_ticks: 10,
                },
                name: "postgres\nworker".into(),
                confidence: Confidence::High,
                label: "observed_runnable_delay_victim_candidate",
                evidence: ProcessCandidateEvidence::RunnableDelay {
                    runnable_wait_ns: 500_000_000,
                    runnable_delay_fraction: 0.05,
                    stable_task_count: 2,
                    taskstats_cpu_delay_ns: None,
                },
            },
            ProcessCandidate {
                role: ProcessRole::CpuSuspect,
                key: ProcessKey {
                    pid: 9231,
                    start_time_ticks: 11,
                },
                name: "rustc".into(),
                confidence: Confidence::Medium,
                label: "concurrent_cpu_consumer",
                evidence: ProcessCandidateEvidence::CpuConsumption {
                    cpu_fraction_of_one: 1.25,
                    cpu_ticks: 125,
                },
            },
        ];
        let mut io = pressure("io_pressure", Severity::Moderate, 0.08);
        io.process_candidates = vec![ProcessCandidate {
            role: ProcessRole::IoSuspect,
            key: ProcessKey {
                pid: 7712,
                start_time_ticks: 12,
            },
            name: "restic".into(),
            confidence: Confidence::Medium,
            label: "same_window_process_io_activity",
            evidence: ProcessCandidateEvidence::IoActivity {
                read_bytes: Some(4_096),
                write_bytes: Some(2_048),
                cancelled_write_bytes: None,
                known_accounted_bytes: 6_144,
            },
        }];
        let mut signals = host_signals(cpu, healthy("memory_no_harmful_pressure"), io);
        let cgroup_id = FindingId::Cgroup {
            path: "/system.slice/db.service".to_owned(),
            resource: CgroupResourceKind::Io,
        };
        signals.cgroups.push((
            cgroup_id,
            pressure("cgroup_io_pressure", Severity::Moderate, 0.08),
        ));
        // A single ingest already produces one history entry (itself) and
        // a NEW-state lifecycle row, which is what draw/app tests exercise.
        let mut window = tracker.ingest_signals(signals);
        decorate(&mut window, 2_000, None);
        window
    }

    /// A window whose lifecycle has exactly `len` tracked findings — CPU,
    /// then memory, then I/O, then (if more are needed) distinct cgroup
    /// paths — for selection/clamping tests that only care about count.
    pub(crate) fn window_with_lifecycle_len(len: usize) -> WatchWindow {
        let mut tracker = WatchTracker::new();
        let mut signals = host_signals(unconfirmed(), unconfirmed(), unconfirmed());
        if len >= 1 {
            signals.cpu = pressure("cpu_scheduling_contention", Severity::High, 0.2);
        }
        if len >= 2 {
            signals.memory = pressure("memory_pressure", Severity::Moderate, 0.1);
        }
        if len >= 3 {
            signals.io = pressure("io_pressure", Severity::Low, 0.05);
        }
        for extra in 3..len {
            signals.cgroups.push((
                FindingId::Cgroup {
                    path: format!("/extra-{extra}.scope"),
                    resource: CgroupResourceKind::Cpu,
                },
                pressure("cgroup_cpu_pressure", Severity::Low, 0.05),
            ));
        }
        let window = tracker.ingest_signals(signals);
        assert_eq!(
            window.lifecycle.len(),
            len,
            "test_support::window_with_lifecycle_len built the wrong count"
        );
        window
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::analysis::CgroupEvidence;
    use crate::cgroup::{CgroupFileState, CgroupResource};

    #[test]
    fn contention_becomes_new_then_persistent_then_resolved() {
        let mut tracker = WatchTracker::new();
        let first = tracker.ingest_signals(host_signals(
            pressure("cpu_scheduling_contention", Severity::High, 0.2),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(first.lifecycle.len(), 1);
        assert_eq!(first.lifecycle[0].id, FindingId::Cpu);
        assert_eq!(first.lifecycle[0].state, LifecycleState::New);
        assert_eq!(first.lifecycle[0].consecutive_windows, 1);

        let second = tracker.ingest_signals(host_signals(
            pressure("cpu_scheduling_contention", Severity::Severe, 0.4),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(second.lifecycle[0].state, LifecycleState::Persistent);
        assert_eq!(second.lifecycle[0].consecutive_windows, 2);
        assert_eq!(second.lifecycle[0].previous_severity, Some(Severity::High));
        assert_eq!(second.lifecycle[0].severity, Severity::Severe);

        let third = tracker.ingest_signals(host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(third.lifecycle[0].state, LifecycleState::Resolved);
        assert_eq!(third.lifecycle[0].consecutive_windows, 2);

        let fourth = tracker.ingest_signals(host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert!(fourth.lifecycle.is_empty());
    }

    #[test]
    fn lifecycle_retains_exact_two_resource_role_lists_and_marks_stale() {
        let roles = vec![
            ProcessRoleList {
                role: ProcessRole::CpuVictim,
                availability: ProcessCandidateAvailability::Available,
                completeness: crate::analysis::ProcessRoleCompleteness::Complete,
                stale: false,
                candidates: Vec::new(),
            },
            ProcessRoleList {
                role: ProcessRole::CpuSuspect,
                availability: ProcessCandidateAvailability::UnavailableOrIncomplete,
                completeness: crate::analysis::ProcessRoleCompleteness::Unavailable,
                stale: false,
                candidates: Vec::new(),
            },
        ];
        let mut tracker = WatchTracker::new();
        let mut confirmed = pressure("cpu_scheduling_contention", Severity::High, 0.2);
        confirmed.process_role_lists = roles.clone();
        let first = tracker.ingest_signals(host_signals(
            confirmed.clone(),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(first.lifecycle[0].process_role_lists, roles);

        let refreshed = tracker.ingest_signals(host_signals(
            confirmed,
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(refreshed.lifecycle[0].process_role_lists.len(), 2);
        assert!(
            refreshed.lifecycle[0]
                .process_role_lists
                .iter()
                .all(|list| !list.stale)
        );

        let unconfirmed = tracker.ingest_signals(host_signals(
            unconfirmed(),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(unconfirmed.lifecycle[0].process_role_lists.len(), 2);
        assert!(
            unconfirmed.lifecycle[0]
                .process_role_lists
                .iter()
                .all(|list| list.stale)
        );
        assert_eq!(
            unconfirmed.lifecycle[0].process_role_lists[1].availability,
            ProcessCandidateAvailability::UnavailableOrIncomplete
        );

        let resolved = tracker.ingest_signals(host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(resolved.lifecycle[0].state, LifecycleState::Resolved);
        assert_eq!(resolved.lifecycle[0].process_role_lists.len(), 2);
        assert!(
            resolved.lifecycle[0]
                .process_role_lists
                .iter()
                .all(|list| list.stale)
        );
    }

    #[test]
    fn healthy_windows_do_not_create_tracked_findings() {
        let mut tracker = WatchTracker::new();
        let window = tracker.ingest_signals(host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert!(window.lifecycle.is_empty());
        assert_eq!(window.current.cpu.status, ObservationStatus::Healthy);
    }

    #[test]
    fn unconfirmed_windows_do_not_resolve_or_extend_persistence() {
        let mut tracker = WatchTracker::new();
        tracker.ingest_signals(host_signals(
            pressure("cpu_scheduling_contention", Severity::Moderate, 0.08),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        let unconfirmed_window =
            tracker.ingest_signals(host_signals(unconfirmed(), unconfirmed(), unconfirmed()));
        assert_eq!(unconfirmed_window.lifecycle.len(), 1);
        assert_eq!(
            unconfirmed_window.lifecycle[0].state,
            LifecycleState::Persistent
        );
        assert!(!unconfirmed_window.lifecycle[0].confirmed);
        assert_eq!(unconfirmed_window.lifecycle[0].consecutive_windows, 1);

        let resolved = tracker.ingest_signals(host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(resolved.lifecycle[0].state, LifecycleState::Resolved);
        assert_eq!(resolved.lifecycle[0].consecutive_windows, 1);
    }

    #[test]
    fn resources_and_cgroup_scopes_are_tracked_independently() {
        let mut tracker = WatchTracker::new();
        let cgroup = FindingId::Cgroup {
            path: "/system.slice/app.service".into(),
            resource: CgroupResourceKind::Cpu,
        };
        let mut signals = host_signals(
            pressure("cpu_scheduling_contention", Severity::Low, 0.02),
            pressure("memory_pressure", Severity::Low, 0.03),
            healthy("io_no_meaningful_contention"),
        );
        signals.cgroups.push((
            cgroup.clone(),
            pressure("cgroup_pressure", Severity::High, 0.2),
        ));
        let window = tracker.ingest_signals(signals);
        assert_eq!(window.lifecycle.len(), 3);
        assert!(
            window
                .lifecycle
                .iter()
                .any(|finding| finding.id == FindingId::Cpu && finding.state == LifecycleState::New)
        );
        assert!(window.lifecycle.iter().any(|finding| finding.id == cgroup));
    }

    #[test]
    fn history_is_bounded_and_cgroup_tracking_is_capped() {
        let mut tracker = WatchTracker::new();
        for index in 0..(MAX_HISTORY_WINDOWS + 4) {
            let mut signals = host_signals(
                pressure("cpu_scheduling_contention", Severity::Low, 0.02),
                healthy("memory_no_harmful_pressure"),
                healthy("io_no_meaningful_contention"),
            );
            if index == 0 {
                for n in 0..(MAX_TRACKED_CGROUPS + 3) {
                    signals.cgroups.push((
                        FindingId::Cgroup {
                            path: format!("/slice/{n}.service"),
                            resource: CgroupResourceKind::Cpu,
                        },
                        pressure("cgroup_pressure", Severity::Low, 0.02),
                    ));
                }
            }
            let window = tracker.ingest_signals(signals);
            if index == 0 {
                let cgroup_new = window
                    .lifecycle
                    .iter()
                    .filter(|finding| finding.id.is_cgroup())
                    .count();
                assert_eq!(cgroup_new, MAX_TRACKED_CGROUPS);
                assert!(window.current.cgroup_tracking_capped);
            }
        }
        let last = tracker.ingest_signals(host_signals(
            pressure("cpu_scheduling_contention", Severity::Low, 0.02),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(last.history.len(), MAX_HISTORY_WINDOWS);
        assert_eq!(
            last.history.first().map(|entry| entry.window_index),
            Some(6)
        );
    }

    #[test]
    fn disappeared_cgroup_pressure_is_unconfirmed_until_the_scope_is_observed_healthy() {
        let mut tracker = WatchTracker::new();
        let id = FindingId::Cgroup {
            path: "/user.slice/app.scope".into(),
            resource: CgroupResourceKind::Memory,
        };
        let mut first = host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        );
        first.cgroups.push((
            id.clone(),
            pressure("cgroup_pressure", Severity::Moderate, 0.1),
        ));
        tracker.ingest_signals(first);

        let missing = tracker.ingest_signals(host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(missing.lifecycle[0].id, id);
        assert_eq!(missing.lifecycle[0].state, LifecycleState::Persistent);
        assert!(!missing.lifecycle[0].confirmed);

        let mut observed_healthy = host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        );
        observed_healthy
            .observed_cgroup_paths
            .insert("/user.slice/app.scope".into());
        let resolved = tracker.ingest_signals(observed_healthy);
        assert_eq!(resolved.lifecycle[0].state, LifecycleState::Resolved);
        assert_eq!(resolved.lifecycle[0].id, id);
    }

    #[test]
    fn ranking_omitted_cgroup_pressure_stays_unconfirmed_not_resolved() {
        let mut tracker = WatchTracker::new();
        let id = FindingId::Cgroup {
            path: "/low-ranked.scope".into(),
            resource: CgroupResourceKind::Memory,
        };
        let mut first = host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        );
        first.cgroups.push((
            id.clone(),
            pressure("cgroup_memory_reclaim_pressure", Severity::Moderate, 0.1),
        ));
        tracker.ingest_signals(first);

        let mut omitted = host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        );
        omitted
            .observed_cgroup_paths
            .insert("/low-ranked.scope".into());
        omitted.ranking_omitted_cgroup_ids.insert(id.clone());
        let window = tracker.ingest_signals(omitted);
        assert_eq!(window.lifecycle[0].id, id);
        assert_eq!(window.lifecycle[0].state, LifecycleState::Persistent);
        assert!(!window.lifecycle[0].confirmed);
    }

    #[test]
    fn text_and_json_render_lifecycle_without_becoming_a_dashboard() {
        let mut tracker = WatchTracker::new();
        let mut first = tracker.ingest_signals(host_signals(
            pressure("cpu_scheduling_contention", Severity::High, 0.2),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        decorate(&mut first, 2_000, Some(3));
        let text = render_window(
            &WatchOptions {
                interval_ms: 2_000,
                count: Some(3),
                output: OutputFormat::Text,
                no_color: false,
            },
            &first,
        )
        .expect("watch text render");
        assert!(text.contains("WATCH  window 1/3  interval 2s"));
        assert!(text.contains("NEW         CPU  cpu_scheduling_contention  high  PSI 20.00%"));
        assert!(text.contains("Current window"));
        assert!(text.contains("this does not prove causality"));
        assert!(text.contains("CPU      pressure     high  PSI 20.00%"));
        assert!(text.contains("Memory   healthy      none  PSI 0.10%"));
        assert!(!text.contains("Top process CPU consumers"));
        assert_eq!(
            text,
            include_str!("../tests/fixtures/render/watch-lifecycle.txt")
        );

        let json: serde_json::Value = serde_json::from_str(
            &render_window(
                &WatchOptions {
                    interval_ms: 2_000,
                    count: Some(3),
                    output: OutputFormat::Json,
                    no_color: false,
                },
                &first,
            )
            .expect("watch json render"),
        )
        .unwrap();
        assert_eq!(json["kind"], WATCH_WINDOW_KIND);
        assert_eq!(json["schema_version"], 2);
        assert_eq!(json["window_index"], 1);
        assert_eq!(json["lifecycle"][0]["state"], "new");
        assert_eq!(json["lifecycle"][0]["id"]["scope"], "cpu");
        assert_eq!(json["current"]["cpu"]["status"], "pressure");
        assert!(json["current"]["cpu"]["process_candidates"].is_array());
        assert_eq!(json["lifecycle"][0]["process_candidates_stale"], false);
    }

    #[test]
    fn analyzer_candidates_survive_watch_signal_conversion() {
        let victim_key = ProcessKey {
            pid: 41,
            start_time_ticks: 7,
        };
        let suspect_key = ProcessKey {
            pid: 42,
            start_time_ticks: 8,
        };
        let cpu = CpuFinding {
            resource: crate::analysis::Resource::Cpu,
            kind: AssessmentKind::CpuContention,
            severity: Severity::High,
            resource_confidence: Confidence::High,
            summary: "CPU pressure".into(),
            evidence: crate::analysis::CpuEvidence {
                psi_some_fraction: 0.2,
                psi_total_delta_us: 2_000_000,
                psi_window_us: 10_000_000,
                host_utilization_fraction: None,
                logical_cpu_count: None,
                runnable_tasks: None,
                loadavg1: None,
            },
            victims: vec![crate::analysis::Victim {
                key: victim_key,
                name: "victim".into(),
                runnable_wait_ns: 500_000_000,
                runnable_delay_fraction: 0.05,
                stable_task_count: 2,
                confidence: Confidence::High,
                label: "observed_runnable_delay_victim_candidate",
            }],
            suspects: vec![crate::analysis::Suspect {
                key: suspect_key,
                name: "suspect".into(),
                cpu_fraction_of_one: 1.25,
                cpu_ticks: 125,
                confidence: Confidence::Medium,
                label: "concurrent_cpu_consumer",
            }],
            qualifiers: vec![],
        };
        let cpu_signal = cpu_finding_signal(&cpu);
        assert_eq!(cpu_signal.process_candidates.len(), 2);
        assert_eq!(cpu_signal.process_candidates[0].key, victim_key);
        assert!(matches!(
            cpu_signal.process_candidates[0].evidence,
            ProcessCandidateEvidence::RunnableDelay {
                runnable_wait_ns: 500_000_000,
                stable_task_count: 2,
                ..
            }
        ));
        assert_eq!(cpu_signal.process_candidates[1].key, suspect_key);

        let io_key = ProcessKey {
            pid: 43,
            start_time_ticks: 9,
        };
        let io = IoFinding {
            resource: crate::analysis::Resource::Io,
            kind: IoAssessmentKind::Pressure,
            severity: Severity::Moderate,
            resource_confidence: Confidence::High,
            summary: "I/O pressure".into(),
            evidence: crate::analysis::IoEvidence {
                psi_some_fraction: 0.08,
                psi_some_total_delta_us: 800_000,
                psi_full_fraction: None,
                psi_full_total_delta_us: None,
                psi_full_state: crate::analysis::IoFullEvidenceState::Missing,
                psi_window_us: 10_000_000,
                diskstats_window_us: None,
                diskstats_capability: None,
                process_io_window_us: Some(10_000_000),
                process_io_capability: Some(crate::io::IoCapability::Available),
            },
            device_candidates: vec![],
            process_suspects: vec![crate::analysis::IoProcessSuspect {
                key: io_key,
                name: "writer".into(),
                read_bytes: Some(4_096),
                write_bytes: Some(2_048),
                cancelled_write_bytes: None,
                known_accounted_bytes: 6_144,
                confidence: Confidence::Medium,
                label: "same_window_process_io_activity",
            }],
            qualifiers: vec![],
        };
        let io_signal = io_finding_signal(&io);
        assert_eq!(io_signal.process_candidates.len(), 1);
        assert_eq!(io_signal.process_candidates[0].key, io_key);
        assert!(matches!(
            io_signal.process_candidates[0].evidence,
            ProcessCandidateEvidence::IoActivity {
                known_accounted_bytes: 6_144,
                ..
            }
        ));
    }

    #[test]
    fn lifecycle_refreshes_candidates_and_labels_retained_ones_as_last_observed() {
        let candidate = ProcessCandidate {
            role: ProcessRole::CpuVictim,
            key: ProcessKey {
                pid: 42,
                start_time_ticks: 7,
            },
            name: "worker".into(),
            confidence: Confidence::Medium,
            label: "observed_runnable_delay_victim_candidate",
            evidence: ProcessCandidateEvidence::RunnableDelay {
                runnable_wait_ns: 10,
                runnable_delay_fraction: 0.1,
                stable_task_count: 1,
                taskstats_cpu_delay_ns: None,
            },
        };
        let mut tracker = WatchTracker::new();
        let mut first_cpu = pressure("cpu_scheduling_contention", Severity::High, 0.2);
        first_cpu.process_candidates = vec![candidate.clone()];
        tracker.ingest_signals(host_signals(
            first_cpu,
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));

        let mut refreshed = candidate.clone();
        refreshed.key.pid = 43;
        let mut second_cpu = pressure("cpu_scheduling_contention", Severity::High, 0.2);
        second_cpu.process_candidates = vec![refreshed.clone()];
        let persistent = tracker.ingest_signals(host_signals(
            second_cpu,
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(persistent.lifecycle[0].process_candidates, vec![refreshed]);
        assert!(!persistent.lifecycle[0].process_candidates_stale);

        let unconfirmed = tracker.ingest_signals(host_signals(
            unconfirmed(),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert!(unconfirmed.lifecycle[0].process_candidates_stale);
        assert_eq!(unconfirmed.lifecycle[0].process_candidates[0].key.pid, 43);
        let text = watch_text(&unconfirmed);
        assert!(text.contains("Last observed for CPU (unconfirmed)"));

        let resolved = tracker.ingest_signals(host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert!(resolved.lifecycle[0].process_candidates_stale);
        assert_eq!(resolved.lifecycle[0].process_candidates[0].key.pid, 43);
    }

    #[test]
    fn process_candidate_evidence_is_typed_and_json_additive() {
        let mut tracker = WatchTracker::new();
        let mut cpu = pressure("cpu_scheduling_contention", Severity::High, 0.2);
        cpu.process_candidates = vec![ProcessCandidate {
            role: ProcessRole::CpuSuspect,
            key: ProcessKey {
                pid: 9231,
                start_time_ticks: 1,
            },
            name: "rustc\nworker".into(),
            confidence: Confidence::Medium,
            label: "concurrent_cpu_consumer",
            evidence: ProcessCandidateEvidence::CpuConsumption {
                cpu_fraction_of_one: 1.25,
                cpu_ticks: 125,
            },
        }];
        cpu.process_candidate_availability = vec![ProcessRoleAvailability {
            role: ProcessRole::CpuSuspect,
            availability: ProcessCandidateAvailability::Available,
        }];
        let mut io = pressure("io_pressure", Severity::Moderate, 0.08);
        io.process_candidates = vec![ProcessCandidate {
            role: ProcessRole::IoSuspect,
            key: ProcessKey {
                pid: 7712,
                start_time_ticks: 2,
            },
            name: "restic".into(),
            confidence: Confidence::Medium,
            label: "same_window_process_io_activity",
            evidence: ProcessCandidateEvidence::IoActivity {
                read_bytes: Some(4096),
                write_bytes: Some(2048),
                cancelled_write_bytes: None,
                known_accounted_bytes: 6144,
            },
        }];
        let window =
            tracker.ingest_signals(host_signals(cpu, healthy("memory_no_harmful_pressure"), io));
        let text = watch_text(&window);
        assert!(text.contains("rustc�worker [9231]"));
        assert!(text.contains("125.0% of one CPU"));
        assert!(text.contains("restic [7712]"));

        let json: serde_json::Value = serde_json::from_str(&watch_json(&window).unwrap()).unwrap();
        assert_eq!(json["schema_version"], 2);
        assert_eq!(
            json["current"]["cpu"]["process_candidates"][0]["role"],
            "cpu_suspect"
        );
        assert_eq!(
            json["current"]["cpu"]["process_candidates"][0]["evidence"]["kind"],
            "cpu_consumption"
        );
        assert_eq!(
            json["current"]["io"]["process_candidates"][0]["role"],
            "io_suspect"
        );
        assert_eq!(
            json["current"]["io"]["process_candidates"][0]["evidence"]["kind"],
            "io_activity"
        );
        assert_eq!(
            json["current"]["cpu"]["process_candidate_availability"][0]["availability"],
            "available"
        );
        assert!(
            json["current"]["memory"]["process_candidates"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    fn sample_cgroup_finding(
        resource: CgroupResourceKind,
        mechanism: Option<CgroupMechanism>,
    ) -> CgroupFinding {
        CgroupFinding {
            path: "/workload.service".into(),
            resource,
            kind: CgroupAssessmentKind::Pressure,
            severity: Severity::High,
            resource_confidence: Confidence::High,
            mechanism,
            mechanism_confidence: mechanism.map(|_| Confidence::Low),
            summary: "scoped pressure".into(),
            evidence: CgroupEvidence {
                psi_some_fraction: Some(0.2),
                psi_some_total_delta_us: Some(2_000_000),
                psi_full_fraction: None,
                psi_full_total_delta_us: None,
                psi_window_us: 10_000_000,
                psi_state: CgroupFileState::Available,
                cpu: CgroupResource {
                    state: CgroupFileState::Missing,
                    value: None,
                },
                memory_current_end: CgroupResource {
                    state: CgroupFileState::Missing,
                    value: None,
                },
                memory_events: CgroupResource {
                    state: CgroupFileState::Missing,
                    value: None,
                },
                memory_stat: CgroupResource {
                    state: CgroupFileState::Missing,
                    value: None,
                },
                io: CgroupResource {
                    state: CgroupFileState::Missing,
                    value: None,
                },
            },
            systemd_unit_candidate: None,
            members: vec![],
            qualifiers: vec![],
        }
    }

    #[test]
    fn host_memory_watch_kinds_transition_without_splitting_identity() {
        let mut tracker = WatchTracker::new();

        let new = tracker.ingest_signals(host_signals(
            healthy("cpu_no_meaningful_contention"),
            pressure("memory_reclaim_pressure", Severity::High, 0.2),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(new.lifecycle.len(), 1);
        assert_eq!(new.lifecycle[0].id, FindingId::Memory);
        assert_eq!(new.lifecycle[0].state, LifecycleState::New);
        assert_eq!(new.lifecycle[0].kind, "memory_reclaim_pressure");

        // A mechanism change on the same host resource stays persistent.
        let persistent = tracker.ingest_signals(host_signals(
            healthy("cpu_no_meaningful_contention"),
            pressure("memory_swap_pressure", Severity::High, 0.2),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(persistent.lifecycle[0].id, FindingId::Memory);
        assert_eq!(persistent.lifecycle[0].state, LifecycleState::Persistent);
        assert_eq!(persistent.lifecycle[0].consecutive_windows, 2);
        assert_eq!(persistent.lifecycle[0].kind, "memory_swap_pressure");

        // A severity change also stays persistent and records the transition.
        let escalated = tracker.ingest_signals(host_signals(
            healthy("cpu_no_meaningful_contention"),
            pressure("memory_swap_pressure", Severity::Severe, 0.4),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(escalated.lifecycle[0].state, LifecycleState::Persistent);
        assert_eq!(
            escalated.lifecycle[0].previous_severity,
            Some(Severity::High)
        );
        assert_eq!(escalated.lifecycle[0].severity, Severity::Severe);

        let resolved = tracker.ingest_signals(host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        ));
        assert_eq!(resolved.lifecycle[0].id, FindingId::Memory);
        assert_eq!(resolved.lifecycle[0].state, LifecycleState::Resolved);
        assert_eq!(resolved.lifecycle[0].kind, "memory_swap_pressure");
    }

    #[test]
    fn cgroup_watch_kind_names_mechanism_without_splitting_identity() {
        let (reclaim_id, reclaim) = cgroup_pressure_signal(
            sample_cgroup_finding(CgroupResourceKind::Memory, Some(CgroupMechanism::Reclaim)),
            &[],
        )
        .expect("reclaim pressure");
        assert_eq!(
            reclaim_id,
            FindingId::Cgroup {
                path: "/workload.service".into(),
                resource: CgroupResourceKind::Memory,
            }
        );
        assert_eq!(reclaim.kind, "cgroup_memory_reclaim_pressure");

        let (_, swap) = cgroup_pressure_signal(
            sample_cgroup_finding(CgroupResourceKind::Memory, Some(CgroupMechanism::Swap)),
            &[],
        )
        .expect("swap pressure");
        assert_eq!(swap.kind, "cgroup_memory_swap_pressure");

        let (_, thrash) = cgroup_pressure_signal(
            sample_cgroup_finding(
                CgroupResourceKind::Memory,
                Some(CgroupMechanism::PossibleThrashing),
            ),
            &[],
        )
        .expect("possible thrashing");
        assert_eq!(thrash.kind, "cgroup_memory_possible_thrashing");

        let (_, throttle) = cgroup_pressure_signal(
            sample_cgroup_finding(
                CgroupResourceKind::Cpu,
                Some(CgroupMechanism::CpuQuotaThrottle),
            ),
            &[],
        )
        .expect("throttle pressure");
        assert_eq!(throttle.kind, "cgroup_cpu_quota_throttle_pressure");

        let (_, unlabeled_cpu) =
            cgroup_pressure_signal(sample_cgroup_finding(CgroupResourceKind::Cpu, None), &[])
                .expect("cpu pressure");
        assert_eq!(unlabeled_cpu.kind, "cgroup_cpu_pressure");

        let (_, unlabeled_memory) =
            cgroup_pressure_signal(sample_cgroup_finding(CgroupResourceKind::Memory, None), &[])
                .expect("memory pressure");
        assert_eq!(unlabeled_memory.kind, "cgroup_memory_pressure");

        let (_, unlabeled_io) =
            cgroup_pressure_signal(sample_cgroup_finding(CgroupResourceKind::Io, None), &[])
                .expect("io pressure");
        assert_eq!(unlabeled_io.kind, "cgroup_io_pressure");

        let mut tracker = WatchTracker::new();
        let id = FindingId::Cgroup {
            path: "/workload.service".into(),
            resource: CgroupResourceKind::Memory,
        };
        let mut first = host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        );
        first.cgroups.push((
            id.clone(),
            pressure("cgroup_memory_reclaim_pressure", Severity::High, 0.2),
        ));
        first
            .observed_cgroup_paths
            .insert("/workload.service".into());
        let new = tracker.ingest_signals(first);
        assert_eq!(new.lifecycle[0].state, LifecycleState::New);
        assert_eq!(new.lifecycle[0].kind, "cgroup_memory_reclaim_pressure");

        let mut second = host_signals(
            healthy("cpu_no_meaningful_contention"),
            healthy("memory_no_harmful_pressure"),
            healthy("io_no_meaningful_contention"),
        );
        second.cgroups.push((
            id.clone(),
            pressure("cgroup_memory_swap_pressure", Severity::High, 0.2),
        ));
        second
            .observed_cgroup_paths
            .insert("/workload.service".into());
        let persistent = tracker.ingest_signals(second);
        assert_eq!(persistent.lifecycle[0].id, id);
        assert_eq!(persistent.lifecycle[0].state, LifecycleState::Persistent);
        assert_eq!(persistent.lifecycle[0].kind, "cgroup_memory_swap_pressure");
    }

    #[test]
    fn cgroup_role_transport_and_lifecycle_stale_state_match_path_and_resource() {
        let roles = vec![
            ProcessRoleList {
                role: ProcessRole::CpuVictim,
                availability: ProcessCandidateAvailability::Available,
                completeness: crate::analysis::ProcessRoleCompleteness::Complete,
                stale: false,
                candidates: vec![],
            },
            ProcessRoleList {
                role: ProcessRole::CpuSuspect,
                availability: ProcessCandidateAvailability::Available,
                completeness: crate::analysis::ProcessRoleCompleteness::Complete,
                stale: false,
                candidates: vec![],
            },
        ];
        let scope = ProcessScope {
            scope: crate::analysis::ProcessScopeKind::Cgroup {
                path: "/workload.service".into(),
            },
            roles: roles.clone(),
        };
        let (id, signal) = cgroup_pressure_signal(
            sample_cgroup_finding(CgroupResourceKind::Cpu, None),
            std::slice::from_ref(&scope),
        )
        .unwrap();
        assert_eq!(signal.process_role_lists, roles);
        let mut signals = host_signals(unconfirmed(), unconfirmed(), unconfirmed());
        signals.cgroups.push((id.clone(), signal));
        signals
            .observed_cgroup_paths
            .insert("/workload.service".into());
        signals.process_scopes.push(scope);
        let mut tracker = WatchTracker::new();
        let current = tracker.ingest_signals(signals);
        assert_eq!(current.lifecycle[0].id, id);
        assert!(
            current.lifecycle[0]
                .process_role_lists
                .iter()
                .all(|list| !list.stale)
        );

        let stale =
            tracker.ingest_signals(host_signals(unconfirmed(), unconfirmed(), unconfirmed()));
        assert!(!stale.lifecycle[0].confirmed);
        assert!(
            stale.lifecycle[0]
                .process_role_lists
                .iter()
                .all(|list| list.stale)
        );
        let mut resolved_signals = host_signals(unconfirmed(), unconfirmed(), unconfirmed());
        resolved_signals
            .observed_cgroup_paths
            .insert("/workload.service".into());
        let resolved = tracker.ingest_signals(resolved_signals);
        assert_eq!(resolved.lifecycle[0].state, LifecycleState::Resolved);
        assert!(
            resolved.lifecycle[0]
                .process_role_lists
                .iter()
                .all(|list| list.stale)
        );
    }
}
