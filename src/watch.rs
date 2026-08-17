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
    Severity,
};
use crate::cli::{OutputFormat, WatchOptions};
use crate::observe::{
    HuntObservation, observation_from_endpoints, read_end_endpoint, read_start_endpoint,
};

pub const MAX_HISTORY_WINDOWS: usize = 16;
pub const MAX_TRACKED_CGROUPS: usize = 16;
pub const WATCH_WINDOW_KIND: &str = "stallhunt.watch_window";
const CLEAR_SCREEN: &str = "\u{1b}[H\u{1b}[2J";

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

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResourceSignal {
    pub status: ObservationStatus,
    pub severity: Severity,
    pub confidence: Confidence,
    pub kind: &'static str,
    pub summary: String,
    pub psi_some_fraction: Option<f64>,
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
    if let FindingId::Cgroup { path, .. } = id
        && observed_cgroup_paths.contains(path)
    {
        return ObservationStatus::Healthy;
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

pub fn run(options: &WatchOptions) -> io::Result<()> {
    let stdout = io::stdout();
    let refresh = options.output == OutputFormat::Text && stdout.is_terminal();
    let mut writer = stdout.lock();
    run_on(&mut writer, options, refresh)
}

fn write_window(
    writer: &mut dyn Write,
    options: &WatchOptions,
    window: &WatchWindow,
    refresh: bool,
) -> io::Result<()> {
    write!(writer, "{}", render_window(options, window, refresh)?)?;
    writer.flush()?;
    Ok(())
}

fn run_on(writer: &mut dyn Write, options: &WatchOptions, refresh: bool) -> io::Result<()> {
    let requested = Duration::from_millis(options.interval_ms);
    if requested.is_zero() {
        return Ok(());
    }

    let mut start = read_start_endpoint();
    let mut tracker = WatchTracker::new();
    let mut completed = 0_u32;
    loop {
        if options.count == Some(completed) {
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
        write_window(writer, options, &window, refresh).or_else(|error| {
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

pub fn render_window(
    options: &WatchOptions,
    window: &WatchWindow,
    refresh: bool,
) -> Result<String, serde_json::Error> {
    match options.output {
        OutputFormat::Json => watch_json(window),
        OutputFormat::Text => Ok(watch_text(window, refresh)),
    }
}

fn watch_text(window: &WatchWindow, refresh: bool) -> String {
    let mut output = String::new();
    if refresh {
        output.push_str(CLEAR_SCREEN);
    } else {
        output.push_str(&format!("--- window {} ---\n", window.index));
    }
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
        schema_version: 1,
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

fn window_index_label(window: &WatchWindow) -> String {
    match window.count {
        Some(count) => format!("{}/{}", window.index, count),
        None => window.index.to_string(),
    }
}

fn state_label(state: LifecycleState) -> &'static str {
    match state {
        LifecycleState::New => "NEW",
        LifecycleState::Persistent => "PERSISTENT",
        LifecycleState::Resolved => "RESOLVED",
    }
}

fn status_label(status: ObservationStatus) -> &'static str {
    match status {
        ObservationStatus::Pressure => "pressure",
        ObservationStatus::Healthy => "healthy",
        ObservationStatus::Unconfirmed => "unconfirmed",
    }
}

fn id_label(id: &FindingId) -> String {
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

fn psi_suffix(fraction: Option<f64>) -> String {
    match fraction {
        Some(value) => format!("  PSI {:.2}%", value * 100.0),
        None => String::new(),
    }
}

fn format_ms(duration_ms: u64) -> String {
    if duration_ms % 60_000 == 0 && duration_ms >= 60_000 {
        format!("{}m", duration_ms / 60_000)
    } else if duration_ms % 1_000 == 0 {
        format!("{}s", duration_ms / 1_000)
    } else {
        format!("{duration_ms}ms")
    }
}

const fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::None => "none",
        Severity::Low => "low",
        Severity::Moderate => "moderate",
        Severity::High => "high",
        Severity::Severe => "severe",
    }
}

pub fn signals_from_observation(observation: &HuntObservation) -> WindowSignals {
    let cpu = cpu_signal(observation);
    let memory = memory_signal(observation);
    let io = io_signal(observation);
    let cgroup_signals = cgroup_signals(observation);
    WindowSignals {
        cpu,
        memory,
        io,
        cgroups: cgroup_signals.pressured,
        observed_cgroup_paths: cgroup_signals.observed_cgroup_paths,
        ranking_omitted_cgroup_ids: cgroup_signals.ranking_omitted_cgroup_ids,
        cgroup_tracking_capped: cgroup_signals.capped,
    }
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
    }
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
    }
}

struct CgroupSignalBundle {
    pressured: Vec<(FindingId, ResourceSignal)>,
    observed_cgroup_paths: BTreeSet<String>,
    ranking_omitted_cgroup_ids: BTreeSet<FindingId>,
    capped: bool,
}

fn cgroup_signals(observation: &HuntObservation) -> CgroupSignalBundle {
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
        .filter_map(cgroup_pressure_signal)
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

fn cgroup_pressure_signal(finding: CgroupFinding) -> Option<(FindingId, ResourceSignal)> {
    if finding.kind != CgroupAssessmentKind::Pressure {
        return None;
    }
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
    }
}

const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::None => 0,
        Severity::Low => 1,
        Severity::Moderate => 2,
        Severity::High => 3,
        Severity::Severe => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::CgroupEvidence;
    use crate::cgroup::{CgroupFileState, CgroupResource};

    fn pressure(kind: &'static str, severity: Severity, psi: f64) -> ResourceSignal {
        ResourceSignal {
            status: ObservationStatus::Pressure,
            severity,
            confidence: Confidence::High,
            kind,
            summary: format!("{kind} {:.2}%", psi * 100.0),
            psi_some_fraction: Some(psi),
        }
    }

    fn healthy(kind: &'static str) -> ResourceSignal {
        ResourceSignal {
            status: ObservationStatus::Healthy,
            severity: Severity::None,
            confidence: Confidence::High,
            kind,
            summary: format!("{kind} healthy"),
            psi_some_fraction: Some(0.001),
        }
    }

    fn unconfirmed() -> ResourceSignal {
        unconfirmed_signal("insufficient_observation", "short window")
    }

    fn host_signals(
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
        }
    }

    fn decorate(window: &mut WatchWindow, interval_ms: u64, count: Option<u32>) {
        window.interval_ms = interval_ms;
        window.count = count;
    }

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
            },
            &first,
            false,
        )
        .expect("watch text render");
        assert!(text.contains("WATCH  window 1/3  interval 2s"));
        assert!(text.contains("NEW         CPU  cpu_scheduling_contention  high  PSI 20.00%"));
        assert!(text.contains("Current window"));
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
                },
                &first,
                false,
            )
            .expect("watch json render"),
        )
        .unwrap();
        assert_eq!(json["kind"], WATCH_WINDOW_KIND);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["window_index"], 1);
        assert_eq!(json["lifecycle"][0]["state"], "new");
        assert_eq!(json["lifecycle"][0]["id"]["scope"], "cpu");
        assert_eq!(json["current"]["cpu"]["status"], "pressure");
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
    fn cgroup_watch_kind_names_mechanism_without_splitting_identity() {
        let (reclaim_id, reclaim) = cgroup_pressure_signal(sample_cgroup_finding(
            CgroupResourceKind::Memory,
            Some(CgroupMechanism::Reclaim),
        ))
        .expect("reclaim pressure");
        assert_eq!(
            reclaim_id,
            FindingId::Cgroup {
                path: "/workload.service".into(),
                resource: CgroupResourceKind::Memory,
            }
        );
        assert_eq!(reclaim.kind, "cgroup_memory_reclaim_pressure");

        let (_, swap) = cgroup_pressure_signal(sample_cgroup_finding(
            CgroupResourceKind::Memory,
            Some(CgroupMechanism::Swap),
        ))
        .expect("swap pressure");
        assert_eq!(swap.kind, "cgroup_memory_swap_pressure");

        let (_, thrash) = cgroup_pressure_signal(sample_cgroup_finding(
            CgroupResourceKind::Memory,
            Some(CgroupMechanism::PossibleThrashing),
        ))
        .expect("possible thrashing");
        assert_eq!(thrash.kind, "cgroup_memory_possible_thrashing");

        let (_, throttle) = cgroup_pressure_signal(sample_cgroup_finding(
            CgroupResourceKind::Cpu,
            Some(CgroupMechanism::CpuQuotaThrottle),
        ))
        .expect("throttle pressure");
        assert_eq!(throttle.kind, "cgroup_cpu_quota_throttle_pressure");

        let (_, unlabeled_cpu) =
            cgroup_pressure_signal(sample_cgroup_finding(CgroupResourceKind::Cpu, None))
                .expect("cpu pressure");
        assert_eq!(unlabeled_cpu.kind, "cgroup_cpu_pressure");

        let (_, unlabeled_memory) =
            cgroup_pressure_signal(sample_cgroup_finding(CgroupResourceKind::Memory, None))
                .expect("memory pressure");
        assert_eq!(unlabeled_memory.kind, "cgroup_memory_pressure");

        let (_, unlabeled_io) =
            cgroup_pressure_signal(sample_cgroup_finding(CgroupResourceKind::Io, None))
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
}
