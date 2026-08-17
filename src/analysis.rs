//! Conservative CPU inference over normalized observations.  This module has
//! no procfs or rendering dependencies so fixtures can exercise it directly.
use std::time::Duration;

use serde::Serialize;

use crate::cpu::{
    self, CpuProcessObservation, ProcessKey, ProcessSchedulerDelayInterval, SchedstatCapability,
};
use crate::psi::CpuPsiObservation;

pub const MIN_DIAGNOSIS_WINDOW: Duration = Duration::from_secs(1);
pub const CPU_SEVERITY_THRESHOLDS: [f64; 4] = [0.01, 0.05, 0.15, 0.30];
const SUSPECT_MIN_FRACTION: f64 = 0.25;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    None,
    Low,
    Moderate,
    High,
    Severe,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentKind {
    #[serde(rename = "cpu_scheduling_contention")]
    CpuContention,
    CpuNoMeaningfulContention,
    InsufficientObservation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    Cpu,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CpuFinding {
    pub resource: Resource,
    pub kind: AssessmentKind,
    pub severity: Severity,
    pub resource_confidence: Confidence,
    pub summary: String,
    pub evidence: CpuEvidence,
    pub victims: Vec<Victim>,
    pub suspects: Vec<Suspect>,
    pub qualifiers: Vec<Qualifier>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CpuEvidence {
    pub psi_some_fraction: f64,
    pub psi_total_delta_us: u64,
    pub psi_window_us: u128,
    pub host_utilization_fraction: Option<f64>,
    pub logical_cpu_count: Option<u32>,
    pub runnable_tasks: Option<u64>,
    pub loadavg1: Option<f64>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Victim {
    pub key: ProcessKey,
    pub name: String,
    pub runnable_wait_ns: u64,
    pub runnable_delay_fraction: f64,
    pub stable_task_count: u32,
    pub confidence: Confidence,
    pub label: &'static str,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Suspect {
    pub key: ProcessKey,
    pub name: String,
    pub cpu_fraction_of_one: f64,
    pub cpu_ticks: u64,
    pub confidence: Confidence,
    pub label: &'static str,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Qualifier {
    pub kind: &'static str,
    pub message: &'static str,
}
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AnalysisResult {
    pub findings: Vec<CpuFinding>,
    pub qualifiers: Vec<Qualifier>,
}

pub fn severity_for_psi(some_fraction: f64) -> Severity {
    if some_fraction < CPU_SEVERITY_THRESHOLDS[0] {
        Severity::None
    } else if some_fraction < CPU_SEVERITY_THRESHOLDS[1] {
        Severity::Low
    } else if some_fraction < CPU_SEVERITY_THRESHOLDS[2] {
        Severity::Moderate
    } else if some_fraction < CPU_SEVERITY_THRESHOLDS[3] {
        Severity::High
    } else {
        Severity::Severe
    }
}

pub fn analyze_cpu(
    psi: Option<&CpuPsiObservation>,
    cpu: Option<&CpuProcessObservation>,
) -> AnalysisResult {
    let Some(psi) = psi else {
        return AnalysisResult {
            findings: vec![],
            qualifiers: vec![Qualifier {
                kind: "cpu_assessment_unavailable",
                message: "CPU PSI is unavailable, so no CPU contention assessment was produced.",
            }],
        };
    };
    if psi.requested.min(psi.interval.elapsed) < MIN_DIAGNOSIS_WINDOW {
        return AnalysisResult { findings: vec![CpuFinding { resource: Resource::Cpu, kind: AssessmentKind::InsufficientObservation, severity: Severity::None, resource_confidence: Confidence::Low, summary: "CPU observation is shorter than 1s; no healthy or contention conclusion was made.".into(), evidence: evidence(psi, cpu), victims: vec![], suspects: vec![], qualifiers: vec![Qualifier { kind: "insufficient_observation", message: "A requested and measured CPU PSI interval of at least 1s is required for a diagnosis." }] }], qualifiers: vec![] };
    }
    let severity = severity_for_psi(psi.interval.some_fraction);
    let contention = severity != Severity::None;
    let resource_confidence = if psi.requested >= Duration::from_secs(5)
        && psi.interval.elapsed >= Duration::from_secs(5)
    {
        Confidence::High
    } else {
        Confidence::Medium
    };
    let mut qualifiers = supporting_qualifiers(cpu);
    if cpu.is_none() {
        qualifiers.push(Qualifier { kind: "attribution_unavailable", message: "CPU interval context is unavailable; victim and suspect attribution was not produced." });
    }
    if cpu.is_some_and(|cpu| cpu.schedstat_capability != SchedstatCapability::Available) {
        qualifiers.push(Qualifier { kind: "victim_attribution_limited", message: "Scheduler accounting is unavailable or partial; victim attribution is limited." });
    }
    if cpu.is_some_and(process_coverage_partial) {
        qualifiers.push(Qualifier {
            kind: "suspect_attribution_limited",
            message: "Process collection is partial; suspect attribution is limited.",
        });
    }
    if !contention {
        qualifiers.push(Qualifier { kind: "cpu_no_meaningful_contention", message: "No meaningful CPU scheduling contention was observed from exact-interval CPU PSI." });
        if cpu.is_some_and(|cpu| {
            cpu.scheduler_delay_candidates
                .iter()
                .any(|candidate| candidate.runnable_wait_ns > 0)
        }) {
            qualifiers.push(Qualifier { kind: "scheduler_delay_context", message: "Positive scheduler-delay intervals are context but do not override the PSI no-contention verdict." });
        }
    }
    let victims = if contention {
        cpu.map(|cpu| victims(cpu, resource_confidence))
            .unwrap_or_default()
    } else {
        vec![]
    };
    let suspects = if contention {
        cpu.map(|cpu| suspects(cpu, resource_confidence, &mut qualifiers))
            .unwrap_or_default()
    } else {
        vec![]
    };
    let summary = if contention {
        format!(
            "CPU scheduling contention observed ({:.2}% CPU PSI some).",
            psi.interval.some_fraction * 100.0
        )
    } else {
        "No meaningful CPU scheduling contention observed.".into()
    };
    AnalysisResult {
        findings: vec![CpuFinding {
            resource: Resource::Cpu,
            kind: if contention {
                AssessmentKind::CpuContention
            } else {
                AssessmentKind::CpuNoMeaningfulContention
            },
            severity,
            resource_confidence,
            summary,
            evidence: evidence(psi, cpu),
            victims,
            suspects,
            qualifiers,
        }],
        qualifiers: vec![],
    }
}

fn evidence(psi: &CpuPsiObservation, cpu: Option<&CpuProcessObservation>) -> CpuEvidence {
    CpuEvidence {
        psi_some_fraction: psi.interval.some_fraction,
        psi_total_delta_us: psi.interval.total_delta_us,
        psi_window_us: psi.interval.elapsed.as_micros(),
        host_utilization_fraction: cpu.map(|c| c.host.utilization_fraction),
        logical_cpu_count: cpu.map(|c| c.host.cpu_count),
        runnable_tasks: cpu.and_then(|c| c.load.as_ref().map(|l| l.runnable_tasks)),
        loadavg1: cpu.and_then(|c| c.load.as_ref().map(|l| l.avg1)),
    }
}
fn supporting_qualifiers(cpu: Option<&CpuProcessObservation>) -> Vec<Qualifier> {
    let mut result = Vec::new();
    if let Some(cpu) = cpu {
        if cpu.host.utilization_fraction >= 0.90 {
            result.push(Qualifier { kind: "high_utilization_context", message: "Host CPU utilization was at least 90%; this is supporting context, not the contention verdict." });
        }
        if cpu
            .load
            .as_ref()
            .is_some_and(|l| l.runnable_tasks > u64::from(cpu.host.cpu_count))
        {
            result.push(Qualifier { kind: "runnable_queue_context", message: "Runnable tasks exceeded logical CPU count; this is supporting context, not the contention verdict." });
        }
    } else {
        result.push(Qualifier { kind: "cpu_context_unavailable", message: "Host/process CPU context was unavailable; PSI alone determines the resource verdict." });
    }
    result
}
fn victims(cpu: &CpuProcessObservation, resource: Confidence) -> Vec<Victim> {
    let direct = match (
        cpu.schedstat_capability,
        cpu.elapsed >= Duration::from_secs(5),
    ) {
        (SchedstatCapability::Available, true) => Confidence::High,
        (SchedstatCapability::Available | SchedstatCapability::Partial, _) => Confidence::Medium,
        _ => Confidence::Low,
    };
    let confidence = direct.min(resource);
    let mut v: Vec<_> = cpu
        .scheduler_delay_candidates
        .iter()
        .filter(|x| x.runnable_wait_ns > 0)
        .map(|x| victim(x, confidence))
        .collect();
    v.sort_by(|a, b| {
        b.runnable_wait_ns
            .cmp(&a.runnable_wait_ns)
            .then_with(|| a.key.cmp(&b.key))
    });
    v.truncate(5);
    v
}
fn victim(x: &ProcessSchedulerDelayInterval, confidence: Confidence) -> Victim {
    Victim {
        key: x.key,
        name: x.name.clone(),
        runnable_wait_ns: x.runnable_wait_ns,
        runnable_delay_fraction: x.runnable_delay_fraction,
        stable_task_count: x.task_count,
        confidence,
        label: "observed_runnable_delay_victim_candidate",
    }
}
fn suspects(
    cpu: &CpuProcessObservation,
    resource: Confidence,
    qualifiers: &mut Vec<Qualifier>,
) -> Vec<Suspect> {
    let process_partial = process_coverage_partial(cpu);
    let confidence = if process_partial {
        Confidence::Low
    } else {
        resource.min(Confidence::Medium)
    };
    let mut s: Vec<_> = cpu
        .processes
        .iter()
        .filter(|x| x.cpu_fraction_of_one >= SUSPECT_MIN_FRACTION)
        .map(|x| Suspect {
            key: x.key,
            name: x.name.clone(),
            cpu_fraction_of_one: x.cpu_fraction_of_one,
            cpu_ticks: x.cpu_ticks,
            confidence,
            label: "concurrent_cpu_consumer",
        })
        .collect();
    s.sort_by(|a, b| {
        b.cpu_fraction_of_one
            .total_cmp(&a.cpu_fraction_of_one)
            .then_with(|| a.key.cmp(&b.key))
    });
    let non_unique = s.first().zip(s.get(1)).is_some_and(|(first, second)| {
        second.cpu_fraction_of_one >= first.cpu_fraction_of_one * 0.90
    });
    let unique_leader = !non_unique && !process_partial && cpu.host.utilization_fraction >= 0.90;
    if let Some(first) = s.first_mut() {
        if unique_leader {
            first.label = "leading_concurrent_cpu_consumer";
        }
        if non_unique {
            first.label = "concurrent_cpu_consumer";
            first.confidence = Confidence::Low;
            qualifiers.push(Qualifier {
                kind: "non_unique_attribution",
                message: "Leading CPU consumers were within 10%; attribution is non-unique.",
            });
        }
    }
    if non_unique {
        let leader = s[0].cpu_fraction_of_one;
        for suspect in &mut s {
            if suspect.cpu_fraction_of_one >= leader * 0.90 {
                suspect.confidence = Confidence::Low;
            }
        }
    }
    if !s.is_empty() {
        qualifiers.push(Qualifier { kind:"same_window_correlation", message:"Suspects consumed CPU in the same window; this correlation does not prove causality." });
    }
    s.truncate(3);
    s
}
fn process_coverage_partial(cpu: &CpuProcessObservation) -> bool {
    let issues = &cpu.collection_issues;
    cpu::process_capability(issues) != cpu::CollectorCapability::Available
        || issues.appeared != 0
        || issues.exited != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::{
        HostCpuInterval, LoadAverageAvailability, ProcessCollectionIssues, ProcessCpuInterval,
        SchedstatCollectionIssues,
    };
    use crate::psi::{CpuPsiInterval, CpuPsiRaw};
    use serde::Deserialize;

    fn psi(fraction: f64, elapsed: Duration) -> CpuPsiObservation {
        CpuPsiObservation {
            requested: elapsed,
            interval: CpuPsiInterval {
                elapsed,
                total_delta_us: (fraction * elapsed.as_micros() as f64) as u64,
                some_fraction: fraction,
            },
            start: CpuPsiRaw {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 0,
            },
            end: CpuPsiRaw {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 1,
            },
        }
    }
    fn cpu(
        processes: Vec<ProcessCpuInterval>,
        delays: Vec<ProcessSchedulerDelayInterval>,
    ) -> CpuProcessObservation {
        CpuProcessObservation {
            elapsed: Duration::from_secs(10),
            clock_ticks_per_second: 100,
            host: HostCpuInterval {
                total_ticks: 1000,
                busy_ticks: 1000,
                idle_ticks: 0,
                utilization_fraction: 1.0,
                cpu_count: 8,
            },
            load: None,
            load_availability: LoadAverageAvailability::Unreadable,
            processes,
            collection_issues: ProcessCollectionIssues::default(),
            scheduler_delay_candidates: delays,
            schedstat_collection_issues: SchedstatCollectionIssues::default(),
            schedstat_capability: SchedstatCapability::Available,
        }
    }
    #[test]
    fn boundaries_are_exact() {
        assert_eq!(severity_for_psi(0.009), Severity::None);
        assert_eq!(severity_for_psi(0.01), Severity::Low);
        assert_eq!(severity_for_psi(0.05), Severity::Moderate);
        assert_eq!(severity_for_psi(0.15), Severity::High);
        assert_eq!(severity_for_psi(0.30), Severity::Severe);
    }
    #[test]
    fn psi_alone_controls_negative_and_short_verdicts() {
        let busy = cpu(vec![], vec![]);
        assert_eq!(
            analyze_cpu(Some(&psi(0.005, Duration::from_secs(10))), Some(&busy)).findings[0].kind,
            AssessmentKind::CpuNoMeaningfulContention
        );
        assert_eq!(
            analyze_cpu(Some(&psi(0.20, Duration::from_millis(999))), Some(&busy)).findings[0].kind,
            AssessmentKind::InsufficientObservation
        );
        assert!(analyze_cpu(None, Some(&busy)).findings.is_empty());
    }
    #[test]
    fn ranks_stable_victims_and_non_unique_consumers() {
        let key1 = ProcessKey {
            pid: 1,
            start_time_ticks: 1,
        };
        let key2 = ProcessKey {
            pid: 2,
            start_time_ticks: 1,
        };
        let c = cpu(
            vec![
                ProcessCpuInterval {
                    key: key2,
                    name: "b".into(),
                    state: 'R',
                    cpu_ticks: 1,
                    cpu_fraction_of_one: 0.90,
                },
                ProcessCpuInterval {
                    key: key1,
                    name: "a".into(),
                    state: 'R',
                    cpu_ticks: 1,
                    cpu_fraction_of_one: 1.0,
                },
            ],
            vec![
                ProcessSchedulerDelayInterval {
                    key: key2,
                    name: "b".into(),
                    task_count: 1,
                    running_ns: 0,
                    runnable_wait_ns: 100,
                    runnable_delay_fraction: 0.1,
                    timeslices: 1,
                },
                ProcessSchedulerDelayInterval {
                    key: key1,
                    name: "a".into(),
                    task_count: 1,
                    running_ns: 0,
                    runnable_wait_ns: 100,
                    runnable_delay_fraction: 0.1,
                    timeslices: 1,
                },
                ProcessSchedulerDelayInterval {
                    key: ProcessKey {
                        pid: 3,
                        start_time_ticks: 1,
                    },
                    name: "zero".into(),
                    task_count: 1,
                    running_ns: 0,
                    runnable_wait_ns: 0,
                    runnable_delay_fraction: 0.0,
                    timeslices: 1,
                },
            ],
        );
        let finding = &analyze_cpu(Some(&psi(0.2, Duration::from_secs(10))), Some(&c)).findings[0];
        assert_eq!(
            finding
                .victims
                .iter()
                .map(|x| x.key.pid)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(finding.suspects[0].label, "concurrent_cpu_consumer");
        assert!(
            finding
                .qualifiers
                .iter()
                .any(|q| q.kind == "non_unique_attribution")
        );
    }
    #[test]
    fn normalized_fixtures_drive_analyzer() {
        for fixture in [
            include_str!("../tests/fixtures/cpu/healthy.json"),
            include_str!("../tests/fixtures/cpu/saturated.json"),
            include_str!("../tests/fixtures/cpu/saturated_no_schedstat.json"),
            include_str!("../tests/fixtures/cpu/busy_but_not_pressured.json"),
        ] {
            let fixture: Fixture = serde_json::from_str(fixture).unwrap();
            assert_eq!(fixture.schema, "normalized_cpu_fixture_v1");
            let key = |pid| ProcessKey {
                pid,
                start_time_ticks: 1,
            };
            let mut c = cpu(
                fixture
                    .processes
                    .iter()
                    .map(|p| ProcessCpuInterval {
                        key: key(p.pid),
                        name: format!("p{}", p.pid),
                        state: 'R',
                        cpu_ticks: p.cpu_ticks,
                        cpu_fraction_of_one: p.cpu_fraction,
                    })
                    .collect(),
                fixture
                    .delays
                    .iter()
                    .map(|d| ProcessSchedulerDelayInterval {
                        key: key(d.pid),
                        name: format!("p{}", d.pid),
                        task_count: d.task_count,
                        running_ns: 0,
                        runnable_wait_ns: d.wait_ns,
                        runnable_delay_fraction: 0.0,
                        timeslices: 1,
                    })
                    .collect(),
            );
            c.elapsed = Duration::from_millis(fixture.window_ms);
            c.host.utilization_fraction = fixture.host_utilization_fraction.unwrap_or(0.0);
            c.host.cpu_count = fixture.logical_cpu_count.unwrap_or(8);
            c.load = fixture
                .runnable_tasks
                .map(|runnable_tasks| crate::cpu::LoadAverageRaw {
                    avg1: 0.0,
                    avg5: 0.0,
                    avg15: 0.0,
                    runnable_tasks,
                    total_tasks: runnable_tasks,
                    last_pid: 0,
                });
            if fixture.schedstat.as_deref() == Some("unsupported") {
                c.schedstat_capability = SchedstatCapability::Unsupported;
            }
            let finding = &analyze_cpu(
                Some(&psi(
                    fixture.psi_some_fraction,
                    Duration::from_millis(fixture.window_ms),
                )),
                Some(&c),
            )
            .findings[0];
            let json = serde_json::to_value(finding).unwrap();
            assert_eq!(json["kind"], fixture.expected_kind);
            assert_eq!(json["severity"], fixture.expected_severity);
            assert_eq!(finding.victims.len(), fixture.expected_victims);
            assert_eq!(finding.suspects.len(), fixture.expected_suspects);
            assert!(
                finding
                    .qualifiers
                    .iter()
                    .any(|q| q.kind == fixture.expected_qualifier)
            );
            assert_eq!(
                finding
                    .victims
                    .iter()
                    .map(|v| v.key.pid)
                    .collect::<Vec<_>>(),
                fixture.expected_victim_pids
            );
            assert_eq!(
                finding
                    .suspects
                    .iter()
                    .map(|s| s.key.pid)
                    .collect::<Vec<_>>(),
                fixture.expected_suspect_pids
            );
            assert_eq!(
                finding.suspects.iter().map(|s| s.label).collect::<Vec<_>>(),
                fixture
                    .expected_suspect_labels
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                finding
                    .suspects
                    .iter()
                    .map(|s| format!("{:?}", s.confidence).to_lowercase())
                    .collect::<Vec<_>>(),
                fixture.expected_suspect_confidences
            );
        }
    }
    fn process(pid: u32, fraction: f64) -> ProcessCpuInterval {
        ProcessCpuInterval {
            key: ProcessKey {
                pid,
                start_time_ticks: 1,
            },
            name: format!("p{pid}"),
            state: 'R',
            cpu_ticks: pid as u64,
            cpu_fraction_of_one: fraction,
        }
    }
    fn delay(pid: u32, wait: u64) -> ProcessSchedulerDelayInterval {
        ProcessSchedulerDelayInterval {
            key: ProcessKey {
                pid,
                start_time_ticks: 1,
            },
            name: format!("p{pid}"),
            task_count: 1,
            running_ns: 0,
            runnable_wait_ns: wait,
            runnable_delay_fraction: 0.0,
            timeslices: 1,
        }
    }
    #[test]
    fn threshold_edges_and_confidence_are_deterministic() {
        let c = cpu(vec![], vec![]);
        for (value, severity) in [
            (0.009_999, Severity::None),
            (0.01, Severity::Low),
            (0.049_999, Severity::Low),
            (0.05, Severity::Moderate),
            (0.149_999, Severity::Moderate),
            (0.15, Severity::High),
            (0.299_999, Severity::High),
            (0.30, Severity::Severe),
        ] {
            assert_eq!(severity_for_psi(value), severity);
        }
        assert_eq!(
            analyze_cpu(Some(&psi(0.2, Duration::from_secs(1))), Some(&c)).findings[0]
                .resource_confidence,
            Confidence::Medium
        );
        assert_eq!(
            analyze_cpu(Some(&psi(0.2, Duration::from_millis(4_999))), Some(&c)).findings[0]
                .resource_confidence,
            Confidence::Medium
        );
        assert_eq!(
            analyze_cpu(Some(&psi(0.2, Duration::from_secs(5))), Some(&c)).findings[0]
                .resource_confidence,
            Confidence::High
        );
        let mut requested_short = psi(0.2, Duration::from_secs(1));
        requested_short.requested = Duration::from_millis(100);
        assert_eq!(
            analyze_cpu(Some(&requested_short), Some(&c)).findings[0].kind,
            AssessmentKind::InsufficientObservation
        );
        let mut exact_one = psi(0.2, Duration::from_secs(1));
        exact_one.requested = Duration::from_secs(1);
        assert_eq!(
            analyze_cpu(Some(&exact_one), Some(&c)).findings[0].resource_confidence,
            Confidence::Medium
        );
    }
    #[test]
    fn missing_intervals_and_suspect_boundary_are_conservative() {
        let c = cpu(vec![process(1, 0.25), process(2, 0.249_999)], vec![]);
        let f = &analyze_cpu(Some(&psi(0.2, Duration::from_secs(10))), Some(&c)).findings[0];
        assert_eq!(
            f.suspects.iter().map(|x| x.key.pid).collect::<Vec<_>>(),
            vec![1]
        );
        let no_cpu = analyze_cpu(Some(&psi(0.2, Duration::from_secs(10))), None);
        assert_eq!(no_cpu.findings[0].kind, AssessmentKind::CpuContention);
        assert!(
            no_cpu.findings[0]
                .qualifiers
                .iter()
                .any(|q| q.kind == "cpu_context_unavailable")
        );
        assert!(analyze_cpu(None, Some(&c)).findings.is_empty());
        assert_eq!(
            analyze_cpu(Some(&psi(0.2, Duration::from_millis(999))), Some(&c)).findings[0].kind,
            AssessmentKind::InsufficientObservation
        );
    }
    #[test]
    fn attribution_limits_and_top_n_are_enforced() {
        let mut c = cpu(
            (1..=5).rev().map(|pid| process(pid, 0.5)).collect(),
            (1..=6).rev().map(|pid| delay(pid, 100)).collect(),
        );
        let f = &analyze_cpu(Some(&psi(0.2, Duration::from_secs(10))), Some(&c)).findings[0];
        assert_eq!(
            f.suspects.iter().map(|x| x.key.pid).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            f.victims.iter().map(|x| x.key.pid).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        c.collection_issues.appeared = 1;
        c.schedstat_capability = SchedstatCapability::Partial;
        let f = &analyze_cpu(Some(&psi(0.2, Duration::from_secs(10))), Some(&c)).findings[0];
        assert!(f.suspects.iter().all(|x| x.confidence == Confidence::Low));
        assert!(f.victims.iter().all(|x| x.confidence == Confidence::Medium));
        assert!(
            f.qualifiers
                .iter()
                .any(|q| q.kind == "suspect_attribution_limited")
        );
        assert!(
            f.qualifiers
                .iter()
                .any(|q| q.kind == "victim_attribution_limited")
        );
    }
    #[test]
    fn no_contention_keeps_positive_delay_as_context() {
        let c = cpu(vec![process(1, 1.0)], vec![delay(1, 100)]);
        let f = &analyze_cpu(Some(&psi(0.005, Duration::from_secs(10))), Some(&c)).findings[0];
        assert!(f.victims.is_empty() && f.suspects.is_empty());
        assert!(
            f.qualifiers
                .iter()
                .any(|q| q.kind == "scheduler_delay_context")
        );
    }
    #[test]
    fn low_share_consumer_is_never_called_major_or_causal() {
        let mut c = cpu(vec![process(1, 0.25)], vec![]);
        c.host.cpu_count = 128;
        c.host.utilization_fraction = 1.0;
        let suspect = &analyze_cpu(Some(&psi(0.2, Duration::from_secs(10))), Some(&c)).findings[0]
            .suspects[0];
        assert_eq!(suspect.label, "leading_concurrent_cpu_consumer");
        assert!(suspect.confidence <= Confidence::Medium);
        assert!(!suspect.label.contains("major") && !suspect.label.contains("cause"));
    }
    #[derive(Deserialize)]
    struct Fixture {
        schema: String,
        psi_some_fraction: f64,
        window_ms: u64,
        host_utilization_fraction: Option<f64>,
        runnable_tasks: Option<u64>,
        logical_cpu_count: Option<u32>,
        schedstat: Option<String>,
        #[serde(default)]
        processes: Vec<FixtureProcess>,
        #[serde(default)]
        delays: Vec<FixtureDelay>,
        expected_kind: String,
        expected_severity: String,
        expected_victims: usize,
        expected_suspects: usize,
        expected_qualifier: String,
        #[serde(default)]
        expected_victim_pids: Vec<u32>,
        #[serde(default)]
        expected_suspect_pids: Vec<u32>,
        #[serde(default)]
        expected_suspect_labels: Vec<String>,
        #[serde(default)]
        expected_suspect_confidences: Vec<String>,
    }
    #[derive(Deserialize)]
    struct FixtureProcess {
        pid: u32,
        cpu_fraction: f64,
        cpu_ticks: u64,
    }
    #[derive(Deserialize)]
    struct FixtureDelay {
        pid: u32,
        wait_ns: u64,
        task_count: u32,
    }
}
