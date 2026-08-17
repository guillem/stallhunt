use std::fs;
use std::io;
#[cfg(test)]
use std::thread;
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

pub const CPU_PSI_PATH: &str = "/proc/pressure/cpu";
pub const MEMORY_PSI_PATH: &str = "/proc/pressure/memory";

/// A direct CPU PSI `some` reading. `total_us` is cumulative since boot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CpuPsiRaw {
    pub avg10_percent: f64,
    pub avg60_percent: f64,
    pub avg300_percent: f64,
    pub total_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CpuPsiInterval {
    pub elapsed: Duration,
    pub total_delta_us: u64,
    pub some_fraction: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuPsiCapability {
    Available,
    Unsupported,
    PermissionDenied,
    Failed,
}

impl CpuPsiCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unsupported => "unsupported",
            Self::PermissionDenied => "permission_denied",
            Self::Failed => "failed",
        }
    }

    pub const fn explanation(self) -> &'static str {
        match self {
            Self::Available => "CPU PSI is readable and valid.",
            Self::Unsupported => "The kernel does not expose /proc/pressure/cpu.",
            Self::PermissionDenied => "Permission was denied while reading CPU PSI.",
            Self::Failed => "CPU PSI could not be read or parsed.",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CpuPsiObservation {
    pub requested: Duration,
    pub interval: CpuPsiInterval,
    pub start: CpuPsiRaw,
    pub end: CpuPsiRaw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuPsiError {
    Unsupported,
    PermissionDenied,
    Unreadable,
    Malformed,
    CounterRegressed,
    EmptyInterval,
    DeltaExceedsElapsed,
}

impl CpuPsiError {
    pub const fn capability(self) -> CpuPsiCapability {
        match self {
            Self::Unsupported => CpuPsiCapability::Unsupported,
            Self::PermissionDenied => CpuPsiCapability::PermissionDenied,
            Self::Unreadable | Self::Malformed => CpuPsiCapability::Failed,
            Self::CounterRegressed | Self::EmptyInterval | Self::DeltaExceedsElapsed => {
                CpuPsiCapability::Available
            }
        }
    }

    pub const fn explanation(self) -> &'static str {
        match self {
            Self::Unsupported => "The kernel does not expose /proc/pressure/cpu.",
            Self::PermissionDenied => "Permission was denied while reading CPU PSI.",
            Self::Unreadable => "CPU PSI could not be read.",
            Self::Malformed => "CPU PSI was readable but did not match the expected kernel format.",
            Self::CounterRegressed => "CPU PSI cumulative total decreased during the observation.",
            Self::EmptyInterval => "CPU PSI snapshots did not have a measurable interval.",
            Self::DeltaExceedsElapsed => {
                "CPU PSI cumulative delta exceeded the measured observation interval."
            }
        }
    }
}

pub fn probe_cpu_psi() -> CpuPsiCapability {
    match read_cpu_psi() {
        Ok(_) => CpuPsiCapability::Available,
        Err(error) => error.capability(),
    }
}

#[cfg(test)]
pub fn observe_cpu_psi(requested: Duration) -> Result<CpuPsiObservation, CpuPsiError> {
    if requested.is_zero() {
        return Err(CpuPsiError::EmptyInterval);
    }

    let start = read_cpu_psi()?;
    let started_at = Instant::now();
    thread::sleep(requested);
    let end = read_cpu_psi()?;
    let elapsed = started_at.elapsed();
    let interval = interval_from_raw(start, end, elapsed)?;

    Ok(CpuPsiObservation {
        requested,
        interval,
        start,
        end,
    })
}

pub fn interval_from_raw(
    start: CpuPsiRaw,
    end: CpuPsiRaw,
    elapsed: Duration,
) -> Result<CpuPsiInterval, CpuPsiError> {
    let elapsed_us = elapsed.as_micros();
    if elapsed_us == 0 {
        return Err(CpuPsiError::EmptyInterval);
    }

    let total_delta_us = end
        .total_us
        .checked_sub(start.total_us)
        .ok_or(CpuPsiError::CounterRegressed)?;
    if u128::from(total_delta_us) > elapsed_us {
        return Err(CpuPsiError::DeltaExceedsElapsed);
    }
    let some_fraction = total_delta_us as f64 / elapsed_us as f64;

    Ok(CpuPsiInterval {
        elapsed,
        total_delta_us,
        some_fraction,
    })
}

pub fn read_cpu_psi() -> Result<CpuPsiRaw, CpuPsiError> {
    let contents = fs::read_to_string(CPU_PSI_PATH).map_err(classify_read_error)?;
    parse_cpu_psi(&contents)
}

fn classify_read_error(error: io::Error) -> CpuPsiError {
    match error.kind() {
        io::ErrorKind::NotFound => CpuPsiError::Unsupported,
        io::ErrorKind::PermissionDenied => CpuPsiError::PermissionDenied,
        _ => CpuPsiError::Unreadable,
    }
}

pub fn parse_cpu_psi(input: &str) -> Result<CpuPsiRaw, CpuPsiError> {
    let mut some = None;
    let mut full_seen = false;

    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let kind = fields.next().ok_or(CpuPsiError::Malformed)?;
        if kind == "full" {
            if full_seen {
                return Err(CpuPsiError::Malformed);
            }
            full_seen = true;
            continue;
        }
        if kind != "some" || some.is_some() {
            return Err(CpuPsiError::Malformed);
        }

        let mut avg10 = None;
        let mut avg60 = None;
        let mut avg300 = None;
        let mut total = None;
        for field in fields {
            let (name, value) = field.split_once('=').ok_or(CpuPsiError::Malformed)?;
            match name {
                "avg10" => set_once(&mut avg10, parse_nonnegative_float(value)?)?,
                "avg60" => set_once(&mut avg60, parse_nonnegative_float(value)?)?,
                "avg300" => set_once(&mut avg300, parse_nonnegative_float(value)?)?,
                "total" => set_once(
                    &mut total,
                    value.parse().map_err(|_| CpuPsiError::Malformed)?,
                )?,
                _ => {}
            }
        }
        some = Some(CpuPsiRaw {
            avg10_percent: avg10.ok_or(CpuPsiError::Malformed)?,
            avg60_percent: avg60.ok_or(CpuPsiError::Malformed)?,
            avg300_percent: avg300.ok_or(CpuPsiError::Malformed)?,
            total_us: total.ok_or(CpuPsiError::Malformed)?,
        });
    }

    some.ok_or(CpuPsiError::Malformed)
}

fn parse_nonnegative_float(value: &str) -> Result<f64, CpuPsiError> {
    let parsed = value.parse::<f64>().map_err(|_| CpuPsiError::Malformed)?;
    if parsed.is_finite() && (0.0..=100.0).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(CpuPsiError::Malformed)
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), CpuPsiError> {
    if slot.replace(value).is_some() {
        Err(CpuPsiError::Malformed)
    } else {
        Ok(())
    }
}

/// One fully parsed PSI line. `total_us` is cumulative since boot.
///
/// Memory PSI retains both `some` and `full`, unlike CPU PSI where host-level
/// `full` has intentionally been treated as compatibility-only data.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemoryPsiLine {
    pub avg10_percent: f64,
    pub avg60_percent: f64,
    pub avg300_percent: f64,
    pub total_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemoryPsiRaw {
    pub some: MemoryPsiLine,
    pub full: Option<MemoryPsiLine>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemoryPsiLineInterval {
    pub total_delta_us: u64,
    pub fraction: f64,
}

/// The `full` interval is independently qualified so valid `some` evidence
/// remains available when a kernel exposes no `full` line or only that counter
/// is inconsistent between endpoints.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryPsiFullInterval {
    Available(MemoryPsiLineInterval),
    Missing,
    CounterRegressed,
    DeltaExceedsElapsed,
    ExceedsSome,
}

impl MemoryPsiFullInterval {
    /// Explains the `full` dimension without changing the broader capability
    /// state. This is used when valid memory-PSI `some` evidence is retained.
    pub const fn explanation(self) -> &'static str {
        match self {
            Self::Available(_) => "Memory PSI `some` and `full` have valid exact intervals.",
            Self::Missing => {
                "Memory PSI `some` has a valid exact interval, but `full` was absent at one or both snapshots."
            }
            Self::CounterRegressed => {
                "Memory PSI `some` has a valid exact interval, but `full` cumulative total decreased during the observation."
            }
            Self::DeltaExceedsElapsed => {
                "Memory PSI `some` has a valid exact interval, but `full` cumulative delta exceeded the measured interval."
            }
            Self::ExceedsSome => {
                "Memory PSI `some` has a valid exact interval, but `full` exceeded `some` during the observation."
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemoryPsiInterval {
    pub elapsed: Duration,
    pub some: MemoryPsiLineInterval,
    pub full: MemoryPsiFullInterval,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemoryPsiObservation {
    pub requested: Duration,
    pub interval: MemoryPsiInterval,
    pub start: MemoryPsiRaw,
    pub end: MemoryPsiRaw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPsiCapability {
    Available,
    Partial,
    Unsupported,
    PermissionDenied,
    Failed,
}

impl MemoryPsiCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
            Self::PermissionDenied => "permission_denied",
            Self::Failed => "failed",
        }
    }

    pub const fn explanation(self) -> &'static str {
        match self {
            Self::Available => "Memory PSI `some` and `full` are readable and valid.",
            Self::Partial => "Memory PSI `some` is readable and valid, but `full` is absent.",
            Self::Unsupported => "The kernel does not expose /proc/pressure/memory.",
            Self::PermissionDenied => "Permission was denied while reading memory PSI.",
            Self::Failed => "Memory PSI could not be read or parsed.",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPsiError {
    Unsupported,
    PermissionDenied,
    Unreadable,
    Malformed,
    CounterRegressed,
    EmptyInterval,
    DeltaExceedsElapsed,
    FullExceedsSome,
}

impl MemoryPsiError {
    pub const fn capability(self) -> MemoryPsiCapability {
        match self {
            Self::Unsupported => MemoryPsiCapability::Unsupported,
            Self::PermissionDenied => MemoryPsiCapability::PermissionDenied,
            Self::Unreadable | Self::Malformed | Self::FullExceedsSome => {
                MemoryPsiCapability::Failed
            }
            Self::CounterRegressed | Self::EmptyInterval | Self::DeltaExceedsElapsed => {
                MemoryPsiCapability::Available
            }
        }
    }
}

pub fn probe_memory_psi() -> MemoryPsiCapability {
    match read_memory_psi() {
        Ok(raw) if raw.full.is_some() => MemoryPsiCapability::Available,
        Ok(_) => MemoryPsiCapability::Partial,
        Err(error) => error.capability(),
    }
}

pub fn read_memory_psi() -> Result<MemoryPsiRaw, MemoryPsiError> {
    let contents = fs::read_to_string(MEMORY_PSI_PATH).map_err(classify_memory_read_error)?;
    parse_memory_psi(&contents)
}

fn classify_memory_read_error(error: io::Error) -> MemoryPsiError {
    match error.kind() {
        io::ErrorKind::NotFound => MemoryPsiError::Unsupported,
        io::ErrorKind::PermissionDenied => MemoryPsiError::PermissionDenied,
        _ => MemoryPsiError::Unreadable,
    }
}

/// Parses memory PSI with one mandatory `some` line and one optional `full`
/// line. A present `full` line must be complete and semantically no greater
/// than `some`; malformed data is never silently discarded.
pub fn parse_memory_psi(input: &str) -> Result<MemoryPsiRaw, MemoryPsiError> {
    let mut some = None;
    let mut full = None;

    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let kind = fields.next().ok_or(MemoryPsiError::Malformed)?;
        let parsed = parse_memory_psi_line(fields)?;
        match kind {
            "some" if some.is_none() => some = Some(parsed),
            "full" if full.is_none() => full = Some(parsed),
            _ => return Err(MemoryPsiError::Malformed),
        }
    }

    let some = some.ok_or(MemoryPsiError::Malformed)?;
    if let Some(full) = full {
        ensure_full_not_greater_than_some(full, some)?;
    }
    Ok(MemoryPsiRaw { some, full })
}

fn parse_memory_psi_line<'a>(
    fields: impl Iterator<Item = &'a str>,
) -> Result<MemoryPsiLine, MemoryPsiError> {
    let mut avg10 = None;
    let mut avg60 = None;
    let mut avg300 = None;
    let mut total = None;
    for field in fields {
        let (name, value) = field.split_once('=').ok_or(MemoryPsiError::Malformed)?;
        match name {
            "avg10" => set_memory_once(&mut avg10, parse_memory_percent(value)?)?,
            "avg60" => set_memory_once(&mut avg60, parse_memory_percent(value)?)?,
            "avg300" => set_memory_once(&mut avg300, parse_memory_percent(value)?)?,
            "total" => set_memory_once(
                &mut total,
                value.parse().map_err(|_| MemoryPsiError::Malformed)?,
            )?,
            _ => {}
        }
    }
    Ok(MemoryPsiLine {
        avg10_percent: avg10.ok_or(MemoryPsiError::Malformed)?,
        avg60_percent: avg60.ok_or(MemoryPsiError::Malformed)?,
        avg300_percent: avg300.ok_or(MemoryPsiError::Malformed)?,
        total_us: total.ok_or(MemoryPsiError::Malformed)?,
    })
}

fn parse_memory_percent(value: &str) -> Result<f64, MemoryPsiError> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| MemoryPsiError::Malformed)?;
    if parsed.is_finite() && (0.0..=100.0).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(MemoryPsiError::Malformed)
    }
}

fn set_memory_once<T>(slot: &mut Option<T>, value: T) -> Result<(), MemoryPsiError> {
    if slot.replace(value).is_some() {
        Err(MemoryPsiError::Malformed)
    } else {
        Ok(())
    }
}

fn ensure_full_not_greater_than_some(
    full: MemoryPsiLine,
    some: MemoryPsiLine,
) -> Result<(), MemoryPsiError> {
    if full.avg10_percent > some.avg10_percent
        || full.avg60_percent > some.avg60_percent
        || full.avg300_percent > some.avg300_percent
        || full.total_us > some.total_us
    {
        Err(MemoryPsiError::FullExceedsSome)
    } else {
        Ok(())
    }
}

/// Normalizes memory PSI totals across the measured monotonic interval.
/// `some` failures reject the observation. `full` failures qualify only the
/// `full` dimension, preserving the valid `some` interval.
pub fn memory_interval_from_raw(
    start: MemoryPsiRaw,
    end: MemoryPsiRaw,
    elapsed: Duration,
) -> Result<MemoryPsiInterval, MemoryPsiError> {
    let elapsed_us = elapsed.as_micros();
    if elapsed_us == 0 {
        return Err(MemoryPsiError::EmptyInterval);
    }
    let some = memory_line_interval(start.some, end.some, elapsed_us)?;
    let full = match (start.full, end.full) {
        (Some(start), Some(end)) => match memory_line_interval(start, end, elapsed_us) {
            Ok(full) if full.total_delta_us <= some.total_delta_us => {
                MemoryPsiFullInterval::Available(full)
            }
            Ok(_) => MemoryPsiFullInterval::ExceedsSome,
            Err(MemoryPsiError::CounterRegressed) => MemoryPsiFullInterval::CounterRegressed,
            Err(MemoryPsiError::DeltaExceedsElapsed) => MemoryPsiFullInterval::DeltaExceedsElapsed,
            Err(_) => unreachable!("memory line intervals only return counter errors"),
        },
        _ => MemoryPsiFullInterval::Missing,
    };
    Ok(MemoryPsiInterval {
        elapsed,
        some,
        full,
    })
}

fn memory_line_interval(
    start: MemoryPsiLine,
    end: MemoryPsiLine,
    elapsed_us: u128,
) -> Result<MemoryPsiLineInterval, MemoryPsiError> {
    let total_delta_us = end
        .total_us
        .checked_sub(start.total_us)
        .ok_or(MemoryPsiError::CounterRegressed)?;
    if u128::from(total_delta_us) > elapsed_us {
        return Err(MemoryPsiError::DeltaExceedsElapsed);
    }
    Ok(MemoryPsiLineInterval {
        total_delta_us,
        fraction: total_delta_us as f64 / elapsed_us as f64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = include_str!("../tests/fixtures/proc-pressure-cpu-valid");
    const MEMORY_VALID: &str = include_str!("../tests/fixtures/proc-pressure-memory-valid");

    #[test]
    fn parses_cpu_psi_fixture() {
        assert_eq!(
            parse_cpu_psi(VALID),
            Ok(CpuPsiRaw {
                avg10_percent: 1.25,
                avg60_percent: 0.5,
                avg300_percent: 0.12,
                total_us: 9_876_543_210,
            })
        );
    }

    #[test]
    fn parser_accepts_extra_kernel_fields_but_requires_the_known_fields() {
        let parsed =
            parse_cpu_psi("\t some  total=20 avg300=0.00 future=ok avg10=1.00 avg60=0.50 \n\n");
        assert_eq!(parsed.unwrap().total_us, 20);
        assert!(matches!(
            parse_cpu_psi("some avg10=1 avg60=2 total=3\n"),
            Err(CpuPsiError::Malformed)
        ));
    }

    #[test]
    fn parser_rejects_malformed_and_non_cpu_psi_input() {
        for input in [
            "some avg10=nan avg60=0 avg300=0 total=1\n",
            "some avg10=inf avg60=0 avg300=0 total=1\n",
            "some avg10=-0.1 avg60=0 avg300=0 total=1\n",
            "some avg10=0 avg10=0 avg60=0 avg300=0 total=1\n",
            "some avg10=101 avg60=0 avg300=0 total=1\n",
            "some avg10=0 avg60=0 avg300=0 total=-1\n",
            "some avg10=0 avg60=0 avg300=0 total=18446744073709551616\n",
            "some avg10=0 avg60=0 avg300=0 total=nope\n",
            "future avg10=0 avg60=0 avg300=0 total=1\n",
        ] {
            assert_eq!(parse_cpu_psi(input), Err(CpuPsiError::Malformed));
        }
    }

    #[test]
    fn interval_uses_cumulative_total_delta_and_actual_elapsed_time() {
        let start = CpuPsiRaw {
            avg10_percent: 0.0,
            avg60_percent: 0.0,
            avg300_percent: 0.0,
            total_us: 1_000,
        };
        let end = CpuPsiRaw {
            total_us: 251_000,
            ..start
        };
        let interval = interval_from_raw(start, end, Duration::from_millis(500)).unwrap();

        assert_eq!(interval.total_delta_us, 250_000);
        assert!((interval.some_fraction - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn interval_rejects_counter_regression_and_empty_windows() {
        let raw = CpuPsiRaw {
            avg10_percent: 0.0,
            avg60_percent: 0.0,
            avg300_percent: 0.0,
            total_us: 10,
        };
        assert_eq!(
            interval_from_raw(
                raw,
                CpuPsiRaw { total_us: 9, ..raw },
                Duration::from_secs(1)
            ),
            Err(CpuPsiError::CounterRegressed)
        );
        assert_eq!(
            interval_from_raw(raw, raw, Duration::ZERO),
            Err(CpuPsiError::EmptyInterval)
        );
        assert_eq!(
            interval_from_raw(
                raw,
                CpuPsiRaw {
                    total_us: 1_000_011,
                    ..raw
                },
                Duration::from_secs(1)
            ),
            Err(CpuPsiError::DeltaExceedsElapsed)
        );
    }

    #[test]
    fn parser_ignores_an_uninterpreted_full_line() {
        let parsed = parse_cpu_psi(
            "some avg10=0 avg60=0 avg300=0 total=1\nfull avg10=0 avg60=0 avg300=0 total=0\n",
        );
        assert_eq!(parsed.unwrap().total_us, 1);
        assert!(
            parse_cpu_psi("some avg10=0 avg60=0 avg300=0 total=1\nfull future-format\n").is_ok()
        );
    }

    #[test]
    fn parser_rejects_duplicate_some_and_full_lines() {
        for input in [
            "some avg10=0 avg60=0 avg300=0 total=1\nsome avg10=0 avg60=0 avg300=0 total=2\n",
            "some avg10=0 avg60=0 avg300=0 total=1\nfull avg10=0 avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0\n",
        ] {
            assert_eq!(parse_cpu_psi(input), Err(CpuPsiError::Malformed));
        }
    }

    #[test]
    fn observation_rejects_a_zero_requested_duration_before_reading() {
        assert_eq!(
            observe_cpu_psi(Duration::ZERO),
            Err(CpuPsiError::EmptyInterval)
        );
    }

    #[test]
    fn read_errors_map_to_explicit_capability_states() {
        assert_eq!(
            classify_read_error(io::Error::from(io::ErrorKind::NotFound)),
            CpuPsiError::Unsupported
        );
        assert_eq!(
            classify_read_error(io::Error::from(io::ErrorKind::PermissionDenied)),
            CpuPsiError::PermissionDenied
        );
        assert_eq!(
            classify_read_error(io::Error::from(io::ErrorKind::Other)),
            CpuPsiError::Unreadable
        );
    }

    #[test]
    fn parses_memory_psi_fixture_and_retains_both_lines() {
        assert_eq!(
            parse_memory_psi(MEMORY_VALID),
            Ok(MemoryPsiRaw {
                some: MemoryPsiLine {
                    avg10_percent: 2.5,
                    avg60_percent: 1.25,
                    avg300_percent: 0.75,
                    total_us: 9_000,
                },
                full: Some(MemoryPsiLine {
                    avg10_percent: 1.0,
                    avg60_percent: 0.5,
                    avg300_percent: 0.25,
                    total_us: 4_000,
                }),
            })
        );
    }

    #[test]
    fn memory_psi_some_without_full_is_partial_but_valid() {
        let raw = parse_memory_psi("some avg10=1 avg60=0.5 avg300=0.25 total=100\n").unwrap();
        assert_eq!(raw.full, None);
        assert_eq!(
            memory_interval_from_raw(
                raw,
                MemoryPsiRaw {
                    some: MemoryPsiLine {
                        total_us: 600,
                        ..raw.some
                    },
                    full: None,
                },
                Duration::from_millis(1)
            )
            .unwrap()
            .full,
            MemoryPsiFullInterval::Missing
        );
    }

    #[test]
    fn memory_parser_rejects_malformed_duplicate_and_invalid_full_lines() {
        for input in [
            "some avg10=1 avg60=1 avg300=1 total=1\nfull avg10=1 avg60=1 total=1\n",
            "some avg10=1 avg60=1 avg300=1 total=1\nsome avg10=1 avg60=1 avg300=1 total=1\n",
            "some avg10=1 avg60=1 avg300=1 total=1\nfull avg10=1 avg60=1 avg300=1 total=1\nfull avg10=1 avg60=1 avg300=1 total=1\n",
        ] {
            assert_eq!(parse_memory_psi(input), Err(MemoryPsiError::Malformed));
        }
        assert_eq!(
            parse_memory_psi(
                "some avg10=1 avg60=1 avg300=1 total=10\nfull avg10=2 avg60=1 avg300=1 total=9\n"
            ),
            Err(MemoryPsiError::FullExceedsSome)
        );
        assert_eq!(
            MemoryPsiError::FullExceedsSome.capability(),
            MemoryPsiCapability::Failed
        );
    }

    #[test]
    fn memory_intervals_normalize_some_and_full_and_check_boundaries() {
        let start = MemoryPsiRaw {
            some: MemoryPsiLine {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 100,
            },
            full: Some(MemoryPsiLine {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 50,
            }),
        };
        let end = MemoryPsiRaw {
            some: MemoryPsiLine {
                total_us: 1_100,
                ..start.some
            },
            full: Some(MemoryPsiLine {
                total_us: 550,
                ..start.full.unwrap()
            }),
        };
        let interval = memory_interval_from_raw(start, end, Duration::from_millis(1)).unwrap();
        assert_eq!(interval.some.total_delta_us, 1_000);
        assert_eq!(interval.some.fraction, 1.0);
        assert_eq!(
            interval.full,
            MemoryPsiFullInterval::Available(MemoryPsiLineInterval {
                total_delta_us: 500,
                fraction: 0.5,
            })
        );
        assert_eq!(
            memory_interval_from_raw(start, end, Duration::ZERO),
            Err(MemoryPsiError::EmptyInterval)
        );
        assert_eq!(
            memory_interval_from_raw(
                start,
                MemoryPsiRaw {
                    some: MemoryPsiLine {
                        total_us: 1_101,
                        ..start.some
                    },
                    full: end.full,
                },
                Duration::from_millis(1)
            ),
            Err(MemoryPsiError::DeltaExceedsElapsed)
        );
    }

    #[test]
    fn memory_full_interval_problems_do_not_discard_valid_some_evidence() {
        let start = MemoryPsiRaw {
            some: MemoryPsiLine {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 100,
            },
            full: Some(MemoryPsiLine {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 100,
            }),
        };
        let full = start.full.unwrap();
        for (full, expected) in [
            (
                MemoryPsiLine {
                    total_us: 99,
                    ..full
                },
                MemoryPsiFullInterval::CounterRegressed,
            ),
            (
                MemoryPsiLine {
                    total_us: 1_101,
                    ..full
                },
                MemoryPsiFullInterval::DeltaExceedsElapsed,
            ),
            (
                MemoryPsiLine {
                    total_us: 701,
                    ..full
                },
                MemoryPsiFullInterval::ExceedsSome,
            ),
        ] {
            let interval = memory_interval_from_raw(
                start,
                MemoryPsiRaw {
                    some: MemoryPsiLine {
                        total_us: 600,
                        ..start.some
                    },
                    full: Some(full),
                },
                Duration::from_millis(1),
            )
            .unwrap();
            assert_eq!(interval.some.total_delta_us, 500);
            assert_eq!(interval.full, expected);
        }
    }

    #[test]
    fn memory_full_interval_explanations_distinguish_absence_from_invalid_data() {
        assert!(
            MemoryPsiFullInterval::Missing
                .explanation()
                .contains("absent")
        );
        assert!(
            MemoryPsiFullInterval::CounterRegressed
                .explanation()
                .contains("decreased")
        );
        assert!(
            MemoryPsiFullInterval::DeltaExceedsElapsed
                .explanation()
                .contains("exceeded the measured interval")
        );
        assert!(
            MemoryPsiFullInterval::ExceedsSome
                .explanation()
                .contains("exceeded `some`")
        );
    }

    #[test]
    fn memory_read_errors_have_explicit_capabilities() {
        assert_eq!(
            classify_memory_read_error(io::Error::from(io::ErrorKind::NotFound)),
            MemoryPsiError::Unsupported
        );
        assert_eq!(
            classify_memory_read_error(io::Error::from(io::ErrorKind::PermissionDenied)),
            MemoryPsiError::PermissionDenied
        );
    }
}
