//! Bounded, request-only TASKSTATS generic-netlink collection.
//!
//! The wire codec deliberately uses byte offsets and checked slices.  Linux's
//! UAPI structs must not be reinterpreted as Rust layouts: that would make
//! padding, alignment, and future kernel extensions part of our ABI.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_GENERIC};
use rustix::net::{
    RecvFlags,
    sockopt::{Timeout, set_socket_timeout},
};
use serde::{Deserialize, Serialize};

use crate::cpu::{ProcessKey, parse_process_stat};

pub const MAX_TGIDS: usize = 512;
const MAX_REPLY_BYTES: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_millis(20);
const TOTAL_TIMEOUT: Duration = Duration::from_millis(100);
const NLMSG_HDR: usize = 16;
const GENL_HDR: usize = 4;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_MULTI: u16 = 2;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const GENL_ID_CTRL: u16 = 16;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const TASKSTATS_CMD_GET: u8 = 1;
const TASKSTATS_CMD_ATTR_TGID: u16 = 2;
const TASKSTATS_TYPE_TGID: u16 = 2;
const TASKSTATS_TYPE_STATS: u16 = 3;
const TASKSTATS_TYPE_AGGR_TGID: u16 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TaskstatsCapability {
    /// The recording schema did not retain TASKSTATS evidence.
    #[default]
    NotRecorded,
    Available,
    Partial,
    Unsupported,
    PermissionDenied,
    TimedOut,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DelayAccountingState {
    Enabled,
    Disabled,
    /// The transport worked. Counter values, including zero, do not establish
    /// whether `kernel.task_delayacct` was enabled for the process lifetime.
    Unknown,
    #[default]
    Unavailable,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskstatsCollectionIssues {
    pub selected_tgids: u32,
    pub queried_tgids: u32,
    pub churned: u32,
    pub permission_denied: u32,
    pub timed_out: u32,
    pub malformed: u32,
    pub reply_budget_exhausted: bool,
    pub time_budget_exhausted: bool,
    pub tgid_limit_reached: bool,
    pub counter_regressed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskstatsRaw {
    pub version: u16,
    pub cpu_delay_ns: Option<u64>,
    pub block_io_delay_ns: Option<u64>,
    pub swapin_delay_ns: Option<u64>,
    pub reclaim_delay_ns: Option<u64>,
    pub thrashing_delay_ns: Option<u64>,
    pub compaction_delay_ns: Option<u64>,
    pub write_protect_copy_delay_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskstatsInterval {
    pub key: ProcessKey,
    /// The oldest TASKSTATS UAPI version observed at both ends of this
    /// interval.  A field introduced later than this cannot support a
    /// complete negative result, even when its decoded value is zero.
    #[serde(default)]
    pub min_uapi_version: u16,
    #[serde(default)]
    pub field_support: TaskstatsFieldSupport,
    pub cpu_delay_ns: Option<u64>,
    pub block_io_delay_ns: Option<u64>,
    pub swapin_delay_ns: Option<u64>,
    pub reclaim_delay_ns: Option<u64>,
    pub thrashing_delay_ns: Option<u64>,
    pub compaction_delay_ns: Option<u64>,
    pub write_protect_copy_delay_ns: Option<u64>,
}

/// Per-field TASKSTATS support, retained independently from transport state.
/// `false` means the kernel version did not define the counter for this
/// interval (or an endpoint did not carry it); it is not a measured zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskstatsFieldSupport {
    pub cpu_delay: bool,
    pub block_io_delay: bool,
    pub swapin_delay: bool,
    pub reclaim_delay: bool,
    pub thrashing_delay: bool,
    pub compaction_delay: bool,
    pub write_protect_copy_delay: bool,
}

impl TaskstatsFieldSupport {
    fn for_version(version: u16) -> Self {
        Self {
            cpu_delay: version >= 1,
            block_io_delay: version >= 1,
            swapin_delay: version >= 1,
            reclaim_delay: version >= 7,
            thrashing_delay: version >= 9,
            compaction_delay: version >= 11,
            write_protect_copy_delay: version >= 13,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskstatsEndpoint {
    pub capability: TaskstatsCapability,
    pub delay_accounting: DelayAccountingState,
    pub values: BTreeMap<ProcessKey, TaskstatsRaw>,
    pub issues: TaskstatsCollectionIssues,
}

impl TaskstatsEndpoint {
    pub(crate) fn unavailable(capability: TaskstatsCapability) -> Self {
        Self {
            capability,
            delay_accounting: DelayAccountingState::Unavailable,
            values: BTreeMap::new(),
            issues: TaskstatsCollectionIssues::default(),
        }
    }
}

/// Query at most the lowest selected leaders. No PID enumeration occurs here:
/// callers pass identities already selected by the bounded procfs walk.
pub fn collect_at(
    proc_root: &Path,
    keys: impl IntoIterator<Item = ProcessKey>,
) -> TaskstatsEndpoint {
    let mut selected: Vec<_> = keys.into_iter().collect();
    selected.sort_unstable();
    selected.dedup();
    let mut endpoint = TaskstatsEndpoint::unavailable(TaskstatsCapability::Failed);
    endpoint.issues.selected_tgids =
        u32::try_from(selected.len().min(MAX_TGIDS)).unwrap_or(u32::MAX);
    endpoint.issues.tgid_limit_reached = selected.len() > MAX_TGIDS;
    selected.truncate(MAX_TGIDS);
    let started = Instant::now();
    let configured_delay_accounting = delay_accounting_state(proc_root);
    // This sysctl is an independent, point-in-time capability observation. It
    // remains useful when TASKSTATS transport is denied or unsupported, while
    // never proving the setting held for a process's whole lifetime.
    endpoint.delay_accounting = configured_delay_accounting;
    let mut transport = match NetlinkTransport::open() {
        Ok(value) => value,
        Err(error) => {
            endpoint.capability = map_io_capability(&error);
            return endpoint;
        }
    };
    let family = match transport.resolve_family(started) {
        Ok(id) => id,
        Err(error) => {
            endpoint.capability = map_error(&error, &mut endpoint.issues);
            return endpoint;
        }
    };
    endpoint.capability = TaskstatsCapability::Available;
    for key in selected {
        if started.elapsed() >= TOTAL_TIMEOUT {
            endpoint.issues.time_budget_exhausted = true;
            break;
        }
        // Bracket each GET with leader identity reads. Any mismatch is normal
        // process churn, never an attribution to a recycled PID.
        if !identity_matches(proc_root, key) {
            endpoint.issues.churned += 1;
            continue;
        }
        match transport.get(family, key.pid, started) {
            Ok(raw) if identity_matches(proc_root, key) => {
                endpoint.issues.queried_tgids += 1;
                endpoint.values.insert(key, raw);
            }
            Ok(_) => endpoint.issues.churned += 1,
            Err(TransportError::Kernel(-3)) => endpoint.issues.churned += 1, // ESRCH
            Err(error) => {
                endpoint.capability = map_error(&error, &mut endpoint.issues);
                if started.elapsed() >= TOTAL_TIMEOUT {
                    endpoint.issues.time_budget_exhausted = true;
                }
                if matches!(error, TransportError::Budget | TransportError::Timeout)
                    || matches!(
                        endpoint.capability,
                        TaskstatsCapability::PermissionDenied | TaskstatsCapability::Unsupported
                    )
                {
                    break;
                }
            }
        }
    }
    if endpoint.capability == TaskstatsCapability::Available
        && (!endpoint.values.is_empty() || endpoint.issues.queried_tgids == 0)
    {
        if endpoint.issues.churned != 0
            || endpoint.issues.tgid_limit_reached
            || endpoint.issues.time_budget_exhausted
        {
            endpoint.capability = TaskstatsCapability::Partial;
        }
    } else if endpoint.capability == TaskstatsCapability::Available {
        endpoint.capability = TaskstatsCapability::Partial;
    }
    endpoint
}

fn delay_accounting_state(proc_root: &Path) -> DelayAccountingState {
    match fs::read_to_string(proc_root.join("sys/kernel/task_delayacct")) {
        Ok(value) => delay_accounting_state_from_text(&value),
        Err(_) => DelayAccountingState::Unavailable,
    }
}

fn delay_accounting_state_from_text(value: &str) -> DelayAccountingState {
    match value.trim() {
        "1" => DelayAccountingState::Enabled,
        "0" => DelayAccountingState::Disabled,
        _ => DelayAccountingState::Unknown,
    }
}

fn identity_matches(proc_root: &Path, expected: ProcessKey) -> bool {
    fs::read_to_string(proc_root.join(expected.pid.to_string()).join("stat"))
        .ok()
        .and_then(|text| parse_process_stat(&text).ok())
        .is_some_and(|current| current.key == expected)
}

pub fn intervals(
    start: &TaskstatsEndpoint,
    end: &TaskstatsEndpoint,
) -> (
    Vec<TaskstatsInterval>,
    TaskstatsCollectionIssues,
    TaskstatsCapability,
    DelayAccountingState,
) {
    let mut issues = merge_issues(&start.issues, &end.issues);
    let mut values = Vec::new();
    for (key, right) in &end.values {
        let Some(left) = start.values.get(key) else {
            continue;
        };
        values.push(TaskstatsInterval {
            key: *key,
            min_uapi_version: left.version.min(right.version),
            field_support: TaskstatsFieldSupport::for_version(left.version.min(right.version)),
            cpu_delay_ns: delta(left.cpu_delay_ns, right.cpu_delay_ns, &mut issues),
            block_io_delay_ns: delta(left.block_io_delay_ns, right.block_io_delay_ns, &mut issues),
            swapin_delay_ns: delta(left.swapin_delay_ns, right.swapin_delay_ns, &mut issues),
            reclaim_delay_ns: delta(left.reclaim_delay_ns, right.reclaim_delay_ns, &mut issues),
            thrashing_delay_ns: delta(
                left.thrashing_delay_ns,
                right.thrashing_delay_ns,
                &mut issues,
            ),
            compaction_delay_ns: delta(
                left.compaction_delay_ns,
                right.compaction_delay_ns,
                &mut issues,
            ),
            write_protect_copy_delay_ns: delta(
                left.write_protect_copy_delay_ns,
                right.write_protect_copy_delay_ns,
                &mut issues,
            ),
        });
    }
    let cap = merge_capability(
        start.capability,
        end.capability,
        !values.is_empty(),
        issues.counter_regressed != 0,
    );
    let delay = merge_delay_accounting(start.delay_accounting, end.delay_accounting);
    (values, issues, cap, delay)
}

fn merge_capability(
    left: TaskstatsCapability,
    right: TaskstatsCapability,
    any_values: bool,
    regressed: bool,
) -> TaskstatsCapability {
    if any_values {
        return if left == TaskstatsCapability::Available
            && right == TaskstatsCapability::Available
            && !regressed
        {
            TaskstatsCapability::Available
        } else {
            TaskstatsCapability::Partial
        };
    }
    if left == right {
        left
    } else {
        TaskstatsCapability::Partial
    }
}

fn merge_delay_accounting(
    left: DelayAccountingState,
    right: DelayAccountingState,
) -> DelayAccountingState {
    if left == DelayAccountingState::Unavailable || right == DelayAccountingState::Unavailable {
        DelayAccountingState::Unavailable
    } else if left == right {
        left
    } else {
        DelayAccountingState::Unknown
    }
}

fn delta(
    left: Option<u64>,
    right: Option<u64>,
    issues: &mut TaskstatsCollectionIssues,
) -> Option<u64> {
    match (left, right) {
        (Some(a), Some(b)) => match b.checked_sub(a) {
            Some(x) => Some(x),
            None => {
                issues.counter_regressed = issues.counter_regressed.saturating_add(1);
                None
            }
        },
        _ => None,
    }
}
fn merge_issues(
    a: &TaskstatsCollectionIssues,
    b: &TaskstatsCollectionIssues,
) -> TaskstatsCollectionIssues {
    TaskstatsCollectionIssues {
        selected_tgids: a.selected_tgids.max(b.selected_tgids),
        queried_tgids: a.queried_tgids.saturating_add(b.queried_tgids),
        churned: a.churned.saturating_add(b.churned),
        permission_denied: a.permission_denied.saturating_add(b.permission_denied),
        timed_out: a.timed_out.saturating_add(b.timed_out),
        malformed: a.malformed.saturating_add(b.malformed),
        reply_budget_exhausted: a.reply_budget_exhausted || b.reply_budget_exhausted,
        time_budget_exhausted: a.time_budget_exhausted || b.time_budget_exhausted,
        tgid_limit_reached: a.tgid_limit_reached || b.tgid_limit_reached,
        counter_regressed: 0,
    }
}

#[derive(Debug)]
enum TransportError {
    Io(io::Error),
    Kernel(i32),
    Malformed,
    Budget,
    Timeout,
}
fn map_io_capability(error: &io::Error) -> TaskstatsCapability {
    if error.kind() == io::ErrorKind::PermissionDenied {
        TaskstatsCapability::PermissionDenied
    } else if error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::WouldBlock {
        TaskstatsCapability::TimedOut
    } else {
        TaskstatsCapability::Failed
    }
}
fn map_error(
    error: &TransportError,
    issues: &mut TaskstatsCollectionIssues,
) -> TaskstatsCapability {
    match error {
        TransportError::Io(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied {
                issues.permission_denied += 1;
            }
            if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock {
                issues.timed_out += 1;
            }
            map_io_capability(e)
        }
        TransportError::Kernel(-1) | TransportError::Kernel(-13) => {
            issues.permission_denied += 1;
            TaskstatsCapability::PermissionDenied
        }
        TransportError::Kernel(-2) | TransportError::Kernel(-95) => {
            TaskstatsCapability::Unsupported
        }
        TransportError::Timeout => {
            issues.timed_out += 1;
            issues.time_budget_exhausted = true;
            TaskstatsCapability::TimedOut
        }
        TransportError::Malformed => {
            issues.malformed += 1;
            TaskstatsCapability::Partial
        }
        TransportError::Budget => {
            issues.reply_budget_exhausted = true;
            TaskstatsCapability::Partial
        }
        TransportError::Kernel(_) => TaskstatsCapability::Partial,
    }
}

struct NetlinkTransport {
    socket: Socket,
    sequence: u32,
    reply_bytes: usize,
    receive_buffer: Vec<u8>,
}
impl NetlinkTransport {
    fn open() -> Result<Self, io::Error> {
        let mut socket = Socket::new(NETLINK_GENERIC)?;
        socket.bind_auto()?;
        Ok(Self {
            socket,
            sequence: 0,
            reply_bytes: 0,
            receive_buffer: vec![0; MAX_REPLY_BYTES],
        })
    }
    fn resolve_family(&mut self, started: Instant) -> Result<u16, TransportError> {
        let reply = self.request(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            &attr(CTRL_ATTR_FAMILY_NAME, b"TASKSTATS\0"),
            started,
        )?;
        let payload = generic_payload(&reply, GENL_ID_CTRL, self.sequence)?;
        for (typ, value) in attrs(payload)? {
            if typ == CTRL_ATTR_FAMILY_ID && value.len() == 2 {
                return Ok(u16::from_ne_bytes([value[0], value[1]]));
            }
        }
        Err(TransportError::Malformed)
    }
    fn get(
        &mut self,
        family: u16,
        tgid: u32,
        started: Instant,
    ) -> Result<TaskstatsRaw, TransportError> {
        let reply = self.request(
            family,
            TASKSTATS_CMD_GET,
            &attr(TASKSTATS_CMD_ATTR_TGID, &tgid.to_ne_bytes()),
            started,
        )?;
        parse_taskstats_reply(&reply, family, self.sequence, tgid)
    }
}

fn parse_taskstats_reply(
    reply: &[u8],
    family: u16,
    sequence: u32,
    tgid: u32,
) -> Result<TaskstatsRaw, TransportError> {
    let payload = generic_payload(reply, family, sequence)?;
    let mut found = None;
    for (typ, nested) in attrs(payload)? {
        if typ == TASKSTATS_TYPE_AGGR_TGID {
            let mut returned = None;
            let mut stats = None;
            for (inner, v) in attrs(nested)? {
                if inner == TASKSTATS_TYPE_TGID && v.len() == 4 {
                    returned = Some(u32::from_ne_bytes([v[0], v[1], v[2], v[3]]));
                } else if inner == TASKSTATS_TYPE_STATS {
                    stats = Some(v);
                }
            }
            if returned == Some(tgid) {
                found = stats.map(parse_taskstats).transpose()?;
            }
        }
    }
    found.ok_or(TransportError::Malformed)
}
impl NetlinkTransport {
    fn request(
        &mut self,
        family: u16,
        cmd: u8,
        attributes: &[u8],
        started: Instant,
    ) -> Result<Vec<u8>, TransportError> {
        self.sequence = self.sequence.wrapping_add(1);
        let message = message(family, self.sequence, cmd, attributes);
        self.set_remaining_timeout(started, Timeout::Send)?;
        self.socket
            .send_to(&message, &SocketAddr::new(0, 0), 0)
            .map_err(TransportError::Io)?;
        self.set_remaining_timeout(started, Timeout::Recv)?;
        // A fixed allocation plus MSG_TRUNC lets us reject an oversized
        // datagram without a peek-driven unbounded allocation.
        let remaining = MAX_REPLY_BYTES - self.reply_bytes;
        let mut receive = &mut self.receive_buffer[..remaining];
        let (length, sender) = self
            .socket
            .recv_from(
                &mut receive,
                i32::try_from(RecvFlags::TRUNC.bits()).unwrap_or(0),
            )
            .map_err(TransportError::Io)?;
        if sender.port_number() != 0 {
            return Err(TransportError::Malformed);
        }
        if !reply_fits_budget(self.reply_bytes, length) {
            return Err(TransportError::Budget);
        }
        self.reply_bytes += length;
        if started.elapsed() >= TOTAL_TIMEOUT {
            return Err(TransportError::Timeout);
        }
        let reply = self.receive_buffer[..length].to_vec();
        validate_netlink_datagram(&reply, family, self.sequence)?;
        Ok(reply)
    }
    fn set_remaining_timeout(
        &self,
        started: Instant,
        direction: Timeout,
    ) -> Result<(), TransportError> {
        let remaining = TOTAL_TIMEOUT
            .checked_sub(started.elapsed())
            .ok_or(TransportError::Timeout)?;
        let timeout = remaining.min(REQUEST_TIMEOUT);
        if timeout.is_zero() {
            return Err(TransportError::Timeout);
        }
        set_socket_timeout(&self.socket, direction, Some(timeout))
            .map_err(|error| TransportError::Io(io::Error::from(error)))
    }
}

fn reply_fits_budget(consumed: usize, received: usize) -> bool {
    received <= MAX_REPLY_BYTES.saturating_sub(consumed)
}

fn message(typ: u16, sequence: u32, cmd: u8, attributes: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDR + GENL_HDR + attributes.len();
    let mut out = Vec::with_capacity(len);
    put_u32(&mut out, u32::try_from(len).unwrap_or(u32::MAX));
    put_u16(&mut out, typ);
    put_u16(&mut out, NLM_F_REQUEST);
    put_u32(&mut out, sequence);
    put_u32(&mut out, 0);
    out.extend_from_slice(&[cmd, 1, 0, 0]);
    out.extend_from_slice(attributes);
    out
}
fn attr(typ: u16, value: &[u8]) -> Vec<u8> {
    let len = 4 + value.len();
    let mut out = Vec::with_capacity(align(len));
    put_u16(&mut out, u16::try_from(len).unwrap_or(u16::MAX));
    put_u16(&mut out, typ);
    out.extend_from_slice(value);
    out.resize(align(len), 0);
    out
}
fn generic_payload(
    message: &[u8],
    expected_type: u16,
    sequence: u32,
) -> Result<&[u8], TransportError> {
    validate_netlink_datagram(message, expected_type, sequence)?;
    let len = usize::try_from(u32_at(message, 0)?).map_err(|_| TransportError::Malformed)?;
    if len < NLMSG_HDR + GENL_HDR || len > message.len() {
        return Err(TransportError::Malformed);
    }
    Ok(&message[NLMSG_HDR + GENL_HDR..len])
}
fn validate_netlink_datagram(
    message: &[u8],
    expected_type: u16,
    sequence: u32,
) -> Result<(), TransportError> {
    if message.len() < NLMSG_HDR {
        return Err(TransportError::Malformed);
    }
    let len = usize::try_from(u32_at(message, 0)?).map_err(|_| TransportError::Malformed)?;
    if len < NLMSG_HDR || len > message.len() || align(len) != message.len() {
        return Err(TransportError::Malformed);
    }
    let typ = u16_at(message, 4)?;
    let flags = u16_at(message, 6)?;
    if u32_at(message, 8)? != sequence || typ == NLMSG_DONE || flags & NLM_F_MULTI != 0 {
        return Err(TransportError::Malformed);
    }
    if typ == NLMSG_ERROR {
        return Err(TransportError::Kernel(i32_at(message, NLMSG_HDR)?));
    }
    if typ != expected_type {
        return Err(TransportError::Malformed);
    }
    if len < NLMSG_HDR + GENL_HDR {
        return Err(TransportError::Malformed);
    }
    Ok(())
}
fn attrs(mut input: &[u8]) -> Result<Vec<(u16, &[u8])>, TransportError> {
    let mut result = Vec::new();
    while !input.is_empty() {
        if input.len() < 4 {
            return Err(TransportError::Malformed);
        }
        let len = usize::from(u16_at(input, 0)?);
        let typ = u16_at(input, 2)? & 0x3fff;
        if len < 4 || len > input.len() {
            return Err(TransportError::Malformed);
        }
        result.push((typ, &input[4..len]));
        let advance = align(len);
        if advance > input.len() {
            return Err(TransportError::Malformed);
        }
        input = &input[advance..];
    }
    Ok(result)
}
fn parse_taskstats(bytes: &[u8]) -> Result<TaskstatsRaw, TransportError> {
    let version = u16_at(bytes, 0)?;
    let required_prefix = match version {
        0 => return Err(TransportError::Malformed),
        1..=6 => 64,
        7..=8 => 328,
        9..=10 => 344,
        11..=12 => 368,
        _ => 416,
    };
    if bytes.len() < required_prefix {
        return Err(TransportError::Malformed);
    }
    Ok(TaskstatsRaw {
        version,
        cpu_delay_ns: field(bytes, version, 1, 24)?,
        block_io_delay_ns: field(bytes, version, 1, 40)?,
        swapin_delay_ns: field(bytes, version, 1, 56)?,
        reclaim_delay_ns: field(bytes, version, 7, 320)?,
        thrashing_delay_ns: field(bytes, version, 9, 336)?,
        compaction_delay_ns: field(bytes, version, 11, 360)?,
        write_protect_copy_delay_ns: field(bytes, version, 13, 408)?,
    })
}
fn field(
    bytes: &[u8],
    version: u16,
    minimum: u16,
    offset: usize,
) -> Result<Option<u64>, TransportError> {
    (version >= minimum)
        .then(|| u64_at(bytes, offset))
        .transpose()
}
fn align(value: usize) -> usize {
    (value + 3) & !3
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, TransportError> {
    let x = bytes
        .get(offset..offset + 2)
        .ok_or(TransportError::Malformed)?;
    Ok(u16::from_ne_bytes([x[0], x[1]]))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, TransportError> {
    let x = bytes
        .get(offset..offset + 4)
        .ok_or(TransportError::Malformed)?;
    Ok(u32::from_ne_bytes([x[0], x[1], x[2], x[3]]))
}
fn i32_at(bytes: &[u8], offset: usize) -> Result<i32, TransportError> {
    Ok(u32_at(bytes, offset)? as i32)
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, TransportError> {
    let x = bytes
        .get(offset..offset + 8)
        .ok_or(TransportError::Malformed)?;
    Ok(u64::from_ne_bytes([
        x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],
    ]))
}
fn put_u16(out: &mut Vec<u8>, x: u16) {
    out.extend_from_slice(&x.to_ne_bytes());
}
fn put_u32(out: &mut Vec<u8>, x: u32) {
    out.extend_from_slice(&x.to_ne_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn taskstats_offsets_and_version_prefixes_follow_the_uapi() {
        let cases = [
            (1, 64, 24),
            (1, 64, 40),
            (1, 64, 56),
            (7, 328, 320),
            (9, 344, 336),
            (11, 368, 360),
            (13, 416, 408),
        ];
        for (version, length, offset) in cases {
            let mut bytes = vec![0; length];
            bytes[0..2].copy_from_slice(&(version as u16).to_ne_bytes());
            bytes[offset..offset + 8].copy_from_slice(&99_u64.to_ne_bytes());
            let parsed = parse_taskstats(&bytes).unwrap();
            let actual = match offset {
                24 => parsed.cpu_delay_ns,
                40 => parsed.block_io_delay_ns,
                56 => parsed.swapin_delay_ns,
                320 => parsed.reclaim_delay_ns,
                336 => parsed.thrashing_delay_ns,
                360 => parsed.compaction_delay_ns,
                408 => parsed.write_protect_copy_delay_ns,
                _ => unreachable!(),
            };
            assert_eq!(actual, Some(99));
        }
        for (version, length, _) in cases {
            let mut bytes = vec![0; length - 1];
            bytes[0..2].copy_from_slice(&(version as u16).to_ne_bytes());
            assert!(parse_taskstats(&bytes).is_err());
        }
        let mut future = vec![0; 416];
        future[0..2].copy_from_slice(&99_u16.to_ne_bytes());
        assert!(parse_taskstats(&future).is_ok());
        future.pop();
        assert!(parse_taskstats(&future).is_err());
    }
    #[test]
    fn interval_retains_version_gated_field_support() {
        for (version, reclaim, thrashing, compaction, wpc) in [
            (1, false, false, false, false),
            (7, true, false, false, false),
            (9, true, true, false, false),
            (11, true, true, true, false),
            (13, true, true, true, true),
        ] {
            let support = TaskstatsFieldSupport::for_version(version);
            assert!(support.cpu_delay && support.block_io_delay && support.swapin_delay);
            assert_eq!(support.reclaim_delay, reclaim);
            assert_eq!(support.thrashing_delay, thrashing);
            assert_eq!(support.compaction_delay, compaction);
            assert_eq!(support.write_protect_copy_delay, wpc);
        }
    }
    macro_rules! support_case {
        ($name:ident, $version:expr, $field:ident) => {
            #[test]
            fn $name() {
                assert!(TaskstatsFieldSupport::for_version($version).$field);
            }
        };
    }
    support_case!(version_one_supports_baseline_cpu_delay, 1, cpu_delay);
    support_case!(version_seven_supports_reclaim_delay, 7, reclaim_delay);
    support_case!(version_nine_supports_thrashing_delay, 9, thrashing_delay);
    support_case!(
        version_eleven_supports_compaction_delay,
        11,
        compaction_delay
    );
    support_case!(
        version_thirteen_supports_write_protect_copy_delay,
        13,
        write_protect_copy_delay
    );
    #[test]
    fn attributes_reject_truncation_and_bad_padding() {
        assert!(attrs(&[4, 0, 1, 0, 1]).is_err());
        assert!(attrs(&[5, 0, 1, 0, 0]).is_err());
    }
    #[test]
    fn regression_is_unavailable_not_zero() {
        let key = ProcessKey {
            pid: 1,
            start_time_ticks: 2,
        };
        let raw = |n| TaskstatsRaw {
            version: 1,
            cpu_delay_ns: Some(n),
            block_io_delay_ns: None,
            swapin_delay_ns: None,
            reclaim_delay_ns: None,
            thrashing_delay_ns: None,
            compaction_delay_ns: None,
            write_protect_copy_delay_ns: None,
        };
        let left = TaskstatsEndpoint {
            capability: TaskstatsCapability::Available,
            delay_accounting: DelayAccountingState::Unknown,
            values: BTreeMap::from([(key, raw(4))]),
            issues: TaskstatsCollectionIssues::default(),
        };
        let right = TaskstatsEndpoint {
            values: BTreeMap::from([(key, raw(3))]),
            ..left.clone()
        };
        let (values, issues, _, _) = intervals(&left, &right);
        assert_eq!(values[0].cpu_delay_ns, None);
        assert_eq!(issues.counter_regressed, 1);
    }
    #[test]
    fn endpoint_capability_merge_is_symmetric() {
        assert_eq!(
            merge_capability(
                TaskstatsCapability::Available,
                TaskstatsCapability::PermissionDenied,
                false,
                false
            ),
            TaskstatsCapability::Partial
        );
        assert_eq!(
            merge_capability(
                TaskstatsCapability::PermissionDenied,
                TaskstatsCapability::Available,
                false,
                false
            ),
            TaskstatsCapability::Partial
        );
        assert_eq!(
            merge_capability(
                TaskstatsCapability::Unsupported,
                TaskstatsCapability::Unsupported,
                false,
                false
            ),
            TaskstatsCapability::Unsupported
        );
        assert_eq!(
            merge_capability(
                TaskstatsCapability::Available,
                TaskstatsCapability::Available,
                true,
                false
            ),
            TaskstatsCapability::Available
        );
        assert_eq!(
            merge_capability(
                TaskstatsCapability::Available,
                TaskstatsCapability::Available,
                true,
                true
            ),
            TaskstatsCapability::Partial
        );
    }
    #[test]
    fn netlink_framing_rejects_wrong_sequence_multi_and_trailing_messages() {
        let packet = message(42, 7, 1, &[]);
        assert!(validate_netlink_datagram(&packet, 42, 7).is_ok());
        assert!(validate_netlink_datagram(&packet, 42, 8).is_err());
        let mut multi = packet.clone();
        multi[6..8].copy_from_slice(&NLM_F_MULTI.to_ne_bytes());
        assert!(validate_netlink_datagram(&multi, 42, 7).is_err());
        let mut trailing = packet;
        trailing.extend_from_slice(&[0; 4]);
        assert!(validate_netlink_datagram(&trailing, 42, 7).is_err());
    }
    #[test]
    fn fake_reply_exercises_tgid_and_kernel_error_paths() {
        let family = 42;
        let sequence = 7;
        let mut stats = vec![0; 64];
        stats[0..2].copy_from_slice(&1_u16.to_ne_bytes());
        let mut aggregate = attr(TASKSTATS_TYPE_TGID, &12_u32.to_ne_bytes());
        aggregate.extend(attr(TASKSTATS_TYPE_STATS, &stats));
        let reply = message(
            family,
            sequence,
            TASKSTATS_CMD_GET,
            &attr(TASKSTATS_TYPE_AGGR_TGID, &aggregate),
        );
        assert!(parse_taskstats_reply(&reply, family, sequence, 12).is_ok());
        assert!(parse_taskstats_reply(&reply, family, sequence, 13).is_err());
        let mut error = Vec::new();
        put_u32(&mut error, NLMSG_HDR as u32 + 4);
        put_u16(&mut error, NLMSG_ERROR);
        put_u16(&mut error, 0);
        put_u32(&mut error, sequence);
        put_u32(&mut error, 0);
        error.extend_from_slice(&(-13_i32).to_ne_bytes());
        assert!(matches!(
            validate_netlink_datagram(&error, family, sequence),
            Err(TransportError::Kernel(-13))
        ));
    }
    #[test]
    fn delay_accounting_state_is_independent_of_transport_failure() {
        assert_eq!(
            delay_accounting_state_from_text("1\n"),
            DelayAccountingState::Enabled
        );
        assert_eq!(
            delay_accounting_state_from_text("0\n"),
            DelayAccountingState::Disabled
        );
        assert_eq!(
            delay_accounting_state_from_text("unexpected"),
            DelayAccountingState::Unknown
        );
        let endpoint = TaskstatsEndpoint {
            capability: TaskstatsCapability::PermissionDenied,
            delay_accounting: DelayAccountingState::Enabled,
            values: BTreeMap::new(),
            issues: TaskstatsCollectionIssues {
                permission_denied: 1,
                ..Default::default()
            },
        };
        assert_eq!(endpoint.capability, TaskstatsCapability::PermissionDenied);
        assert_eq!(endpoint.delay_accounting, DelayAccountingState::Enabled);
    }
    #[test]
    fn receive_budget_never_allows_more_than_the_remaining_bytes() {
        assert!(reply_fits_budget(MAX_REPLY_BYTES - 1, 1));
        assert!(!reply_fits_budget(MAX_REPLY_BYTES - 1, 2));
        assert!(!reply_fits_budget(MAX_REPLY_BYTES, 1));
    }
}
