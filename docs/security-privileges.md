# Security and privilege model

## Goal

Provide maximum useful diagnosis with minimum privilege.

Running a performance tool should not require `root` merely because deeper tracing could use it.

## Privilege tiers

### Tier 0: ordinary user

Expected to support:

- host PSI,
- global CPU/memory/disk metrics,
- own-process details,
- readable process metadata,
- baseline findings.

### Tier 1: expanded process visibility

System configuration may permit broader `/proc` access without full root.

The tool should detect this rather than assume it.

### Tier 2: privileged tracing

Future eBPF/perf/tracepoint capabilities may require:

- Linux capabilities,
- privileged helper,
- root,
- appropriate LSM/sysctl settings.

Do not make this the default execution mode.

### Implemented M4 cgroup-v2 collection

M4 reads only from the caller-visible cgroup2 mount and procfs membership files;
it does not create, move, configure, or delete cgroups. Mount namespaces and
delegation may intentionally hide ancestors or controller files. Such absence is
reported as partial capability/context rather than worked around with privilege
escalation. Bounded membership-first reads (1,024 PIDs, 2,048 groups plus depth,
path, and file-byte limits) protect against a large or adversarial hierarchy.

Cgroup paths and inferred unit names can disclose service, user, or container
structure. They are sensitive collection output alongside process names and
command lines.

## Degradation

When access is denied:

Bad behavior:

```text
fatal: cannot read /proc/1234/io
```

Desired behavior:

```text
I/O process attribution is incomplete:
37 processes were not readable with current permissions.
Device-level I/O diagnosis remains available.
```

The finding's confidence may be reduced.

## `/proc` privacy

Command lines and process metadata can contain sensitive information.

Default human output should avoid unnecessarily printing complete command lines containing secrets.

Prefer process `comm`/executable names in summary views.

If a future verbose mode prints full command lines, document the risk.

## Recorded diagnostics

M5 recordings may contain:

- process names,
- cgroup paths,
- inferred systemd unit candidates,
- device names,
- PIDs and start-time identities,
- resource counters.

Treat recordings as potentially sensitive.

Implemented privacy defaults:

- new recording files are created with mode `0600`
- existing paths are not overwritten unless `--force` is passed
- default `record` retains identifiers for local diagnosis
- `record --redact` and `redact` replace process names, disk names, cgroup path
  components, and inferred unit candidates
- PIDs, start times, major/minor keys, counters, and path hierarchy are kept
- redaction is not cryptographic anonymization
- hunt JSON is a report, not a recording, and is rejected by `replay`

A support bundle is the recording file. Capture locally without redaction, then
write a redacted copy before sharing.

## eBPF safety

Future eBPF components must:

- use bounded maps/buffers,
- avoid unbounded event generation,
- tolerate event loss,
- fail closed when verifier/load fails,
- not require disabling kernel security mechanisms.

Never instruct users to broadly weaken kernel protections as the default installation path.

## Privileged helper

Do not create a setuid binary casually.

If privileged collection later becomes necessary, evaluate alternatives:

- capabilities on a narrow binary,
- systemd service/helper,
- privileged collector plus unprivileged client,
- on-demand `sudo`,
- BPF token/delegation mechanisms where practical.

Any such decision requires an ADR and threat model.

## Threat model

The project should consider:

### Malicious local process

A process may expose pathological `/proc` metadata or churn rapidly.

Parsers must be robust.

### Resource exhaustion

A host may have:

- hundreds of thousands of threads,
- rapid fork/exit churn,
- huge cgroup trees.

Collection must be bounded and avoid attacker-controlled unbounded allocation.

### Terminal injection

Process names and command lines are untrusted text.

Sanitize control characters before terminal rendering.

### Symlink/path races

Be cautious when traversing procfs/sysfs/cgroupfs.

Prefer file-descriptor-relative operations where complexity is justified.

### Numeric overflow

Kernel counters can be large.

Use appropriate integer widths and checked/saturating arithmetic where subtraction or conversion can fail.

### Privilege boundary

If a privileged helper is ever introduced, inputs from the unprivileged client are untrusted.

## Network behavior

The core tool should not require network access.

No telemetry should leave the machine unless a future explicit feature says so.

This keeps the diagnostic trust model simple.
