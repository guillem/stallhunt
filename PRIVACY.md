# Stallhunt privacy policy

Last updated: 2026-08-26

Stallhunt is an open-source command-line tool and local Model Context Protocol
(MCP) server. It runs on the user's Linux machine and does not operate a hosted
service or require a Stallhunt account.

## Data Stallhunt reads

To diagnose local performance contention, Stallhunt reads bounded telemetry
from Linux interfaces such as `/proc`, PSI, taskstats when permitted, and the
caller-visible cgroup-v2 hierarchy. Results may contain process names and
identifiers, resource counters, device names, cgroup paths, and inferred
service or container names. These values can reveal sensitive information
about workloads running on the machine.

## Data use and transmission

Stallhunt uses that telemetry only to calculate and explain local performance
findings. Stallhunt does not include analytics, advertising, update checks, or
independent network transmission. Its MCP server communicates with the local
MCP client that launched it over standard input and output.

When an MCP client invokes Stallhunt, the client may transmit tool requests and
results to its own model provider or other services. That processing is
controlled by the client and is governed by the client's privacy policy, not
by Stallhunt. Review the client's data controls before exposing sensitive host
telemetry.

## Storage and retention

Ordinary `hunt`, `watch`, and MCP operation do not persist telemetry. The
`record` command writes a diagnostic recording only when the user requests it;
new recordings use mode `0600`. Recordings remain until the user deletes them.
The `redact` command can replace several identifiers before sharing, but its
output is not cryptographic anonymization.

## Sharing and third parties

Stallhunt does not sell or share data with third parties. Data is disclosed
only through output destinations explicitly selected by the user, including a
terminal, file, pipe, or invoking MCP client.

## Permissions

Stallhunt requests no root access and does not elevate privileges. Linux may
restrict which process or cgroup telemetry an ordinary user can read; Stallhunt
reports those gaps instead of bypassing them.

## Contact

Questions and privacy reports can be filed at
<https://github.com/guillem/stallhunt/issues>.
