---
title: Track history and SLAs
description: Keep every scan as a file and get trends, finding age, SLA breaches and mean time to fix, with no server. Git becomes the database and the audit trail.
sidebar:
  order: 6
---

`fleetreach scan --history-dir history/` keeps every run as a file. From that directory,
`fleetreach history` reports trends, the age of each finding, SLA breaches and time to fix.
Commit the directory from a scheduled CI job and git is the database and the audit trail.

```sh
fleetreach scan --enrich --history-dir history/
fleetreach history trend --history-dir history/ --by owner --since 90d
fleetreach history age   --history-dir history/ --min-age 30d
fleetreach history sla   --history-dir history/ -c fleet.toml   # exits 1 on a breach
fleetreach history mttr  --history-dir history/ --by severity
```

## When a finding counts as fixed

Only when a later run that can vouch for the repo no longer has it. A run vouches for a repo
when it did not exit `2` and the repo was scanned without error and read in full. So an
errored repo, a partly read source, a repo dropped from the fleet or a suppressed finding
never looks fixed. For the same reason `--history-dir` refuses the flags that drop findings
from a report (`--baseline`, `--min-severity`, `--min-epss`, `--ignore-dev-deps`,
`--ignore-phantom`, `--reachable-only`).

## Queries

All four take `--history-dir`, `-f table|json` and `--at <RFC 3339>` to measure as of
another time.

| Query | Shows |
|-------|-------|
| `trend` | Open findings per run, `--by severity`, `ssvc`, `ecosystem` or `owner`. A run that exited `2` is marked `(gap)`. |
| `age` | Open findings, oldest first, with the date first seen. |
| `sla` | Open findings past their deadline, most overdue first. Exits `1` on a breach, `2` with no policy. |
| `mttr` | Mean and median days from first seen to fixed, per group. |

## Set SLAs

```toml title="fleet.toml"
[settings.sla]
immediate      = "2d"    # by SSVC outcome
"out-of-cycle" = "7d"
scheduled      = "30d"
critical       = "7d"    # by severity, when no SSVC outcome applies
high           = "30d"

[settings.history]
keep = "180d"            # drop old snapshots; the index keeps first-seen dates
```

The clock starts when the finding was first seen. An `unknown` severity gets the shortest
severity deadline, so not knowing never buys time.

## What is stored

Each run writes `history/<UTC time>-<hash>.json.gz` (the full report, suppressed findings,
the exit code, every package name read) and updates `history/index.json`. The snapshots are
the source of truth; a missing or inconsistent index is rebuilt from them.

## Next

- [Send notifications](/fleetreach/docs/guides/send-notifications/) on new, fixed and
  overdue findings.
- [Publish a fleet report](/fleetreach/docs/guides/publish-a-fleet-report/) as one HTML page.
