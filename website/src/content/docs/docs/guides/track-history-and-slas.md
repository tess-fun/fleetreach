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

The demo fleet has two recorded runs, on 1 September and 15 October, measured here as of
1 November:

<!-- run: fleetreach history trend --history-dir history/ -->
```console
$ fleetreach history trend --history-dir history/
┌──────────────────────┬──────┬──────────┬──────┬─────┬────────┬─────────┐
│ Run                  ┆ Open ┆ critical ┆ high ┆ low ┆ medium ┆ unknown │
╞══════════════════════╪══════╪══════════╪══════╪═════╪════════╪═════════╡
│ 2026-09-01T09:00:00Z ┆ 239  ┆ 4        ┆ 74   ┆ 24  ┆ 74     ┆ 63      │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┤
│ 2026-10-15T09:00:00Z ┆ 257  ┆ 6        ┆ 79   ┆ 21  ┆ 88     ┆ 63      │
└──────────────────────┴──────┴──────────┴──────┴─────┴────────┴─────────┘
```
<!-- /run -->

<!-- run: fleetreach history sla --history-dir history/ | head -n 9 -->
```console
$ fleetreach history sla --history-dir history/ | head -n 9
┌─────────────────┬─────────────────────┬────────────────────────────────────────────────────┬─────────────────────────┬─────────────────┬──────────────────────┬──────────────────────┬────────────────┐
│ Repo            ┆ Advisory            ┆ Package                                            ┆ Severity                ┆ Owner           ┆ First seen           ┆ Due                  ┆ Overdue (days) │
╞═════════════════╪═════════════════════╪════════════════════════════════════════════════════╪═════════════════════════╪═════════════════╪══════════════════════╪══════════════════════╪════════════════╡
│ data-pipeline   ┆ GHSA-6q48-6c7w-9gw2 ┆ certifi@2022.9.24                                  ┆ critical / defer        ┆ team-data       ┆ 2026-09-01T09:00:00Z ┆ 2026-09-15T09:00:00Z ┆ 47.0           │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ checkout-web    ┆ GHSA-mrrh-fwg8-r2c3 ┆ tj-actions/changed-files@44.0.0                    ┆ high / out-of-cycle     ┆ team-storefront ┆ 2026-09-01T09:00:00Z ┆ 2026-09-15T09:00:00Z ┆ 47.0           │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ payments-api    ┆ RUSTSEC-2020-0159   ┆ chrono@0.4.19                                      ┆ unknown / out-of-cycle  ┆ team-payments   ┆ 2026-09-01T09:00:00Z ┆ 2026-09-15T09:00:00Z ┆ 47.0           │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

<!-- run: fleetreach history mttr --history-dir history/ -->
```console
$ fleetreach history mttr --history-dir history/
┌──────────┬───────┬─────────────┬───────────────┬────────────┐
│ Group    ┆ Fixed ┆ Mean (days) ┆ Median (days) ┆ Still open │
╞══════════╪═══════╪═════════════╪═══════════════╪════════════╡
│ critical ┆ 0     ┆ -           ┆ -             ┆ 6          │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┤
│ high     ┆ 13    ┆ 44.0        ┆ 44.0          ┆ 79         │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┤
│ low      ┆ 5     ┆ 44.0        ┆ 44.0          ┆ 21         │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┤
│ medium   ┆ 12    ┆ 44.0        ┆ 44.0          ┆ 88         │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┤
│ unknown  ┆ 0     ┆ -           ┆ -             ┆ 63         │
└──────────┴───────┴─────────────┴───────────────┴────────────┘
```
<!-- /run -->

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
