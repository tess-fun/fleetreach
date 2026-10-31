# History and SLAs

`fleetreach scan --history-dir history/` keeps every run as a file, so trends, the age of
each finding, SLA breaches and time to fix need no server. Commit the directory to a repo from
a scheduled CI job and git becomes the database and the audit trail.

```sh
fleetreach scan -c fleet.toml --enrich --history-dir history/
fleetreach history trend --history-dir history/ --by owner --since 90d
fleetreach history age   --history-dir history/ --min-age 30d
fleetreach history sla   --history-dir history/ -c fleet.toml   # exits 1 on a breach
fleetreach history mttr  --history-dir history/ --by severity
```

## What is stored

Each run writes `history/<UTC time>-<hash>.json.gz`: the full JSON report, the occurrences
that ignores suppressed, and the run's exit code. `history/index.json` records, for each
finding (advisory, ecosystem, repo, package and version), when it was first and last seen,
when it was fixed, how often it came back, and its latest severity, SSVC outcome and owner.

The snapshots are the source of truth. An index that is missing, unreadable or out of step
with them (a snapshot older than its newest run appeared, say from merging two branches of
the history repo) is rebuilt from them, keeping what it knew about findings whose snapshots
are gone.

```toml
[settings.history]
keep = "180d"   # drop snapshots older than this; the index keeps first-seen dates
```

The newest snapshot is never dropped.

## When a finding counts as fixed

Only when a later run that can vouch for the repo no longer has it. A run vouches for a repo
when the run did not exit `2` and the repo was scanned without error and read in full. So:

- a run that exited `2` (an errored repo, a stale database) never marks anything fixed;
- a repo that errored, or had a source read with partial coverage, keeps its findings open;
- a repo dropped from the fleet keeps its findings open (their age keeps growing);
- a finding an ignore suppresses is recorded as `ignored`, not fixed, and leaves the age and
  SLA lists until the ignore is removed.

Because a missing finding means "fixed", `--history-dir` refuses the flags that drop findings
from the report: `--baseline`, `--min-severity`, `--min-epss`, `--ignore-dev-deps`,
`--ignore-phantom` and `--reachable-only`. Use them on separate runs.

## Queries

All four take `--history-dir`, `-f table|json` and `--at <RFC 3339>` to measure as of another
time.

- **`trend`**: open findings per run, grouped `--by severity` (default), `ssvc`, `ecosystem`
  or `owner`, optionally `--since 90d`. A run that exited `2` is marked `(gap)`: part of the
  fleet was not read, so its counts are a floor.
- **`age`**: open findings, oldest first, with the date first seen; `--min-age 30d` keeps the
  old ones.
- **`sla`**: open findings past their deadline (see below), most overdue first. Exits `1` on
  any breach, so a scheduled job can gate on it, and `2` when there is no `[settings.sla]` or
  no history: a missing policy is not a pass.
- **`mttr`**: mean and median days from first seen to fixed, per group, with the count still
  open.

## SLAs

```toml
[settings.sla]
immediate      = "2d"    # by SSVC outcome (see Context and SSVC)
"out-of-cycle" = "7d"
scheduled      = "30d"
critical       = "7d"    # by severity, when the finding has no SSVC outcome with a deadline
high           = "30d"
```

The clock starts when the finding was first seen. A finding's SSVC outcome decides its
deadline when the policy names that outcome; otherwise its severity does. An `unknown`
severity without its own entry gets the shortest severity deadline, so not knowing never buys
time. A finding with neither has no deadline.
