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

## Notifications

```
fleetreach notify --history-dir history/ -c fleet.toml                          # print the payload
fleetreach notify --history-dir history/ -c fleet.toml --webhook "$HOOK_URL"    # generic JSON
fleetreach notify --history-dir history/ -c fleet.toml -f slack --webhook "$SLACK_WEBHOOK"
fleetreach notify --history-dir history/ -c fleet.toml --github-issues --repo acme/security
fleetreach notify --history-dir history/ -c fleet.toml --gitlab-issues --repo acme/security
```

Run it after `scan --history-dir`, from the same job. It reports, grouped by owner:

- **new**: open in the newest run and not open before it: first seen, back after a fix, or
  no longer ignored;
- **fixed**: marked fixed by the newest run;
- **breaches**: every open finding past its `[settings.sla]` deadline (only with `-c`),
  measured now, so an overdue finding is repeated on every run until it is fixed.

"Before" is the history as it stood before the newest run, so a gap run in between does not
make old findings look new when their repo is read again.

### Webhooks

`--webhook` POSTs the payload as JSON (a build with the `network` feature; the release
binaries have it). It must be `https://`, or `http://` to localhost. Messages name only the
URL's host, since webhook URLs carry their secret in the path. When nothing is new, fixed or
past due nothing is sent, unless `--always`. `--dry-run` prints the payload instead.

`-f generic` (the default) is the stable payload below, for Jira automation rules,
ServiceNow, PagerDuty or your own script. Its fields only grow within
`fleetreach-notify/1`; a breaking change gets a new schema id.

```json
{
  "schema": "fleetreach-notify/1",
  "run": { "id": "20261210T000000Z-1a2b3c4d", "at": "2026-12-10T00:00:00Z",
           "exit_code": 1, "gap": false },
  "previous_run": "20261120T000000Z-5e6f7a8b",
  "summary": { "new": 0, "fixed": 0, "breaches": 1, "open": 1 },
  "owners": [
    {
      "owner": "team-b",
      "open": 1,
      "new": [],
      "fixed": [],
      "breaches": [
        {
          "advisory": "RUSTSEC-2099-0001", "ecosystem": "cargo", "repo": "api",
          "package": "fixturevuln", "version": "1.0.0", "severity": "critical",
          "first_seen": "2026-10-31T00:00:00Z", "due": "2026-11-30T00:00:00Z",
          "overdue_days": 10.0, "url": "https://osv.dev/vulnerability/RUSTSEC-2099-0001"
        }
      ]
    }
  ]
}
```

`owners` lists only owners with something to report, named owners first; `owner` is `null`
for repos without one. `url` is the advisory's own page when its database gives an `https://` one,
otherwise its osv.dev page; the HTML report links the same way. Items also carry `ssvc` when an outcome was computed and `fixed_at`
when fixed. `run.gap` is true when the newest run exited `2`.

`-f slack` sends a Block Kit message: a summary header, then one section per owner with up
to ten findings per list.

### Issues

`--github-issues` (through `gh`) or `--gitlab-issues` (through `glab`) keeps one issue per
owner in `--repo`, which should be a repo for this purpose. Each issue lists the owner's
findings past SLA, every open finding (new ones marked) and those fixed by the newest run.
A hidden first line, `<!-- fleetreach:campaign=fleetreach;owner=team-b -->`, finds it again
on the next run, where it is rewritten in place. It is closed when the owner has nothing open
and reopened when a finding comes back. `--campaign` names a separate set of issues, for
example per program or quarter. `--dry-run` prints the issues without running `gh` or
`glab`. Edits made by hand to these issues are overwritten.

There is no Jira client: point the generic webhook at a Jira automation rule instead, so
fleetreach holds no Jira credentials.

## Static report

```
fleetreach report html --history-dir history/ -c fleet.toml -o fleet-report.html
fleetreach fix status -c fleet.toml > fix-status.json   # optional: list fix campaigns too
fleetreach report html --history-dir history/ -c fleet.toml --fix-status fix-status.json -o site/index.html
```

One self-contained HTML file: inline styles, an inline SVG chart and a few lines of script for
its tooltips, nothing fetched, so it works offline and on any static host (GitHub Pages, an
internal bucket). It shows:

- summary tiles: open findings, past SLA, new and fixed in the newest run, median days to fix;
- open findings per run, stacked by severity, with gap runs marked, and a table view;
- every finding past its SLA (with `-c` and `[settings.sla]`), most overdue first;
- a queue per owner: past due first, then by severity and age, with each deadline;
- fix campaigns from a saved `fix status` (`--fix-status`), with links to the requests;
- time to fix by severity.

`--title` names the page and `--since 90d` shortens the trend. `-o -` writes to stdout. Every
value from the history is escaped, and only `https://` links from a status file become links.
The page is the same for the same history and `SOURCE_DATE_EPOCH`, so it diffs cleanly when
committed. It follows the light or dark setting of the viewer's system.
