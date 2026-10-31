# Spec 09: History, SLAs and notifications without a server

Status: phases 1 to 3 implemented (unreleased: history store, trend, age, sla, mttr, notify); the static HTML report not started · Gap: #6 (triage workflow) · CTEM stage: mobilization (and the loop back to scoping) · Effort: M

## Problem

`diff` and `--baseline` compare two JSON files. There is no trend over time, no "how long
has this been open", no SLA clock, no notifications and nowhere findings live between runs.
Teams with a security program usually want those, and today they reach for Dependency-Track
or a SaaS platform to get them.

## What competitors do

- **Dependency-Track v5**: time-series metrics (risk score and finding counts per project
  and portfolio), every project version kept, findings triaged with analysis state,
  justification and an exportable audit trail, notification publishers including Jira,
  Slack, Teams, email and webhooks, filtered with CEL.
  ([features](https://dependencytrack.org/features), [notifications](https://docs.dependencytrack.org/integrations/notifications/))
- **GitHub security overview**: org-level trends, security campaigns with due dates,
  alert assignment.
- **Commercial platforms**: SLA policies per severity, Jira/ServiceNow ticket sync,
  ownership routing.

## Goals

1. Keep scan history as plain files, so a git repo (or an object-store prefix) is the
   database and the audit trail.
2. Trends, age and SLA breaches across the fleet from that history.
3. Notify on what changed since the last run, routed by owner (Spec 08).
4. An optional static HTML report that can be hosted anywhere, no server.

Non-goals: a web app, multi-user editing, bidirectional Jira sync.

## Design

### History store

```
fleetreach scan -c fleet.toml --history-dir history/
```

- Each run writes `history/<UTC timestamp>-<short report hash>.json.gz` (gzip via the
  pure-Rust `flate2` + `zlib-rs` backend already in the dependency tree): the JSON report plus
  provenance (DB snapshot, fleet source commits from Spec 06).
- `history/index.json`: per finding key `(advisory, repo, package, version)` its `first_seen`,
  `last_seen`, `fixed_at` and the run ids. Rebuilt from the snapshots if missing or corrupt,
  so the snapshots stay the source of truth.
- Retention: `[settings.history] keep = "180d"` (index keeps first-seen dates forever).
- Recommended setup: commit `history/` to a dedicated repo from CI; git log is then the
  audit trail. Triage decisions are already files (`[[settings.ignore]]` with reasons, VEX
  assertions with `approved_by`), so their history comes with the config repo.

### Queries

```
fleetreach history trend   [--by severity|ssvc|ecosystem|owner] [--since 90d]
fleetreach history age     [--min-age 30d]
fleetreach history sla     # breaches against [settings.sla]
fleetreach history mttr    [--by severity|owner]
```

```toml
[settings.sla]               # keyed by SSVC outcome (Spec 08) or severity
immediate      = "2d"
"out-of-cycle" = "7d"
scheduled      = "30d"
critical       = "7d"        # used when SSVC is not computed
high           = "30d"
```

SLA clock starts at `first_seen` in the fleet. `history sla` exits 1 on any breach, so it
can gate a scheduled CI job.

### Notifications

```
fleetreach notify --history-dir history/ --webhook $URL [--format slack|generic]
fleetreach notify --history-dir history/ --github-issues --repo acme/security-findings
```

- Content: new findings, SLA breaches and fixed findings since the previous snapshot,
  grouped by owner.
- `generic`: a documented JSON payload (stable schema) for any automation (Jira automation
  rules, ServiceNow, PagerDuty) to consume. `slack`: Block Kit message.
- `--github-issues`: one issue per owner per campaign via `gh issue create`, updated in
  place on later runs (found by a hidden marker in the body). GitLab via `glab`.
- No Jira client: the generic webhook plus Jira automation covers it without credentials in
  fleetreach.

### Static report

```
fleetreach report html --history-dir history/ -o fleet-report.html
```

One self-contained HTML file (inline CSS/JS, no CDN): fleet summary, trend chart, SLA
breaches, campaigns (Spec 07 status if present), per-owner queues. Publishable to GitHub
Pages or any internal static host. This is the "dashboard" without operating anything.

## Fail-closed rules

- A run that exited 2 (gap) is recorded as a gap run; its missing repos do not count as
  "fixed". Fixed requires a later trustworthy scan of that repo without the finding.
- An unreadable snapshot is reported and skipped; `index.json` is rebuilt rather than
  trusted.

## Testing

- Synthetic history: 30 snapshots with known introductions/fixes; assert age, MTTR, SLA
  breaches, and that a gap run never marks findings fixed.
- Webhook payload schema test; `gh` behind a fake.
- HTML report snapshot test (DOM text), size budget.

## Phasing

1. History store + `trend`/`age`: S/M.
2. SLA + `history sla` gate: S.
3. `notify` (generic, Slack, GitHub issues): M.
4. Static HTML report: M.
