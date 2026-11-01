---
title: For platform and security teams
description: Run one nightly fleetreach job over every repository in the organisation to get a ranked fix queue per team, SLA tracking, notifications and verified fix pull requests.
sidebar:
  order: 1
---

**The problem.** You own security for a hundred repos across six languages. Each repo's
scanner opens its own alerts; nobody can tell you which fix matters most, which teams are
behind, or whether last month's push to fix Log4Shell actually landed everywhere.

**With fleetreach.** One scheduled job scans the org, records history, and tells each team
what is theirs.

```toml title="fleet.toml"
[[source]]
kind = "github"
org  = "acme"
exposure = "controlled"

[settings.context.defaults]
mission_impact = "mef-support-crippled"
safety_impact  = "negligible"

[settings.sla]
immediate      = "2d"
"out-of-cycle" = "7d"
scheduled      = "30d"
```

```sh
fleetreach scan --sync --enrich --history-dir history/ -f json > report.json
fleetreach notify --history-dir history/ -c fleet.toml -f slack --webhook "$SLACK_WEBHOOK"
fleetreach report html --history-dir history/ -c fleet.toml -o public/index.html
```

What you get:

- **A fix queue ranked across the fleet**, with KEV and EPSS, and SSVC decisions from each
  repo's exposure (a `[[repo]]` with the same id as a discovered one sets its own `exposure`
  and `owner`). The first rows are the bumps that remove the most risk.
- **One queue per team** with `-f owners`, and a Slack message or issue per owner.
- **SLAs that do not reset**: first-seen dates survive across runs, and `history sla` exits 1
  on a breach.
- **Verified fixes**: `fix plan` and `fix apply --open-pr` open lock-only pull requests,
  each re-scanned before it is pushed.
- **A report people can open**: one static HTML page with trends and time to fix.

Start with [Your first scan](/fleetreach/docs/getting-started/first-scan/), then
[Scan a GitHub or GitLab org](/fleetreach/docs/guides/scan-a-github-or-gitlab-org/).
