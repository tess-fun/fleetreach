---
title: Run a vulnerability program
description: One nightly fleetreach job over every repository and image in the organisation gives each team a ranked fix queue, SLAs that never reset, notifications and verified fix pull requests.
sidebar:
  order: 1
---

**The problem.** You own security for a hundred repos and a few dozen images across six
languages. Each repo's scanner opens its own alerts. Nobody can say which fix matters most,
which teams are behind, or whether last month's Log4Shell push actually landed everywhere.

**With fleetreach**, one scheduled job scans the org, records history, and tells each team
what is theirs.

```toml title="fleet.toml"
[[source]]
kind = "github"
org  = "acme"
exposure = "controlled"

[[repo]]                         # the same id as a discovered repo: its own context
id = "payments-api"
owner = "team-payments"
exposure = "open"
mission_impact = "mission-failure"

[[image]]
id = "storefront-web"
reference = "docker://ghcr.io/acme/storefront-web:main"
owner = "team-storefront"
exposure = "open"

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
fleetreach history sla --history-dir history/        # exits 1 on a breach
```

## A queue per team

Each team sees its own bumps, in the fleet's order, with the SSVC decision for its own
repos' exposure:

<!-- run: fleetreach scan -f owners --enrich | head -n 12 -->
```console
$ fleetreach scan -f owners --enrich | head -n 12
team-data (2 repo(s): data-pipeline, ml-service)
┌───┬───────────┬────────────────────────────────────────────────┬──────────────┬───────────────┬───────┬─────────┬─────────┬────────────────────────┐
│ # ┆ SSVC      ┆ Action                                         ┆ Severity     ┆ Resolves      ┆ Repos ┆ Reach   ┆ Exploit ┆ Bump risk              │
╞═══╪═══════════╪════════════════════════════════════════════════╪══════════════╪═══════════════╪═══════╪═════════╪═════════╪════════════════════════╡
│ 1 ┆ scheduled ┆ bump urllib3 1.26.12 → 2.8.0 (breaking)        ┆ high 8.1     ┆ 10 advisories ┆ 2     ┆ unknown ┆ EPSS 3% ┆ high                   │
│   ┆           ┆   or 1.26.19 on 1.x (2 repos, 7 left open)     ┆              ┆               ┆       ┆         ┆         ┆                        │
├╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2 ┆ scheduled ┆ bump flask 2.2.2 → 3.1.3 (breaking)            ┆ high 7.5     ┆ 2 advisories  ┆ 1     ┆ unknown ┆ EPSS 1% ┆ high                   │
│   ┆           ┆   or 2.2.5 on 2.x (1 repo, 1 left open)        ┆              ┆               ┆       ┆         ┆         ┆                        │
├╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 3 ┆ defer     ┆ bump certifi 2022.9.24 → 2026.10.18 (breaking) ┆ critical 7.5 ┆ 4 advisories  ┆ 1     ┆ unknown ┆ EPSS 1% ┆ high · 1 on 2026.10.23 │
│   ┆           ┆   or 2022.12.7 on 2022.x (1 repo, 3 left open) ┆              ┆               ┆       ┆         ┆         ┆                        │
```
<!-- /run -->

## SLAs that do not reset

First-seen dates survive across runs, so a finding that moves between files or repos keeps
its clock. `history sla` lists what is past due, per SSVC outcome or severity:

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

## What you get

- **A fix queue ranked across the fleet**, with KEV, EPSS, public exploits and SSVC
  decisions from each repo's exposure. The first rows remove the most risk.
- **One queue per team** with `-f owners`, and a Slack message or issue per owner.
- **Verified fixes**: `fix plan` and `fix apply --open-pr` open lock-only pull requests on
  GitHub, GitLab, Gitea, Forgejo, Bitbucket or Azure DevOps, each re-scanned before it is
  pushed.
- **A report people can open**: one static HTML page with trends and time to fix, and
  `fleetreach serve` for recording triage decisions in a browser.

Start with [Your first scan](/fleetreach/docs/getting-started/first-scan/), then
[Scan a GitHub or GitLab org](/fleetreach/docs/guides/scan-a-github-or-gitlab-org/) and
[Track history and SLAs](/fleetreach/docs/guides/track-history-and-slas/).
