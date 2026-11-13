---
title: Triage findings
description: Record decisions on findings as files in git, with an owner, an expiry and a log, and publish them as OpenVEX that Trivy and Grype honor.
sidebar:
  order: 14
---

A triage decision is a file in your repo. Each finding has its own, so two people triaging
different findings never touch the same file, branches merge clean, and the audit trail is the
git history.

```sh
fleetreach triage set RUSTSEC-2024-0421 --package idna --ecosystem cargo \
  --state accepted_risk --reason "internal hosts only" \
  --expires 2027-01-31 --assignee lee \
  --alias CVE-2024-12224 --alias GHSA-h97m-ww89-6jmq
```

That writes `triage/RUSTSEC-2024-0421/cargo-idna.toml` beside `fleet.toml`, and each later `set`
on the same finding adds to its `[[log]]`:

```toml
advisory = "RUSTSEC-2024-0421"
aliases = ["CVE-2024-12224", "GHSA-h97m-ww89-6jmq"]
ecosystem = "cargo"
package = "idna"
state = "accepted_risk"
assignee = "lee"
expires = "2027-01-31"
reason = "internal hosts only"

[[log]]
at = "2026-11-04T06:14:34Z"
by = "pat"
state = "accepted_risk"
note = "internal hosts only"
```

Use the advisory id and ecosystem the report shows. A decision covers every version of the
package in the fleet; `--repo` narrows it to named repos.

## States

| State | Sets the finding aside | OpenVEX |
|-------|------------------------|---------|
| `affected` | no | `affected` |
| `in_triage` | no | `under_investigation` |
| `accepted_risk` | yes, needs `--reason` | `affected` |
| `false_positive` | yes, needs `--reason` | `not_affected` |
| `not_affected` | yes, needs `--reason` | `not_affected` |
| `fixed` | no | `fixed` |

Decisions apply to vulnerabilities. Warnings, such as unmaintained crates, are not triaged;
use `[[settings.ignore]]` for those.

## In a scan

`scan` reads `triage/` beside `fleet.toml`, `[settings.triage] dir`, or `--triage-dir`. A decision
holds through its `expires` day. After that its finding is back, and the run exits 1 whatever the
gate's level, until someone decides again. A triage file that cannot be read, or that sits at the
wrong path, exits 2: a decision skipped in silence would change what the scan says.

```sh
fleetreach triage list
fleetreach triage list --expired
fleetreach triage list --assignee lee --json
```

## In a browser

`fleetreach serve` shows the history report and the newest run's findings in a browser, and
records decisions from a form. A decision it records is the same file `triage set` writes, with
the same log entry; it never runs git, so commit `triage/` as you would after `triage set`.

```sh
fleetreach scan --history-dir history/
fleetreach serve --history-dir history/ -c fleet.toml
# open http://127.0.0.1:8484/
```

The pages read `history/` and `triage/` on every request, so a new scan or a decision made with
`triage set` shows on the next reload. `/triage` lists the newest run's findings with their
decisions and filters by state or text; each finding links to a form with the states and fields
of `triage set`, and the decision takes the aliases the report knows for it. `/api/decisions`
returns every decision as JSON. Release binaries include `serve`; with cargo, build with
`--features serve`.

By default it listens on `127.0.0.1:8484`, serves only requests from the same machine, and
records decisions as `--by`, else git's `user.name`, else `$USER`. With none of those the pages
are read only. Every form carries a token made when the server starts, and a post from another
site is refused, so a page you visit elsewhere cannot record a decision in your name.

To share it with a team, put it behind a reverse proxy that signs people in, and name the proxy:

```sh
fleetreach serve --history-dir history/ -c fleet.toml \
  --listen 0.0.0.0:8484 --trust-proxy 10.0.0.5 --identity-header X-Forwarded-User
```

Then only requests from `10.0.0.5` are served, and the reviewer is the user the proxy names in
`X-Forwarded-User`; a request without it gets 401. Make sure the proxy sets that header itself and
drops one a client sends. `serve` refuses to listen anywhere but a loopback address without
`--trust-proxy`, and it speaks plain HTTP, so the proxy also terminates TLS.

## Share the decisions

```sh
fleetreach triage export -f openvex --author security@acme.example > triage.vex.json
trivy fs --vex triage.vex.json .
grype dir:. --vex triage.vex.json
```

Each id of a decision gets a statement on the package's versionless purl. Trivy reports CVE ids
and Grype GHSA ids, so give `--alias` for the ids other tools use. An accepted risk is exported as
`affected`, and `-f vex` writes no statement for it: the package is vulnerable, and other tools keep
saying so. An expired decision is exported as `under_investigation`.
