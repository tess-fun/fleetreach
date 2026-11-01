---
title: GitHub Actions
description: Run fleetreach in GitHub Actions with the bundled action, upload SARIF to code scanning, gate pull requests on new findings only, and scan a whole org on a schedule.
sidebar:
  order: 1
---

## One repo, findings in the Security tab

```yaml title=".github/workflows/audit.yml"
name: audit
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 6 * * *"   # daily, so newly published advisories surface

permissions:
  contents: read
  security-events: write   # to upload SARIF

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tess-fun/fleetreach@v1
        with:
          args: "--enrich"   # rank by CISA KEV and EPSS
```

The action installs a checksum-verified release binary, scans the repo (a generated
`fleet.toml`, or yours with `config:`), and uploads SARIF to code scanning even when the gate
fails. Inputs: `args`, `config`, `sarif-file`, `upload` and `version`.

Each SARIF result has a stable fingerprint built from the advisory, ecosystem, repo and
package, not the version, so an alert survives a bump that does not fix it. Findings proven
`not_affected` carry a suppression and are greyed out instead of alerting.

## The whole org, nightly

```yaml title=".github/workflows/fleet.yml"
on:
  schedule:
    - cron: "0 5 * * *"
jobs:
  fleet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4      # the repo holding fleet.toml
      - run: curl -fsSL https://raw.githubusercontent.com/tess-fun/fleetreach/main/scripts/install.sh | sh
      - run: fleetreach scan --sync --enrich --history-dir history/ -f json > report.json
        env:
          GITHUB_TOKEN: ${{ secrets.FLEET_READ_TOKEN }}   # read access to the org's repos
      - run: fleetreach notify --history-dir history/ -c fleet.toml -f slack --webhook "${{ secrets.SLACK_WEBHOOK }}"
```

`fleet.toml` has a `[[source]] kind = "github"` (see
[Scan a GitHub or GitLab org](/fleetreach/docs/guides/scan-a-github-or-gitlab-org/)). Keep
`history/` between runs (commit it, or cache it) for new and fixed findings and SLAs.

## Gate on new findings only

```sh
fleetreach scan -f json > current.json
fleetreach diff baseline.json current.json --fail-on high
```

`diff` reads two saved reports, nothing else, and exits 1 only when a new finding trips the
gate. See [Track drift between scans](/fleetreach/docs/guides/track-drift-between-scans/).

## Gating flags

| Flag | Fails the build when |
|------|----------------------|
| `--fail-on <severity>` | a finding reaches the severity (default `low`; unknown always counts) |
| `--fail-on-kev` | a finding is on CISA's KEV list (with `--enrich`) |
| `--min-epss 0.5` | a finding's EPSS score is at least 0.5 (with `--enrich`) |
| `--fail-on-ssvc out-of-cycle` | the SSVC decision is at least out-of-cycle |
| `--fail-on-warnings` | any supply-chain warning is present |
| `--require-full-coverage` | any source was only partly read |
