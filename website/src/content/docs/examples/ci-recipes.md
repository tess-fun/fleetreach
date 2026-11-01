---
title: CI recipes
description: "Copyable CI configurations for fleetreach: GitHub Actions per repo and per org, GitLab CI, a pull-request gate on new findings only, and a nightly SLA check."
sidebar:
  order: 3
---

## GitHub: one repo, SARIF to the Security tab

```yaml
- uses: tess-fun/fleetreach@v1
  with:
    args: "--enrich --fail-on high"
```

## GitHub: fail a pull request only on new findings

```yaml
on: pull_request
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: curl -fsSL https://raw.githubusercontent.com/tess-fun/fleetreach/main/scripts/install.sh | sh
      - run: |
          git worktree add ../base "origin/${{ github.base_ref }}"
          printf '[[repo]]\nid = "repo"\npath = "../base"\n' > base.toml
          printf '[[repo]]\nid = "repo"\npath = "."\n' > head.toml
          fleetreach scan -c base.toml -f json > base.json || true
          fleetreach scan -c head.toml -f json > head.json || true
          fleetreach diff base.json head.json --fail-on high
```

Both scans use the same repo id, so `diff` compares like with like.

## Nightly: fail when anything is past its SLA

```yaml
- run: fleetreach scan --sync --enrich --history-dir history/ > /dev/null || test $? -eq 1
- run: fleetreach history sla --history-dir history/ -c fleet.toml
```

## Nightly: weekly license gate

```yaml
- run: fleetreach licenses -c fleet.toml
```

## GitLab: scheduled fleet job

See [GitLab CI](/fleetreach/docs/integrations/gitlab-ci/) for the full pipeline.

```yaml
fleet-audit:
  rules: [{ if: '$CI_PIPELINE_SOURCE == "schedule"' }]
  script:
    - fleetreach scan --sync --enrich -f json > report.json || test $? -eq 1
  artifacts: { paths: [report.json] }
```

## Any CI: exit codes

`0` pass, `1` findings, `2` could not read something. Treat `2` as a failure even when you
accept `1`. See [Exit codes](/fleetreach/docs/reference/exit-codes/).
