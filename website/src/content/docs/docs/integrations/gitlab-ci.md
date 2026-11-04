---
title: GitLab CI
description: Scan a GitLab group with fleetreach in a scheduled pipeline, keep one issue per owner, and open verified merge requests with glab.
sidebar:
  order: 2
---

fleetreach discovers a GitLab group (subgroups included), opens issues and merge requests
through `glab`, and works the same on gitlab.com and self-managed GitLab.

```yaml title=".gitlab-ci.yml"
fleet-audit:
  image: rust:1.89            # or any image; fleetreach is one static binary
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
  variables:
    GITLAB_TOKEN: $FLEET_READ_TOKEN      # read_api + read_repository
  script:
    - curl -fsSL https://raw.githubusercontent.com/tess-fun/fleetreach/main/scripts/install.sh | sh
    - fleetreach scan --sync --enrich --history-dir history/ -f json > report.json || test $? -eq 1
    - fleetreach notify --history-dir history/ -c fleet.toml --gitlab-issues --repo acme/security
    - fleetreach report html --history-dir history/ -c fleet.toml -o public/index.html
  cache:
    key: fleetreach-history
    paths: [history/]
  artifacts:
    paths: [report.json, public/]
```

```toml title="fleet.toml"
[[source]]
kind = "gitlab"
org  = "acme/platform"
# api_url = "https://gitlab.example.com/api/v4"   # self-managed
```

`|| test $? -eq 1` keeps the job going when findings exist (exit 1) but still fails it when
something could not be read (exit 2). A cache can be evicted; for long-lived SLA history,
commit `history/` to a repo instead.

## One repo, on every pipeline

To scan a single project, include the template. It installs the release binary, scans the repo
and keeps `fleetreach.sarif` as an artifact, whether the scan passes or not:

```yaml title=".gitlab-ci.yml"
include:
  - remote: https://raw.githubusercontent.com/tess-fun/fleetreach/main/ci/fleetreach.gitlab-ci.yml

variables:
  FLEETREACH_ARGS: "--enrich"     # extra `fleetreach scan` flags
```

`FLEETREACH_VERSION` pins a release and `FLEETREACH_CONFIG` names a `fleet.toml`. The job fails
on findings at the gate and when something could not be read. To keep a pipeline going on
findings alone, add this to the job:

```yaml
fleetreach:
  allow_failure:
    exit_codes: [1]
```

## Merge requests

```sh
fleetreach fix plan --report report.json > plan.json
fleetreach fix apply -c fleet.toml plan.json --open-pr
```

The forge is chosen per repo from its `origin` host; pass `--forge gitlab` for a
self-managed host whose name does not contain `gitlab`. Only verified branches are pushed.
See [Plan and apply fixes](/fleetreach/docs/guides/plan-and-apply-fixes/).
