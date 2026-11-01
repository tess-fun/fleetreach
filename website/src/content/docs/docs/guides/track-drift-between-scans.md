---
title: Track drift between scans
description: Compare two saved fleetreach reports to see new, fixed and still-open findings, and fail a pull request only on what it introduced.
sidebar:
  order: 5
---

`fleetreach diff <baseline.json> <current.json>` splits findings into **new**, **fixed**
and **still open**. It answers "did this change make the fleet better or worse?", and gates
CI on new findings only.

```sh
fleetreach scan -f json > current.json
fleetreach diff baseline.json current.json --fail-on high
```

`diff` reads two JSON files and nothing else: no scanning, no advisory data, no network.
Its exit code mirrors `scan`: `1` when a new finding meets `--fail-on`. `--exit-zero` makes
it report-only.

## Keep a baseline

The usual pattern: the default branch saves its report as an artifact (or commits it), and
each pull request diffs against it.

```yaml title=".github/workflows/audit.yml (excerpt)"
- run: fleetreach scan -f json > current.json || true
- run: fleetreach diff baseline/report.json current.json --fail-on high
```

For a fleet-wide record of every run, with trends and time to fix, use the
[scan history](/fleetreach/docs/guides/track-history-and-slas/) instead.
