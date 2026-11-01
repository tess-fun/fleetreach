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

On the demo fleet, between a scan on 1 September and one on 15 October: billing moved to a
newer rack (fixed) and partner-api joined the fleet (new).

<!-- run: fleetreach diff before.json report.json | head -n 12 -->
```console
$ fleetreach diff before.json report.json | head -n 12
29 new, 12 fixed, 183 still open.

New (29):

┌──────────┬─────────────────────┬────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Severity ┆ Advisory            ┆ Repos  ┆ Title                                                                                                                                         │
╞══════════╪═════════════════════╪════════╪═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╡
│ critical ┆ GHSA-7rjr-3q55-vv33 ┆ 1 (+1) ┆ Incomplete fix for Apache Log4j vulnerability                                                                                                 │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ critical ┆ GHSA-jfh8-c2jp-5v3q ┆ 1 (+1) ┆ Remote code injection in Log4j                                                                                                                │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ high     ┆ GHSA-57j2-w4cx-62h2 ┆ 1 (+1) ┆ Deeply nested json in jackson-databind                                                                                                        │
```
<!-- /run -->

## Keep a baseline

The usual pattern: the default branch saves its report as an artifact (or commits it), and
each pull request diffs against it.

```yaml title=".github/workflows/audit.yml (excerpt)"
- run: fleetreach scan -f json > current.json || true
- run: fleetreach diff baseline/report.json current.json --fail-on high
```

For a fleet-wide record of every run, with trends and time to fix, use the
[scan history](/fleetreach/docs/guides/track-history-and-slas/) instead.
