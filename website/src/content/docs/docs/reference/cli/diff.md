---
title: fleetreach diff
description: "fleetreach diff: Compare two saved JSON reports: new vs. fixed vs. still-open findings. Every flag, from the binary's help."
sidebar:
  order: 2
---

Compare two saved JSON reports: new vs. fixed vs. still-open findings

```text
Compare two saved JSON reports: new vs. fixed vs. still-open findings

Usage: fleetreach diff [OPTIONS] <BASELINE> <CURRENT>

Arguments:
  <BASELINE>  Prior report JSON — the baseline to compare against
  <CURRENT>   Current report JSON, from `fleetreach scan -f json`

Options:
  -f, --format <FORMAT>      [default: table] [possible values: table, json]
      --fail-on <FAIL_ON>    fail if any NEW vuln is at/above this severity (Unknown always counts) [default: low] [possible values: low, medium, high, critical]
      --fail-on-warnings     also fail if a NEW supply-chain warning appeared
      --exit-zero            always exit 0 (report-only; never gate on new findings)
      --base <REF>           Attribute each new finding to the lockfile and manifest lines changed since the merge base with this git ref, and gate only on what the change brought in
      --fail-on-dev <FLOOR>  The floor for dev and build-only packages under `--base`, or `never` [possible values: low, medium, high, critical, never]
      --checkout <DIR>       The git checkout `--base` reads [default: .]
      --repo <ID>            The repo id of that checkout, when the reports cover several repos
  -h, --help                 Print help
```
