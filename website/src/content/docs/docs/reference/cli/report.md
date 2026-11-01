---
title: fleetreach report
description: "fleetreach report: Publishable reports from the scan history. Every flag, from the binary's help."
sidebar:
  order: 11
---

Publishable reports from the scan history

```text
Publishable reports from the scan history

Usage: fleetreach report <COMMAND>

Commands:
  html  One self-contained HTML page from `scan --history-dir` snapshots
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## fleetreach report html

One self-contained HTML page from `scan --history-dir` snapshots

```text
One self-contained HTML page from `scan --history-dir` snapshots

Usage: fleetreach report html [OPTIONS] --history-dir <HISTORY_DIR>

Options:
      --history-dir <HISTORY_DIR>  The directory `scan --history-dir` writes
  -o, --output <OUTPUT>            Where to write the page (`-` for stdout) [default: fleet-report.html]
  -c, --config <CONFIG>            fleet.toml whose `[settings.sla]` sets deadlines (without it no breaches are shown)
      --fix-status <FIX_STATUS>    A saved `fleetreach fix status` (JSON) to list the fix campaigns
      --title <TITLE>              The page title [default: "Fleet security report"]
      --since <SINCE>              Only runs this recent in the trend (`90d`)
  -h, --help                       Print help
```
