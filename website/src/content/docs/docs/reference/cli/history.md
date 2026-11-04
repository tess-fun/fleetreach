---
title: fleetreach history
description: "fleetreach history: Trends, age, SLA breaches and time to fix from `scan --history-dir` snapshots. Every flag, from the binary's help."
sidebar:
  order: 9
---

Trends, age, SLA breaches and time to fix from `scan --history-dir` snapshots

```text
Trends, age, SLA breaches and time to fix from `scan --history-dir` snapshots

Usage: fleetreach history <COMMAND>

Commands:
  trend  Open findings per run, grouped
  age    Open findings by how long they have been open, oldest first
  sla    Open findings past their `[settings.sla]` deadline; exits 1 on any
  mttr   Mean and median time to fix
  epss   Open advisories whose EPSS rose sharply; exits 1 on any
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## fleetreach history trend

Open findings per run, grouped

```text
Open findings per run, grouped

Usage: fleetreach history trend [OPTIONS] --history-dir <HISTORY_DIR>

Options:
      --history-dir <HISTORY_DIR>  The directory `scan --history-dir` writes
  -f, --format <FORMAT>            [default: table] [possible values: table, json]
      --at <AT>                    Measure as of this time (RFC 3339) instead of now
      --by <BY>                    [default: severity] [possible values: severity, ssvc, ecosystem, owner]
      --since <SINCE>              Only runs this recent (`90d`)
  -h, --help                       Print help
```

## fleetreach history age

Open findings by how long they have been open, oldest first

```text
Open findings by how long they have been open, oldest first

Usage: fleetreach history age [OPTIONS] --history-dir <HISTORY_DIR>

Options:
      --history-dir <HISTORY_DIR>  The directory `scan --history-dir` writes
  -f, --format <FORMAT>            [default: table] [possible values: table, json]
      --at <AT>                    Measure as of this time (RFC 3339) instead of now
      --min-age <MIN_AGE>          Only findings open at least this long (`30d`)
  -h, --help                       Print help
```

## fleetreach history sla

Open findings past their `[settings.sla]` deadline; exits 1 on any

```text
Open findings past their `[settings.sla]` deadline; exits 1 on any

Usage: fleetreach history sla [OPTIONS] --history-dir <HISTORY_DIR>

Options:
      --history-dir <HISTORY_DIR>  The directory `scan --history-dir` writes
  -f, --format <FORMAT>            [default: table] [possible values: table, json]
      --at <AT>                    Measure as of this time (RFC 3339) instead of now
  -c, --config <CONFIG>            fleet.toml holding `[settings.sla]` [default: ./fleet.toml]
  -h, --help                       Print help
```

## fleetreach history mttr

Mean and median time to fix

```text
Mean and median time to fix

Usage: fleetreach history mttr [OPTIONS] --history-dir <HISTORY_DIR>

Options:
      --history-dir <HISTORY_DIR>  The directory `scan --history-dir` writes
  -f, --format <FORMAT>            [default: table] [possible values: table, json]
      --at <AT>                    Measure as of this time (RFC 3339) instead of now
      --by <BY>                    [default: severity] [possible values: severity, ssvc, ecosystem, owner]
  -h, --help                       Print help
```

## fleetreach history epss

Open advisories whose EPSS rose sharply; exits 1 on any

```text
Open advisories whose EPSS rose sharply; exits 1 on any

Usage: fleetreach history epss [OPTIONS] --history-dir <HISTORY_DIR>

Options:
      --history-dir <HISTORY_DIR>  The directory `scan --history-dir` writes
  -f, --format <FORMAT>            [default: table] [possible values: table, json]
      --at <AT>                    Measure as of this time (RFC 3339) instead of now
      --since <SINCE>              Only runs this recent (`30d`)
      --rise <RISE>                Flag a rise of at least this much [default: 0.1]
      --top <TOP>                  Flag an entry into this top share of all scored CVEs [default: 0.05]
  -h, --help                       Print help
```
