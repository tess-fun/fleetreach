---
title: fleetreach vex
description: "fleetreach vex: Operate on OpenVEX documents (drift gate, witness verification). Every flag, from the binary's help."
sidebar:
  order: 3
---

Operate on OpenVEX documents (drift gate, witness verification)

```text
Operate on OpenVEX documents (drift gate, witness verification)

Usage: fleetreach vex <COMMAND>

Commands:
  check   Fail when a committed OpenVEX document has drifted from a fresh scan (§10)
  verify  Re-derive each machine `not_affected` witness against current source (§9.2)
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## fleetreach vex check

Fail when a committed OpenVEX document has drifted from a fresh scan (§10)

```text
Fail when a committed OpenVEX document has drifted from a fresh scan (§10)

Usage: fleetreach vex check [OPTIONS] --against <PATH>

Options:
  -c, --config <CONFIG>  [default: ./fleet.toml]
      --against <PATH>   the committed OpenVEX document to check against
      --db <DB>          use a local advisory-db clone instead of fetching
      --db-rev <DB_REV>  pin advisory DB to an exact commit (requires --db)
      --offline          never fetch; require cache/--db
  -q, --quiet            suppress the summary line
  -h, --help             Print help
```

## fleetreach vex verify

Re-derive each machine `not_affected` witness against current source (§9.2)

```text
Re-derive each machine `not_affected` witness against current source (§9.2)

Usage: fleetreach vex verify [OPTIONS] <DOCUMENT>

Arguments:
  <DOCUMENT>
          The OpenVEX document whose machine witnesses to re-check

Options:
  -c, --config <CONFIG>
          [default: ./fleet.toml]

      --db <DB>
          use a local advisory-db clone instead of fetching

      --db-rev <DB_REV>
          pin advisory DB to an exact commit (requires --db)

      --offline
          never fetch; require cache/--db

      --allow-untrusted-builds
          REQUIRED: re-deriving witnesses compiles each repo, running its build scripts and proc-macros (arbitrary code). Only verify repos you trust.

      --reach-driver <PATH>
          path to the built fleetreach-reach-driver

      --build-sandbox <MODE>
          Possible values:
          - auto:    Confine if a mechanism is available, else warn and run unconfined
          - off:     Never confine — run the build with full user privileges
          - require: Confine, or refuse to build (→ Unknown) if no mechanism is available
          
          [default: auto]

      --features <FEATURES>
          

      --all-features
          

      --no-default-features
          

  -q, --quiet
          suppress the summary line

  -v, --verbose
          per-repo progress to stderr

  -h, --help
          Print help (see a summary with '-h')
```
