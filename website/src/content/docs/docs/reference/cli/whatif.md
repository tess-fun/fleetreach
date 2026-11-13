---
title: fleetreach whatif
description: "fleetreach whatif: What a set of bumps would clear, leave and add, from a saved report, before any edit. Every flag, from the binary's help."
sidebar:
  order: 14
---

What a set of bumps would clear, leave and add, from a saved report, before any edit

```text
What a set of bumps would clear, leave and add, from a saved report, before any edit

Usage: fleetreach whatif [OPTIONS] --report <REPORT>

Options:
      --report <REPORT>  The saved report (`fleetreach scan -f json > report.json`)
      --bump <BUMP>      A bump to try, `[ECOSYSTEM:]PACKAGE@VERSION` (repeatable); the ecosystem is needed only when the package name is in more than one
      --top <N>          Try the first N upgrades of the remediation queue
      --plan <PLAN>      Try every edit of a `fix plan` file that is not blocked, each in its own repo
      --repo <REPO>      Apply `--bump` and `--top` bumps to this repo only
  -c, --config <CONFIG>  fleet.toml, for `[settings.osv]`; `./fleet.toml` is read when it exists
      --osv-dir <DIR>    Directory of OSV exports to match targets against
  -f, --format <FORMAT>  [default: table] [possible values: table, json]
  -h, --help             Print help
```
