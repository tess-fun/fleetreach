---
title: fleetreach db
description: "fleetreach db: Manage the osv.dev exports the toolchain-free ecosystems match against. Every flag, from the binary's help."
sidebar:
  order: 4
---

Manage the osv.dev exports the toolchain-free ecosystems match against

```text
Manage the osv.dev exports the toolchain-free ecosystems match against

Usage: fleetreach db <COMMAND>

Commands:
  sync    Fetch or refresh the exports the fleet needs (or --all / --ecosystems)
  status  Show which exports are present and how old they are
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## fleetreach db sync

Fetch or refresh the exports the fleet needs (or --all / --ecosystems)

```text
Fetch or refresh the exports the fleet needs (or --all / --ecosystems)

Usage: fleetreach db sync [OPTIONS]

Options:
  -c, --config <CONFIG>    fleet.toml whose ecosystems decide what to fetch (ignored with --all/--ecosystems) [default: ./fleet.toml]
      --ecosystems <ECOS>  fetch these ecosystems (comma-separated, e.g. npm,pypi,maven)
      --all                fetch every osv.dev export fleetreach can read
      --osv-dir <DIR>      sync into this directory instead of the default cache (e.g. to copy to an air-gapped host)
      --force              re-download even if the cached export was checked recently
  -q, --quiet              no progress output
  -h, --help               Print help
```

## fleetreach db status

Show which exports are present and how old they are

```text
Show which exports are present and how old they are

Usage: fleetreach db status [OPTIONS]

Options:
      --osv-dir <DIR>  show this directory instead of the default cache
  -h, --help           Print help
```
