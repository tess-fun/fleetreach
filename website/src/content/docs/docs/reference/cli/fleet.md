---
title: fleetreach fleet
description: "fleetreach fleet: Discover and check out the repos named by `[[source]]` entries. Every flag, from the binary's help."
sidebar:
  order: 5
---

Discover and check out the repos named by `[[source]]` entries

```text
Discover and check out the repos named by `[[source]]` entries

Usage: fleetreach fleet <COMMAND>

Commands:
  sync  List every source afresh and clone or refresh its checkouts
  list  Print the repos the fleet resolves to (no network)
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## fleetreach fleet sync

List every source afresh and clone or refresh its checkouts

```text
List every source afresh and clone or refresh its checkouts

Usage: fleetreach fleet sync [OPTIONS]

Options:
  -c, --config <CONFIG>  fleet.toml whose `[[source]]` entries to list and check out [default: ./fleet.toml]
  -q, --quiet            no progress output
  -h, --help             Print help
```

## fleetreach fleet list

Print the repos the fleet resolves to (no network)

```text
Print the repos the fleet resolves to (no network)

Usage: fleetreach fleet list [OPTIONS]

Options:
  -c, --config <CONFIG>  fleet.toml to resolve (explicit repos plus cached source listings) [default: ./fleet.toml]
  -h, --help             Print help
```
