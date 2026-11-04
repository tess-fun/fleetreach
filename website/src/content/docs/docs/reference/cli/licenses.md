---
title: fleetreach licenses
description: "fleetreach licenses: License inventory and policy violations across the fleet. Every flag, from the binary's help."
sidebar:
  order: 7
---

License inventory and policy violations across the fleet

```text
License inventory and policy violations across the fleet

Usage: fleetreach licenses [OPTIONS]

Options:
  -c, --config <CONFIG>        fleet.toml naming the repos (and the `[settings.licenses]` policy) [default: ./fleet.toml]
  -f, --format <FORMAT>        [default: table] [possible values: table, json]
      --sync                   List `[[source]]` entries afresh and clone or refresh their checkouts first
      --fetch                  Look up licenses no local source knows on deps.dev. Sends each such package's ecosystem, name and version to deps.dev (Google); answers are cached locally
      --detect                 Read the license files of packages on this machine: fills in what no source declares, and names a package whose files say more than it declares
      --download               With --detect, fetch the archive of each public package whose files are not on this machine, check it against the lockfile's hash and keep its license files in a shared cache. Sends each such package's name and version to its registry
      --maven-fetch            resolve pom.xml and Gradle builds with POMs fetched when they are not in ~/.m2, from the mirror of Maven Central that settings.xml names, else Maven Central (sends each artifact's coordinates there); without it, only local repositories are used
      --maven-settings <FILE>  the Maven settings.xml whose mirror --maven-fetch uses (default: ~/.m2/settings.xml when present)
  -h, --help                   Print help
```
