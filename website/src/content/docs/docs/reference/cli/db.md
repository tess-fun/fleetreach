---
title: fleetreach db
description: "fleetreach db: Manage the advisory data: osv.dev exports, CVE 5.x and vendor CSAF indexes, quality. Every flag, from the binary's help."
sidebar:
  order: 4
---

Manage the advisory data: osv.dev exports, CVE 5.x and vendor CSAF indexes, quality

```text
Manage the advisory data: osv.dev exports, CVE 5.x and vendor CSAF indexes, quality

Usage: fleetreach db <COMMAND>

Commands:
  sync        Fetch or refresh the exports the fleet needs (or --all / --ecosystems)
  import      Bring in local data for hosts that cannot fetch it: a bundle, or one source's copy
  snapshot    Write a dated, hashed manifest of every source, for `scan --db-snapshot`
  bundle      Pack every source into one tar for `db import --bundle`
  status      Show which exports are present and how old they are
  quality     Report data-quality issues in the local advisory data and overlay
  crosscheck  Measure what the CVE and CSAF indexes add to or contradict in the OSV data (JSON)
  help        Print this message or the help of the given subcommand(s)

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
      --all                fetch every language osv.dev export fleetreach can read (distro exports are fetched only by name or for a fleet's images: some are over a gigabyte)
      --distros <DISTROS>  fetch the exports for these distro releases (comma-separated, e.g. Debian:12,Wolfi): the whole distribution's export, which is what osv.dev maintains
      --osv-dir <DIR>      sync into this directory instead of the default cache (e.g. to copy to an air-gapped host)
      --source <SOURCES>   what to fetch: `osv` (the exports), `cve` (cvelistV5), `csaf:<provider>` (vendor CSAF VEX; `csaf:redhat`, `csaf:suse`), `rustsec`, `kev` and `epss`; `nvd` and `vulnrichment` copy what scans have cached. All of them land in one directory for `db bundle` [default: osv]
      --force              re-download even if the cached export was checked recently
  -q, --quiet              no progress output
  -h, --help               Print help
```

## fleetreach db import

Bring in local data for hosts that cannot fetch it: a bundle, or one source's copy

```text
Bring in local data for hosts that cannot fetch it: a bundle, or one source's copy

Usage: fleetreach db import [OPTIONS]

Options:
      --bundle <PATH>        a `db bundle` tar: every file is checked against its manifest before any is installed
      --sha256 <HEX>         refuse a bundle whose sha256 is not this (the one `db bundle` printed)
      --cve <PATH>           a cvelistV5 checkout, its `cves.zip`, or a release's `*_all_CVEs_at_midnight.zip.zip`
      --csaf <PATH>          a directory of CSAF documents, or a `.tar.zst` or `.tar.bz2` archive (Red Hat's `csaf_vex_<date>.tar.zst`, SUSE's `csaf-vex.tar.bz2`)
      --provider <PROVIDER>  the provider name the CSAF index is filed under (`redhat`, `suse`) [default: redhat]
      --rustsec <DIR>        a RustSec advisory-db clone
      --kev <PATH>           a KEV catalog JSON file
      --epss <PATH>          an EPSS CSV file
      --osv-dir <DIR>        index into this directory instead of the default cache
  -q, --quiet                no progress output
  -h, --help                 Print help
```

## fleetreach db snapshot

Write a dated, hashed manifest of every source, for `scan --db-snapshot`

```text
Write a dated, hashed manifest of every source, for `scan --db-snapshot`

Usage: fleetreach db snapshot [OPTIONS]

Options:
      --osv-dir <DIR>  snapshot this directory instead of the default cache
  -o, --out <FILE>     write here instead of `snapshot-<date>.json` in the directory
  -q, --quiet          no progress output
  -h, --help           Print help
```

## fleetreach db bundle

Pack every source into one tar for `db import --bundle`

```text
Pack every source into one tar for `db import --bundle`

Usage: fleetreach db bundle [OPTIONS] --out <FILE>

Options:
      --osv-dir <DIR>  pack this directory instead of the default cache
  -o, --out <FILE>     the tar to write
  -q, --quiet          no progress output
  -h, --help           Print help
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

## fleetreach db quality

Report data-quality issues in the local advisory data and overlay

```text
Report data-quality issues in the local advisory data and overlay

Usage: fleetreach db quality [OPTIONS]

Options:
  -c, --config <CONFIG>       fleet.toml whose `[settings.advisories] dir` overlay to check with the data (optional)
      --advisories-dir <DIR>  check this overlay directory (overrides the config's)
      --osv-dir <DIR>         read this directory instead of the default cache
      --json                  print every issue as JSON instead of the summary
      --limit <LIMIT>         examples to print per check [default: 5]
  -h, --help                  Print help
```

## fleetreach db crosscheck

Measure what the CVE and CSAF indexes add to or contradict in the OSV data (JSON)

```text
Measure what the CVE and CSAF indexes add to or contradict in the OSV data (JSON)

Usage: fleetreach db crosscheck [OPTIONS]

Options:
      --osv-dir <DIR>  read this directory instead of the default cache
      --json           print the measurements as JSON
      --limit <LIMIT>  examples to keep per kind [default: 5]
  -h, --help           Print help
```
