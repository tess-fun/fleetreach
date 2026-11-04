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
  import      Index a local cvelistV5 or vendor CSAF copy (for hosts that cannot fetch them)
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
      --source <SOURCES>   what to fetch: `osv` (the exports), `cve` (cvelistV5) and `csaf:<provider>` (vendor CSAF VEX; `csaf:redhat`, `csaf:suse`) [default: osv]
      --force              re-download even if the cached export was checked recently
  -q, --quiet              no progress output
  -h, --help               Print help
```

## fleetreach db import

Index a local cvelistV5 or vendor CSAF copy (for hosts that cannot fetch them)

```text
Index a local cvelistV5 or vendor CSAF copy (for hosts that cannot fetch them)

Usage: fleetreach db import [OPTIONS]

Options:
      --cve <PATH>           a cvelistV5 checkout, its `cves.zip`, or a release's `*_all_CVEs_at_midnight.zip.zip`
      --csaf <PATH>          a directory of CSAF documents, or a `.tar.zst` or `.tar.bz2` archive (Red Hat's `csaf_vex_<date>.tar.zst`, SUSE's `csaf-vex.tar.bz2`)
      --provider <PROVIDER>  the provider name the CSAF index is filed under (`redhat`, `suse`) [default: redhat]
      --osv-dir <DIR>        index into this directory instead of the default cache
  -q, --quiet                no progress output
  -h, --help                 Print help
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
