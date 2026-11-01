---
title: Run offline or air-gapped
description: Prepare advisory data on a connected machine with fleetreach db sync, carry it across, and scan with no network, including KEV and EPSS from files.
sidebar:
  order: 14
---

fleetreach reads advisory data from files, so it runs without a network once the files are
there. On a connected machine:

```sh
fleetreach db sync --all --osv-dir ./osv            # every osv.dev export fleetreach reads
git clone https://github.com/rustsec/advisory-db     # RustSec
curl -fsSLo kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

Carry `osv/`, `advisory-db/` and `kev.json` across, then:

```sh
fleetreach scan --offline --db ./advisory-db --osv-dir ./osv --kev-file kev.json
```

`--offline` refuses every network call. Set the directory once instead of on every command:

```toml title="fleet.toml"
[settings.osv]
dir = "../osv"     # laid out as <dir>/<Ecosystem>/all.zip, the osv.dev bucket layout
```

`fleetreach db status` shows which exports are present and how old they are, and
`--max-db-age 7d` refuses data older than that (including data whose age cannot be told).

## The offline build

`cargo install fleetreach-cli` without `--features network` has no network code at all, for
environments that require it. It needs `--db` and `--osv-dir`.

## Where data comes from, in order

1. `--<ecosystem>-vuln-db file://<path>` for one ecosystem.
2. `--osv-dir`, `FLEETREACH_OSV_DIR` or `[settings.osv] dir`.
3. The cache, `~/.cache/fleetreach/osv/`, refreshed every 6 hours in network builds unless
   `--offline` or `FLEETREACH_OSV_SYNC=off`.

Without data for an ecosystem the fleet uses, its repos are errored gaps, never clean.
