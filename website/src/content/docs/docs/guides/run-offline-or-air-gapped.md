---
title: Run offline or air-gapped
description: Prepare advisory data on a connected machine with fleetreach db sync, carry it across, and scan with no network, including KEV and EPSS from files.
sidebar:
  order: 14
---

fleetreach reads advisory data from files, so it runs without a network once the files are
there. On a connected machine:

```sh
fleetreach db sync --all --osv-dir ./data --source osv,rustsec,kev,epss
fleetreach scan --enrich --osv-dir ./data            # fills the NVD and Vulnrichment caches
fleetreach db sync --osv-dir ./data --source nvd,vulnrichment
fleetreach db bundle --osv-dir ./data -o data.tar    # prints the tar's sha256
```

Add `csaf:redhat`, `csaf:suse` and `cve` to `--source`, and `--distros` for distro exports, or
leave out `--all` and give a `-c fleet.toml`, which fetches what the fleet's repos and images
need. Carry `data.tar` across, then:

```sh
fleetreach db import --bundle data.tar --sha256 <hash> --osv-dir ./data
fleetreach scan --offline --enrich --osv-dir ./data
```

The import checks every file against the bundle's manifest before it replaces anything. An
offline scan finds RustSec, KEV, EPSS and both caches in that directory, so its findings are
the ones the connected scan reported. The caches hold only the CVEs scans have asked about,
so a CVE new to the offline fleet has no NVD backfill or Vulnrichment answer.

`--offline` refuses every network call. A host that cannot use a bundle can take the pieces:
`db import --rustsec <clone> --kev <file> --epss <file>`, or `--db`, `--kev-file` and
`--epss-file` on the scan. Set the directory once instead of on every command:

```toml title="fleet.toml"
[settings.osv]
dir = "../osv"     # laid out as <dir>/<Ecosystem>/all.zip, the osv.dev bucket layout
```

`fleetreach db status` shows which exports are present and how old they are, and
`--max-db-age 7d` refuses data older than that (including data whose age cannot be told).

## Pin a run to a snapshot

```sh
fleetreach db snapshot --osv-dir ./data              # writes ./data/snapshot-<date>.json
fleetreach scan --db-snapshot ./data/snapshot-2026-11-04.json
```

The manifest lists every source with its hash, upstream URL, date and, for RustSec, its commit.
`--db-snapshot` turns the run offline and exits 2 unless the directory holds exactly those files,
naming what changed, is missing or is extra. The manifest's hash goes in the report as
`provenance.db_snapshot`. An imported bundle has its manifest at `<dir>/manifest.json`. A later
`db sync` changes the data and so ends the pin: keep the bundle to go back to that day.

## The offline build

`cargo install fleetreach-cli` without `--features network` has no network code at all, for
environments that require it. It needs `--db` and `--osv-dir`.

## Where data comes from, in order

1. `--<ecosystem>-vuln-db file://<path>` for one ecosystem.
2. `--osv-dir`, `FLEETREACH_OSV_DIR` or `[settings.osv] dir`.
3. The cache, `~/.cache/fleetreach/osv/`, refreshed every 6 hours in network builds unless
   `--offline` or `FLEETREACH_OSV_SYNC=off`.

Without data for an ecosystem the fleet uses, its repos are errored gaps, never clean.
Here the demo fleet's Elixir repo is scanned against a directory with no Hex export:

<!-- run: fleetreach scan -c ecosystems/hex.toml --osv-dir no-such-dir >/dev/null; echo "exit $?" -->
```console
$ fleetreach scan -c ecosystems/hex.toml --osv-dir no-such-dir >/dev/null; echo "exit $?"
note: no OSV export for Hex; run `fleetreach db sync` (network build) or pass --osv-dir <dir> laid out as <dir>/<Ecosystem>/all.zip
Scanned 0 repo(s) (1 errored): 0 vulns, 0 warning(s); max severity unknown.
exit 2
```
<!-- /run -->
