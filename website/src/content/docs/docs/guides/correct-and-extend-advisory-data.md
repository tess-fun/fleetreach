---
title: Correct and extend advisory data
description: Add your own advisories and corrections as OSV files, bring in CVE 5.x records and Red Hat CSAF VEX, check the local data for quality problems, and measure what each source adds.
sidebar:
  order: 17
---

Upstream advisory data is good but not perfect: a range can be wrong, a record can cover a
package that is not affected, and an issue your team found may never be filed. fleetreach lets
you fix that locally, versioned with your config, and shows where the data has problems.

## Your own advisories and corrections

Put OSV JSON records in a directory next to `fleet.toml` and point the config at it:

```toml
[settings.advisories]
dir = "advisories"   # searched recursively; subdirectories and hidden files are fine
```

Every OSV feeder (npm, PyPI, RubyGems, Packagist, NuGet, Julia, Swift, Hex, GitHub Actions,
Maven) layers these records over its upstream export:

| Your record | Effect |
|-------------|--------|
| same `id` as an upstream record | **replaces** it everywhere (copy the upstream record and edit it) |
| a new `id` (for example `ACME-2026-001`) | **adds** an advisory |
| same `id` with `withdrawn` set | **retracts** the upstream record |

A correction is a whole record, not a patch, so it never depends on the upstream text staying
the same. Keep `modified` current: `db quality` flags a correction whose upstream record
changed after it (`overlay-stale`), so you know to review it.

The overlay is fail-closed. A configured directory that is missing, unreadable or holds a file
that is not valid OSV JSON stops the scan with exit 2, and a duplicate `id` is refused. Go and
Rust do not read OSV exports through this loader (Go's offline matcher reads its own format,
Rust reads RustSec), so a record for them is not applied: the scan warns, and `db quality`
reports it as an error. The report's `provenance.osv` gets an `overlay` entry with the
directory and a sha256 over every record, so a report says which corrections it was produced
with.

## CVE 5.x records and vendor CSAF

```sh
fleetreach db sync --source cve,csaf:redhat     # network build
fleetreach db import --cve ./cvelistV5          # or a local copy
fleetreach db import --csaf ./csaf_vex_2026-11-01.tar.zst --provider redhat
```

- **CVE 5.x** (the CVE Program's [cvelistV5](https://github.com/CVEProject/cvelistV5)) carries
  what the CNA wrote at publication: affected products and versions, often a package registry
  and name or a repository, plus ADP enrichment such as CISA's CVSS and SSVC. `db sync` takes
  the newest full snapshot; `db import` reads a checkout, its `cves.zip`, or a release's
  `*_all_CVEs_at_midnight.zip.zip`.
- **Red Hat CSAF VEX** gives a status for every Red Hat product and component per CVE,
  including the ones OSV's Red Hat export does not carry: affected with no fix yet, will not
  fix, fix deferred, out of support scope, under investigation, and not affected with a
  justification. `db import --csaf` reads any CSAF 2.0 directory or `.tar.zst`.

Both are reduced to a compact index next to the OSV exports (`cvelistV5/index.jsonl.gz`,
`csaf/<provider>/index.jsonl.gz`, each with a `.meta.json` recording the upstream file,
sha256 and date), so one directory still serves an air-gapped host. `db status` lists them.
A failed fetch or index never replaces a good one.

In this release they feed `db quality` and `db crosscheck`; scans do not match against them
yet. CVE-derived package data is the CNA's claim, unreviewed; Red Hat's statuses are for OS
packages, which scans read in a later release.

## Check the data: `db quality`

```sh
fleetreach db quality                 # the default cache
fleetreach db quality -c fleet.toml   # with your overlay layered on
fleetreach db quality --json          # every issue
```

| Check | Level | Meaning |
|-------|-------|---------|
| `unmatchable-entry` | warning | an affected package has no range or version list its feeder evaluates, so it never matches |
| `versions-outside-ranges` | warning | enumerated affected versions the record's own ranges call safe |
| `events-out-of-order` | warning | range bounds decrease in the order written |
| `unparseable-bound` | warning | an `introduced` bound the ecosystem's parser rejects (matched as affected) |
| `alias-conflict` | warning | records for the same CVE and package name different fixed versions |
| `rejected-cve-alias` | warning | a live record aliases a CVE that cvelistV5 marks REJECTED (needs the CVE index) |
| `missing-severity` | info | no CVSS vector and no severity band |
| `withdrawn` | info | a withdrawn record still in the export (never matched) |
| `overlay-not-applied` | error | an overlay record for an ecosystem no OSV feeder layers |
| `overlay-stale` | warning | upstream changed the record after your correction |
| `overlay-revives-withdrawn` | warning | your record replaces one upstream withdrew |

The checks run on the data as the matchers see it: each feeder's own version parser and range
type, with the overlay applied. Exit code 1 means an error-level issue, 2 that the data could
not be read.

## Measure the sources: `db crosscheck`

`db crosscheck` prints, as JSON, what the CVE and CSAF indexes add to or contradict in the OSV
data: CVEs whose CNA data maps to a package OSV has no record for, CNA fixed versions that
disagree with OSV's, how often the CVE was published before the first OSV record, live OSV
records aliasing rejected CVEs, OSV records with no severity whose CVE has a CVSS vector, and,
for Red Hat, how many of OSV's fixes the CSAF data confirms exactly and how many unfixed
statuses it adds. Each kind keeps a few examples (`--limit`) for checking against the source.
