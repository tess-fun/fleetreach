---
title: Correct and extend advisory data
description: Add your own advisories and corrections as OSV files, bring in CVE 5.x records and Red Hat and SUSE CSAF VEX, check the local data for quality problems, and measure what each source adds.
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
fleetreach db sync --source cve,csaf:redhat,csaf:suse   # network build
fleetreach db import --cve ./cvelistV5                  # or a local copy
fleetreach db import --csaf ./csaf_vex_2026-11-01.tar.zst --provider redhat
fleetreach db import --csaf ./csaf-vex.tar.bz2 --provider suse
```

- **CVE 5.x** (the CVE Program's [cvelistV5](https://github.com/CVEProject/cvelistV5)) carries
  what the CNA wrote at publication: affected products and versions, often a package registry
  and name or a repository, plus ADP enrichment such as CISA's CVSS and SSVC. `db sync` takes
  the newest full snapshot; `db import` reads a checkout, its `cves.zip`, or a release's
  `*_all_CVEs_at_midnight.zip.zip`.
- **Red Hat CSAF VEX** gives a status for every Red Hat product and component per CVE,
  including the ones OSV's Red Hat export does not carry: affected with no fix yet, will not
  fix, fix deferred, out of support scope, under investigation, and not affected with a
  justification. `db import --csaf` reads any CSAF 2.0 directory, `.tar.zst` or `.tar.bz2`.
  Scans of RHEL and UBI images use it for the CVEs Red Hat has not fixed (see
  [container images](/fleetreach/docs/ecosystems/container-images/)).
- **SUSE CSAF VEX** does the same for SUSE and openSUSE products, per binary package. Scans
  of openSUSE, SLES and SLE Micro images use it. SUSE publishes a `.sha256` beside the
  archive that matches neither the archive nor its contents, so fleetreach records the
  sha256 of what it downloaded instead.

Both are reduced to a compact index next to the OSV exports (`cvelistV5/index.jsonl.gz`,
`csaf/<provider>/index.jsonl.gz`, each with a `.meta.json` recording the upstream file,
sha256 and date), so one directory still serves an air-gapped host. `db status` lists them.
A failed fetch or index never replaces a good one.

Both feed `db quality` and `db crosscheck`. Scans match the vendor CSAF indexes for images
of that vendor's distributions, but never the CVE 5.x records: CVE-derived package data is
the CNA's claim, unreviewed.

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

## Check fixed versions against fix commits: `db ranges`

About half of the OSV records link the commit that fixed them. `db ranges` clones each linked
repository (commits and tags only: `git clone --bare --filter=tree:0`, never checked out) and
asks which release tags contain the fix. Each published `fixed` bound gets a verdict:

| Verdict | Meaning |
|---------|---------|
| `confirmed` | the bound's tag is the first on its line with the fix |
| `fixed-earlier` | an earlier release on the same line already holds the fix: versions in between are reported vulnerable but are not |
| `fixed-later` | the bound's tag lacks the fix and a later release on its line has it: versions in between are reported safe but are vulnerable (a false clean) |
| `fix-missing` | the range has no fix, but a release at or after its start and every one after it holds the fix |
| `unverified` | the fix is on another line (a backport the record does not link), or the releases in between disagree |
| `no-tag` | no tag names the published version |
| `no-commit` | the linked commit is not in the repository |
| `no-repo` | the repository could not be cloned |

```sh
fleetreach db ranges --ecosystems npm,pypi --limit 300
fleetreach db ranges --ecosystems maven --ids GHSA-xxxx-xxxx-xxxx --json
fleetreach db ranges --ecosystems npm --out corrections/    # write the corrected records
```

A correction is proposed only when every release between the two bounds agrees with it and
both tags are on one history (`git merge-base --is-ancestor`). The registry then has to agree
too (npm, PyPI, crates.io, RubyGems, Hex and Maven Central publish times): the derived version
must be published, and after the fix was committed (a tag made later proves nothing); a fix
shipped later also needs the published version to predate the commit, since one released after
it may carry a backport the record does not link. Offline, and for other registries, the detail
says the times were not checked.

Tags map to versions as `<name>-1.2.3` or `<name>@1.2.3` first, and as bare `1.2.3`, `v1.2.3`
only when the repository is named for the package: a monorepo's `v1.2.3` is the product's
release, not each package's version. A record whose range starts at a release that already
holds the linked commit links another advisory's fix, and is `unverified`. Pre-releases never
move a bound, and `last_affected` bounds are not checked.

`--out` writes each corrected record as OSV JSON with the upstream id, so it drops into
`[settings.advisories] dir`. The record carries its evidence (repository, commits, tags) under
`database_specific.fleetreach_correction` with `status: unreviewed`: read it before you put it
in the overlay, and send the ones that hold up to the upstream database. Clones are cached and
refreshed once a day; `--offline` uses only what is cloned.

## Measure the sources: `db crosscheck`

`db crosscheck` prints, as JSON, what the CVE and CSAF indexes add to or contradict in the OSV
data: CVEs whose CNA data maps to a package OSV has no record for, CNA fixed versions that
disagree with OSV's, how often the CVE was published before the first OSV record, live OSV
records aliasing rejected CVEs, OSV records with no severity whose CVE has a CVSS vector, and,
for Red Hat, how many of OSV's fixes the CSAF data confirms exactly and how many unfixed
statuses it adds. Each kind keeps a few examples (`--limit`) for checking against the source.
