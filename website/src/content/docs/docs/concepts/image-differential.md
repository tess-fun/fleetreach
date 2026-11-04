---
title: Image differential
description: "fleetreach against Trivy and Grype on 217 public images: every difference in findings classified, and the bugs the comparison found."
sidebar:
  order: 7
---

fleetreach, Trivy 0.73.0 and Grype v0.121.1 scanned the same 217 public images, pinned by
digest, on 3 November 2026, each with that day's data. All three read the same layers: Trivy
and Grype ran on the OCI layouts fleetreach had pulled. Findings were reduced to rows of
package, version and vulnerability, with any id of a record standing for the record.

The images cover 18 distribution families: Debian (89), Ubuntu (35), Alpine (31), Red Hat UBI
(11), Oracle Linux (10), Wolfi and Chainguard (6), AlmaLinux (5), Rocky Linux (4), SUSE BCI (4),
Fedora, CentOS, Photon OS and openSUSE Leap (3 each), Amazon Linux and Azure Linux (2 each),
Tumbleweed, CBL-Mariner, and 4 with no OS at all.

| | Rows |
|---|---:|
| fleetreach | 337,686 |
| Trivy | 348,708 |
| Grype | 177,303 |
| fleetreach and Trivy both report | 310,112 |
| fleetreach and Grype both report | 161,427 |

**No difference is unexplained.** A script gives every differing row a reason from upstream
data: the OSV record, the Debian tracker, the tool's own match, the image's package database.
A row no rule claims is printed as unexplained, and there are none. The script, the pinned
images and the counts are in
[`docs/differential`](https://github.com/tess-fun/fleetreach/tree/main/docs/differential).

## What the other tools report and fleetreach does not

| Reason | Trivy | Grype |
|---|---:|---:|
| Debian 10 and 11 left the tracker and the CVE is not in their frozen export: a [coverage gap](#known-limits) is reported | 33,804 | 9,733 |
| Debian placeholder ids (`TEMP-`) and advisories with no CVE, absent from the OSV export | 2,770 | |
| Debian testing, which has no release to match | | 1,863 |
| Grype's binary classifiers guess a version from file contents | | 1,930 |
| Grype matched NVD CPEs, which no distribution record backs | | 875 |
| Debian 11's frozen export marks the record withdrawn; the tools keep the CVE | 400 | 355 |
| Red Hat fixed it at or below the installed build; Trivy keeps the open status | 866 | |
| Grype compares Oracle's FIPS builds (epoch 10) with ordinary ones | | 315 |
| The file belongs to an OS package, whose advisories cover it | | 308 |
| No OSV record for this release or package: the tool's own feed | 279 | 87 |
| Grype applies Red Hat's fixes to Rocky, which ships its own | | 134 |
| Java archive with no coordinates: a coverage gap is reported | 70 | 43 |
| Ubuntu 25.04 left OSV: a coverage gap is reported | 1 | 47 |
| OSV's lower bound or range leaves the installed version out | 28 | 29 |
| Main module built as `(devel)`: the tool takes a version from outside the build info | 8 | 19 |
| Vendored copy Trivy reads from an embedded SBOM | 16 | |
| Rows of other kinds: Perl modules, a resolved Debian entry, a Grype mock record, a private project matched to an npm malware record, a SUSE advisory with no record | 21 | 31 |
| **Total** | **38,263** | **15,769** |

## What fleetreach reports and the other tools do not

| Reason | Not in Trivy | Not in Grype |
|---|---:|---:|
| Grype's default ignore rule drops kernel headers | | 164,115 |
| Ubuntu's open and Ubuntu Pro records: Grype lists them, Trivy leaves them out | 10,645 | |
| Red Hat's open statuses for its rebuilds and itself: one tool lists them | 4,344 | 212 |
| OSV's Debian record has no entry in the tracker, which both tools read | 3,731 | 3,598 |
| Go vulnerability database or OSV record Grype's data lacks; Trivy has it | | 2,326 |
| A package only fleetreach reads: a lockfile or module list inside the image | 2,259 | 2,259 |
| A fix named for the source package; the tool reads fixes per binary | 1,048 | 70 |
| SUSE's per-CVE statuses, which the tool does not read here | 985 | 671 |
| Debian status undetermined: fleetreach keeps it open, both tools drop it | 527 | 492 |
| Red Hat's open status names no module stream: kept, fail-closed | 434 | 278 |
| OSV's Debian record is open where the tracker resolved it (`unimportant`) | 294 | 259 |
| Ubuntu notices with no CVE, not listed under that id | 217 | 217 |
| Third-party `.deb` packages Debian also names (nginx.org, MariaDB) | 208 | |
| Records only OSV carries for this package | 150 | 150 |
| Chainguard's open statuses: both tools read fixes only | 121 | 120 |
| Open in a retired Debian release's frozen export, which may be out of date | 765 | 163 |
| Debian ids or statuses Grype's data leaves out | | 166 |
| Grype has no Julia data | | 182 |
| The distribution's OSV record, with the tool's feed lacking it | 228 | 74 |
| An openSUSE GA-media record with a wrong fix version (an upstream data error) | 16 | 16 |
| The other tool reports the package row; this tool's data lacks it | 58 | 9 |
| **Total** | **26,030** | **175,377** |

## Where the status differs

Both tools and fleetreach report the row, and one names a fix where the other does not: 213
rows against Trivy and 1,338 against Grype. Most are fixes Grype does not count: Ubuntu Pro
(907), Red Hat's Extended Life Support (206), and Debian LTS (57 against Grype, 46 against
Trivy). On 52 rows against Trivy and 28 against Grype, Debian 11's frozen export says open and
the tool knows a later fix. On 80 rows the fix is in the finding's title but stays out of its `patched` range,
because the version cannot be rendered in the report's SemVer form without reading the
installed build as fixed (Oracle's `2.56.1-9.0.5.el7_9`), or it is in a line the image cannot
reach. A `GO-` record with no fix can also stand for a GitHub twin that names one (31 rows).

## Bugs the comparison found

All fixed before these numbers were taken:

- **Go binaries were not read at all.** Trivy-only Go rows fell from 4,803 to 8. Modules and
  the standard library now come from the build info, with Trivy's rule for a main module's
  version stamped by `-ldflags`.
- **Files of third-party OS packages were skipped.** A file owned by `mongodb-database-tools`
  or `docker-ce-cli` is not covered by any distribution's advisories. Files are now skipped only
  when a distribution's records know the owning package.
- **GitHub records in the Go export were dropped**, and `+incompatible` versions missed a
  `last_affected` bound.
- **Standalone `package.json`, Composer's `installed.json`, .NET's `.deps.json` and bare
  `.egg-info` files were not read.**
- **Ubuntu Pro's records were read only for `+esm` images.** Canonical stops a release's records
  at the end of standard support and never publishes universe outside Pro, so Pro now speaks
  wherever the release says nothing. Grype-only Ubuntu rows fell from 2,575 to 98.
- **CentOS 6 had no `os-release`** and was not matched (1,726 rows to none). CentOS now stays
  affected by a Red Hat fix made after it stopped, where before the fix hid the CVE.
- **Red Hat's Extended Life Support records for RHEL 6 and 7 were not read**, and RHEL 10's
  records, which go by minor release with no repository, were a false coverage gap.
- **A Red Hat record naming only the source package** (`vim`) was not applied to its binaries
  (`vim-minimal`).
- **A Ubuntu notice joined the CVEs it covers into one finding**, with the first one's status:
  14 expat CVEs read as open, though some had fixes.
- **Alpine ranges with a lower bound above their fix** hid an open CVE.
- **A finding's title could name another release** when two releases shared an advisory id, and
  **one GitHub record across two ecosystems** was merged into one finding.
- **Reading standalone `package.json` created a false positive of its own**, which the comparison
  caught: a private Nextcloud app with the name of a malicious npm package. Grype still reports
  these. `"private": true` now keeps a project off the registry.

## Known limits

The reasons above are not all equally strong. A row one tool reports and fleetreach does not has
been traced to evidence. A row only fleetreach reports has a record behind it by construction,
and its classes were checked by sample, not row by row. Some of those records are stale
upstream: 294 Debian rows are open in OSV and resolved in the tracker, 763 rows open in Debian
11's frozen export are listed by neither tool, and 16 Tumbleweed rows come from a wrong fix
version.

- **Debian 10 and 11** are the largest class. They left the security tracker, and osv.dev's
  current export holds few of their CVEs. fleetreach also reads osv.dev's frozen export of each
  release, which stopped in October 2024, wherever the current export says nothing about a CVE.
  That recovered 5,691 of Trivy's rows and 3,261 of Grype's. What remains is mostly CVEs from
  2025 on, which no export osv.dev publishes has for these releases. Debian 10's frozen export
  holds almost no open CVEs at all. Each such image carries a coverage gap saying so.
- **Rust binaries** are read when built with `cargo auditable`, and a coverage gap reports those
  that are not. None of the 217 images holds one with a crate list, so this was checked apart,
  on real binaries. **Perl modules** are not read.
- **Go main modules built as `(devel)`** with no version in the build info, such as Vault and
  Grafana, are matched by their dependencies only.
- **Debian testing** has no release to match, and **Azure Linux distroless** images have no
  package database. Both say so in a coverage gap.
- **Jars with no metadata** stay a gap: fleetreach has no checksum index of Maven Central.
