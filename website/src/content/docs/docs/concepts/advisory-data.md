---
title: Advisory data
description: Where fleetreach's vulnerability data comes from (RustSec, osv.dev exports, vuln.go.dev, CVE 5.x, Red Hat and SUSE CSAF, CISA KEV, FIRST EPSS, Vulnrichment, NVD, your own overlay), how it is cached, and how to pin or mirror it.
sidebar:
  order: 4
---

fleetreach is not an advisory database. It reads audited structured sources and never
scrapes web pages.

| Data | Source | Used for |
|------|--------|----------|
| Rust advisories | [RustSec advisory-db](https://github.com/rustsec/advisory-db) | Cargo findings, warnings, yanks |
| Everything else | [osv.dev](https://osv.dev) per-ecosystem exports (`all.zip`) | npm, PyPI, Go, Maven and the rest |
| Go (with govulncheck) | [vuln.go.dev](https://vuln.go.dev) | call-level Go findings |
| Exploitation | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `--enrich`, SSVC, `--fail-on-kev` |
| Exploit probability | [FIRST EPSS](https://www.first.org/epss/) | `--enrich`, ranking, `--min-epss` |
| CISA's SSVC inputs | [Vulnrichment](https://github.com/cisagov/vulnrichment) | SSVC Exploitation and Automatable |
| Missing severities | [NVD](https://nvd.nist.gov) | CVSS when the advisory has none |
| CNA data and ADP enrichment | [CVE 5.x records](https://github.com/CVEProject/cvelistV5) | `db quality`, `db crosscheck` |
| Vendor statuses | [Red Hat CSAF VEX](https://security.access.redhat.com/data/csaf/v2/vex/), [SUSE CSAF VEX](https://ftp.suse.com/pub/projects/security/csaf-vex/) | `db crosscheck`; RHEL and SUSE image statuses |
| Your corrections | OSV files in `[settings.advisories] dir` | layered over every OSV export |
| Licenses | lockfiles and local package caches, else deps.dev with `licenses --fetch` | `fleetreach licenses`, SBOMs |

**Caching.** osv.dev exports live in `~/.cache/fleetreach/osv/` and are re-checked every 6
hours in network builds. `fleetreach db sync` fetches them ahead of time and `db status`
shows their age. `--max-db-age 7d` refuses stale data.

**Pinning.** `--db <path> --db-rev <commit>` pins RustSec to one commit; a copied
`--osv-dir` pins the rest. The report's `provenance` records what was used.

**Withdrawn advisories** are skipped, and an advisory published under several ids (a
`PYSEC-` and a `GHSA-`) counts once.

**Corrections and quality.** Your own OSV records replace, add to or retract upstream
records, and `db quality` reports data problems instead of hiding them. See
[Correct and extend advisory data](/fleetreach/docs/guides/correct-and-extend-advisory-data/).

**Offline.** Every source can be a file. See
[Run offline or air-gapped](/fleetreach/docs/guides/run-offline-or-air-gapped/).
