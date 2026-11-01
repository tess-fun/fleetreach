---
title: Advisory data
description: Where fleetreach's vulnerability data comes from (RustSec, osv.dev exports, vuln.go.dev, CISA KEV, FIRST EPSS, Vulnrichment, NVD), how it is cached, and how to pin or mirror it.
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
| Licenses | lockfiles and local package caches, else deps.dev with `licenses --fetch` | `fleetreach licenses`, SBOMs |

**Caching.** osv.dev exports live in `~/.cache/fleetreach/osv/` and are re-checked every 6
hours in network builds. `fleetreach db sync` fetches them ahead of time and `db status`
shows their age. `--max-db-age 7d` refuses stale data.

**Pinning.** `--db <path> --db-rev <commit>` pins RustSec to one commit; a copied
`--osv-dir` pins the rest. The report's `provenance` records what was used.

**Withdrawn advisories** are skipped, and an advisory published under several ids (a
`PYSEC-` and a `GHSA-`) counts once.

**Offline.** Every source can be a file. See
[Run offline or air-gapped](/fleetreach/docs/guides/run-offline-or-air-gapped/).
