---
title: Accuracy and validation
description: "How fleetreach's matching is validated against independent oracles: upstream version comparators over hundreds of thousands of pairs, recall against OSV, and real repos compared with osv-scanner, mvn, go list and uv."
sidebar:
  order: 6
---

A matcher that orders versions wrongly reports clean when it is not. Every ecosystem's
comparator is a port of the ecosystem's own rules, checked against the real implementation,
and every feature is checked on real repositories against a source that shares no code with
fleetreach.

## Version comparators

| Ecosystem | Oracle | Pairs agreeing |
|-----------|--------|----------------|
| Maven | Apache Maven `ComparableVersion` | 710,000+ |
| Packagist | `composer/semver` | 185,000 |
| NuGet | `NuGet.Versioning` | 100% of the corpus |
| Julia | Julia `VersionNumber` | 100% of the corpus |
| RubyGems | `Gem::Version` (RubyGems 3.3+) | golden tests pinned |
| Debian, Ubuntu | dpkg 1.21 | 619,997 |
| Alpine, Wolfi | apk-tools 2.14 | 619,999 |
| rpm distributions | rpm 4.20 `rpm.vercmp` | 538,780 |

The differential runs found real bugs that are now fixed, for example Maven 3.9 treating
`.X` as `-X`, and Composer including `X`'s prereleases in `>=X`.

## Matching

- **npm:** 511 of 511 known-vulnerable cases found (100% recall), zero false cleans, on real
  lockfiles; 565 lockfiles against the full npm export without a failure.
- **PyPI:** 100% recall and precision on 3,000 advisories. Matching the enumerated version
  lists is required: range-only matching missed 220 of 600.
- **bun.lock:** the same 4,829 packages as osv-scanner on four large projects.
- **Maven:** on 14 real repositories, 3,555 of 3,555 resolved packages are identical to
  `mvn dependency:tree` from Maven 3.9.9, without running Maven. Module by module on 30
  more, 1,999 of 2,136 modules are identical, and the other 137 differ only by profiles that
  Maven activates by the machine's OS or CPU.
- **.NET call graph:** of 6,727 methods the .NET runtime compiled while the test apps ran,
  the static call graph missed none.

## Features checked against independent sources

Each 1.5.0 feature was run on real repos and compared with osv.dev, CISA KEV, Vulnrichment,
the CERT/CC SSVC table (row by row), `pyspdxtools`, `go list` and `uv lock --check`.
Disagreements were fixed before release, among them safe-version selection across
overlapping ranges, Go modules with several OSV entries, and SBOM timestamps.

On 217 public images, every difference from Trivy and Grype has a reason: see the
[image differential](/fleetreach/docs/concepts/image-differential/).

A scan of 13 large open-source monorepos found and fixed four bugs, including polyglot repos
where only the root ecosystem was detected. That class of bug, a silent false clean, is
what the [fail-closed design](/fleetreach/docs/concepts/coverage-and-fail-closed/) and
these checks exist to catch.
