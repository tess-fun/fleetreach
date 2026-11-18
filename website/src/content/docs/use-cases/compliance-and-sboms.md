---
title: Produce compliance evidence
description: CycloneDX or SPDX SBOMs for every repository with NTIA checks, license policy and NOTICE files, VEX statements and SLA history, for audits such as SOC 2, ISO 27001, PCI DSS and the EU Cyber Resilience Act.
sidebar:
  order: 6
---

**The problem.** An auditor, a customer or a regulation (the EU Cyber Resilience Act, US
federal procurement, PCI DSS) wants an SBOM per product, proof that known vulnerabilities
are handled on time, statements about the ones that do not apply, and a license review.

**With fleetreach**, all of it comes from the same files as the scan, in one run per fleet:

| Evidence | Command |
|----------|---------|
| SBOM per repo with component hashes, CycloneDX 1.7, SPDX 2.3 or SPDX 3 | `fleetreach sbom -o boms/` (`-f spdx`, `-f spdx3`) |
| NTIA minimum elements checked on each SBOM | `fleetreach sbom -o boms/ --check-ntia` |
| SBOM with known vulnerabilities and VEX analysis | `fleetreach sbom --report report.json -o boms/` |
| Statements that a finding does not apply | `fleetreach scan -f vex`, `-f csaf-vex` |
| License inventory, policy violations and NOTICE files | `fleetreach licenses` |
| Vulnerability handling over time | `fleetreach history sla`, `history mttr`, `report html` |

## SBOMs that say when they are incomplete

<!-- run: fleetreach sbom -o boms/ --check-ntia -q 2>&1 | head -n 3 -->
```console
$ fleetreach sbom -o boms/ --check-ntia -q 2>&1 | head -n 3
ntia: payments-api: missing supplier name (28 of 28 components lack it); version (1 of 28 components lack it); other unique identifiers (1 of 28 components lack it)
ntia: ledger-svc: missing supplier name (26 of 26 components lack it); version (1 of 26 components lack it); other unique identifiers (1 of 26 components lack it)
ntia: checkout-web: missing supplier name (9 of 9 components lack it); version (1 of 9 components lack it); other unique identifiers (1 of 9 components lack it)
```
<!-- /run -->

Every SBOM passes its official schema, records whether its inventory is complete, and is
byte-for-byte reproducible with `SOURCE_DATE_EPOCH`. A repo that could not be fully read
still gets its SBOM, marked incomplete, and the run exits 2: an incomplete inventory is
never presented as complete. SBOMs from other tools (CycloneDX, SPDX, GitHub's export) can
be scanned too, so a supplier's SBOM goes through the same checks.

## Licenses across the fleet

<!-- run: fleetreach licenses -->
```console
$ fleetreach licenses
┌──────────────┬──────────┬──────────┬───────┐
│ License      ┆ Category ┆ Packages ┆ Repos │
╞══════════════╪══════════╪══════════╪═══════╡
│ MIT          ┆ notice   ┆ 63       ┆ 2     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┤
│ ISC          ┆ notice   ┆ 3        ┆ 1     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┤
│ BSD-3-Clause ┆ notice   ┆ 2        ┆ 1     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┤
│ Apache-2.0   ┆ notice   ┆ 1        ┆ 1     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┤
│ (unknown)    ┆ unknown  ┆ 71       ┆ 8     │
└──────────────┴──────────┴──────────┴───────┘
```
<!-- /run -->

A policy in `fleet.toml` lists what is allowed, `--detect` reads license texts when the
metadata is missing, and copyleft conflicts are flagged.

## Time to fix, per period

<!-- run: fleetreach history mttr --history-dir history/ -->
```console
$ fleetreach history mttr --history-dir history/
┌──────────┬───────┬─────────────┬───────────────┬────────────┐
│ Group    ┆ Fixed ┆ Mean (days) ┆ Median (days) ┆ Still open │
╞══════════╪═══════╪═════════════╪═══════════════╪════════════╡
│ critical ┆ 0     ┆ -           ┆ -             ┆ 15         │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┤
│ high     ┆ 13    ┆ 44.0        ┆ 44.0          ┆ 86         │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┤
│ low      ┆ 5     ┆ 44.0        ┆ 44.0          ┆ 21         │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┤
│ medium   ┆ 12    ┆ 44.0        ┆ 44.0          ┆ 102        │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┤
│ unknown  ┆ 0     ┆ -           ┆ -             ┆ 33         │
└──────────┴───────┴─────────────┴───────────────┴────────────┘
```
<!-- /run -->

fleetreach produces evidence; it does not make you compliant. Which evidence a framework
needs is for your auditor to say.

See [Generate SBOMs](/fleetreach/docs/guides/generate-sboms/),
[Enforce a license policy](/fleetreach/docs/guides/enforce-a-license-policy/) and
[Track history and SLAs](/fleetreach/docs/guides/track-history-and-slas/).
