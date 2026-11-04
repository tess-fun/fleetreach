---
title: For compliance and SBOMs
description: Produce CycloneDX or SPDX SBOMs for every repository, license policy reports, VEX statements and SLA evidence for audits such as SOC 2, ISO 27001, PCI DSS and the EU Cyber Resilience Act.
sidebar:
  order: 3
---

**The problem.** An auditor, a customer or a regulation (the EU Cyber Resilience Act, US
federal procurement, PCI DSS) wants an SBOM per product, proof that known vulnerabilities are
handled on time, and a license review.

**With fleetreach**, all of it comes from the same files, in one run per fleet:

| Evidence | Command |
|----------|---------|
| SBOM per repo with component hashes, CycloneDX 1.7 or SPDX 2.3 | `fleetreach sbom -o boms/` (`-f spdx`) |
| SBOM with known vulnerabilities and VEX analysis | `fleetreach sbom --report report.json -o boms/` |
| Vulnerability handling over time | `fleetreach history sla`, `history mttr`, `report html` |
| Statements that a finding does not apply | `fleetreach scan -f vex` |
| License inventory and policy violations | `fleetreach licenses` |

Every SBOM passes its official schema, records whether its inventory is complete, and is
reproducible with `SOURCE_DATE_EPOCH`. A repo that could not be fully read still gets its
SBOM, marked incomplete, and the run exits 2: an incomplete inventory is never presented as
complete.

fleetreach produces evidence; it does not make you compliant. Which evidence a framework
needs is for your auditor to say.

See [Generate SBOMs](/fleetreach/docs/guides/generate-sboms/),
[Enforce a license policy](/fleetreach/docs/guides/enforce-a-license-policy/) and
[Track history and SLAs](/fleetreach/docs/guides/track-history-and-slas/).
