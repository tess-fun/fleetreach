---
title: Trivy and Grype
description: Share fleetreach's OpenVEX statements with Trivy and Grype so findings proven not to affect you are quiet in image scans too, and scan fleetreach SBOMs with either.
sidebar:
  order: 4
---

Trivy and Grype scan container images; fleetreach scans the source repos the images are
built from. They meet in two files.

**OpenVEX.** fleetreach writes `not_affected` statements for findings it can prove do not
apply (an unreachable function, a dependency never compiled) and for reviewed exceptions.
Both scanners read OpenVEX:

```sh
fleetreach scan -f vex --vex-author security@acme.example > fleet.vex.json
trivy image --vex fleet.vex.json ghcr.io/acme/payments-api:1.4.2
grype ghcr.io/acme/payments-api:1.4.2 --vex fleet.vex.json
```

**SBOMs.** `fleetreach sbom` writes CycloneDX (or SPDX), which both scanners accept as input:

```sh
fleetreach sbom -c fleet.toml -o boms/
trivy sbom boms/payments-api.cdx.json
grype sbom:boms/payments-api.cdx.json
```

See [Suppress with OpenVEX](/fleetreach/docs/guides/suppress-with-openvex/) and
[fleetreach vs Trivy and Grype](/fleetreach/compare/trivy-and-grype/).
