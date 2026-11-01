---
title: Dependency-Track
description: Feed OWASP Dependency-Track with a CycloneDX SBOM for every repo in the fleet, and use fleetreach SBOMs for builds it cannot read.
sidebar:
  order: 3
---

[OWASP Dependency-Track](https://dependencytrack.org) is a server that tracks components
across a portfolio from SBOMs. fleetreach writes those SBOMs for the whole fleet in one run,
from the lockfiles, without building anything:

```sh
fleetreach sbom -c fleet.toml -o boms/
for bom in boms/*.cdx.json; do
  name=$(basename "$bom" .cdx.json)
  curl -sf -X POST "$DT_URL/api/v1/bom" -H "X-Api-Key: $DT_API_KEY" \
    -F "projectName=$name" -F autoCreate=true -F "bom=@$bom"
done
```

A repo that could not be fully read still gets its SBOM, marked incomplete, and the run exits
2, so a partial inventory is never uploaded as complete without you knowing.

## The other way round

Where a build is opaque to fleetreach (Gradle without locking, Bazel) but writes a CycloneDX
or SPDX SBOM, point the repo at it with `sbom = "build/reports/bom.json"` and fleetreach
scans the SBOM instead. See [Generate SBOMs](/fleetreach/docs/guides/generate-sboms/).

## Which to use

Dependency-Track is a platform you run, with a UI and a database. fleetreach is a CLI that
answers fleet questions from files: which fix clears the most repos, why a package is there,
what is new since the last run. Many teams use both: fleetreach in CI, its SBOMs in
Dependency-Track. See [fleetreach vs Dependency-Track](/fleetreach/compare/dependency-track/).
