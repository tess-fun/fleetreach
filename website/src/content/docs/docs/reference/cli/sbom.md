---
title: fleetreach sbom
description: "fleetreach sbom: Write a CycloneDX 1.7 or SPDX 2.3 SBOM per repo from the same sources `scan` reads. Every flag, from the binary's help."
sidebar:
  order: 6
---

Write a CycloneDX 1.7 or SPDX 2.3 SBOM per repo from the same sources `scan` reads

```text
Write a CycloneDX 1.7 or SPDX 2.3 SBOM per repo from the same sources `scan` reads

Usage: fleetreach sbom [OPTIONS] --out-dir <OUT_DIR>

Options:
  -c, --config <CONFIG>
          fleet.toml naming the repos
          
          [default: ./fleet.toml]

  -o, --out-dir <OUT_DIR>
          Directory to write `<repo-id>.cdx.json` (or `.cdx.xml`, `.spdx.json`) files into (created if missing)

  -f, --format <FORMAT>
          SBOM format

          Possible values:
          - cyclonedx:     CycloneDX JSON, 1.7 unless `--cyclonedx-version` says otherwise
          - cyclonedx-xml: CycloneDX XML, the same content as the JSON
          - spdx:          SPDX 2.3 JSON
          
          [default: cyclonedx]

      --cyclonedx-version <CYCLONEDX_VERSION>
          CycloneDX spec version to declare
          
          [default: 1.7]
          [possible values: 1.6, 1.7]

      --report <REPORT>
          Embed this saved scan's findings (`fleetreach scan -f json > report.json`)

      --sync
          List `[[source]]` entries afresh and clone or refresh their checkouts first

  -q, --quiet
          no progress output

      --fetch-licenses
          Look up licenses no local source knows on deps.dev. Sends each such package's ecosystem, name and version to deps.dev (Google); answers are cached locally

      --maven-fetch
          resolve pom.xml with POMs fetched when they are not in ~/.m2, from the mirror of Maven Central that settings.xml names, else Maven Central (sends each artifact's coordinates there); without it, only local repositories are used

      --maven-settings <FILE>
          the Maven settings.xml whose mirror --maven-fetch uses (default: ~/.m2/settings.xml when present)

  -h, --help
          Print help (see a summary with '-h')
```
