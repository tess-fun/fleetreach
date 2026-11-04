---
title: Output formats
description: "Every fleetreach output format and view: table, JSON, SARIF, OpenVEX, CycloneDX, SPDX, HTML and the impact, blast, packages, fix-first, remediation, SSVC and owners views."
sidebar:
  order: 3
---

`fleetreach scan -f <format>`:

| Format | For |
|--------|-----|
| `table` | people (default) |
| `json` | machines: every finding with paths, coverage and provenance; input to `diff`, `fix plan`, `sbom --report` |
| `sarif` | GitHub code scanning (SARIF 2.1.0, stable fingerprints, suppressions) |
| `vex` | OpenVEX 0.2.0 `not_affected` statements |
| `impact` | advisories ranked by repos affected |
| `blast` | impact split into direct and transitive, with a fix path |
| `packages`, `packages-json` | vulnerable packages ranked by fleet reach |
| `fix-first` | KEV first, then severity, then reach |
| `remediation`, `remediation-json` | the fix queue: batched bumps with bump risk |
| `ssvc` | findings grouped by SSVC decision |
| `owners` | the fix queue split by owner |

Other commands:

| Command | Writes |
|---------|--------|
| `sbom -f cyclonedx` | CycloneDX 1.7 JSON per repo (default); 1.6 with `--cyclonedx-version 1.6` |
| `sbom -f cyclonedx-xml` | the same in XML |
| `sbom -f spdx` | SPDX 2.3 JSON per repo |
| `report html` | one self-contained HTML page |
| `notify -f generic` | `fleetreach-notify/1` JSON |
| `notify -f slack` | Slack Block Kit |
| `fix plan` | a JSON plan |

The JSON report's fields only grow within a major version. See
[Reading the report](/fleetreach/docs/getting-started/reading-the-report/) for the views with
real output.
