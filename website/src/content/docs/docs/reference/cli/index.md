---
title: CLI reference
description: Every fleetreach command and flag, generated from the binary's own help text.
sidebar:
  order: 0
---

Generated from `fleetreach --help`; each command's page has its full help.

| Command | What it does |
|---------|--------------|
| [`scan`](/fleetreach/docs/reference/cli/scan/) | Scan the fleet for advisories |
| [`diff`](/fleetreach/docs/reference/cli/diff/) | Compare two saved JSON reports: new vs. fixed vs. still-open findings |
| [`vex`](/fleetreach/docs/reference/cli/vex/) | Operate on OpenVEX documents (drift gate, witness verification) |
| [`db`](/fleetreach/docs/reference/cli/db/) | Manage the advisory data: osv.dev exports, CVE 5.x and vendor CSAF indexes, quality |
| [`fleet`](/fleetreach/docs/reference/cli/fleet/) | Discover and check out the repos named by `[[source]]` entries |
| [`sbom`](/fleetreach/docs/reference/cli/sbom/) | Write a CycloneDX 1.6 or SPDX 2.3 SBOM per repo from the same sources `scan` reads |
| [`licenses`](/fleetreach/docs/reference/cli/licenses/) | License inventory and policy violations across the fleet |
| [`fix`](/fleetreach/docs/reference/cli/fix/) | Plan and apply verified dependency fixes from the remediation queue |
| [`history`](/fleetreach/docs/reference/cli/history/) | Trends, age, SLA breaches and time to fix from `scan --history-dir` snapshots |
| [`notify`](/fleetreach/docs/reference/cli/notify/) | Send what the newest history run changed, and SLA breaches, to a webhook or issues |
| [`report`](/fleetreach/docs/reference/cli/report/) | Publishable reports from the scan history |

```text
Fleet-native dependency security audit across 12 ecosystems

Usage: fleetreach <COMMAND>

Commands:
  scan      Scan the fleet for advisories
  diff      Compare two saved JSON reports: new vs. fixed vs. still-open findings
  vex       Operate on OpenVEX documents (drift gate, witness verification)
  db        Manage the advisory data: osv.dev exports, CVE 5.x and vendor CSAF indexes, quality
  fleet     Discover and check out the repos named by `[[source]]` entries
  sbom      Write a CycloneDX 1.6 or SPDX 2.3 SBOM per repo from the same sources `scan` reads
  licenses  License inventory and policy violations across the fleet
  fix       Plan and apply verified dependency fixes from the remediation queue
  history   Trends, age, SLA breaches and time to fix from `scan --history-dir` snapshots
  notify    Send what the newest history run changed, and SLA breaches, to a webhook or issues
  report    Publishable reports from the scan history
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```
