---
title: One-liners
description: Short fleetreach commands for everyday questions, from which fix clears the most repos to what changed since yesterday, each with what it answers.
sidebar:
  order: 1
---

| Question | Command |
|----------|---------|
| What is vulnerable across the fleet? | `fleetreach scan` |
| Which fix clears the most repos? | `fleetreach scan -f packages` |
| What do I fix first, given exploitation? | `fleetreach scan --enrich -f fix-first` |
| What are the exact bumps to make? | `fleetreach scan -f remediation` |
| Which repos have this package, and why? | `fleetreach scan --why lodash` |
| Is anything on CISA's KEV list? | `fleetreach scan --enrich --fail-on-kev` |
| What act-now items does each team have? | `fleetreach scan --enrich -f owners` |
| What changed since the last saved report? | `fleetreach diff baseline.json current.json` |
| Was anything pulled in during a worm outbreak? | `fleetreach scan --release-age 72h` |
| Any install scripts, git deps or typosquats? | `fleetreach scan --signals` |
| Which licenses do we ship? | `fleetreach licenses` |
| SBOMs for every repo | `fleetreach sbom -o boms/` |
| Is the advisory data fresh? | `fleetreach db status` |
| Which repos would a source discover? | `fleetreach fleet list` |
| Who is past their deadline? | `fleetreach history sla --history-dir history/` |
| How fast do we fix criticals? | `fleetreach history mttr --history-dir history/` |

## Real output

<!-- run: fleetreach scan -f packages | head -n 12 -->
```console
$ fleetreach scan -f packages | head -n 12
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬─────────────────────────────────────────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package                                             │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪═════════════════════════════════════════════════════╡
│ 2     ┆ 2      ┆ 0          ┆ 25         ┆ high     ┆ manifest ┆ -       ┆ axios (npm)                                         │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 10         ┆ high     ┆ manifest ┆ -       ┆ urllib3 (pypi)                                      │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 6          ┆ high     ┆ manifest ┆ -       ┆ lodash (npm)                                        │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 1          ┆ high     ┆ manifest ┆ -       ┆ regex                                               │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 4          ┆ medium   ┆ manifest ┆ -       ┆ requests (pypi)                                     │
```
<!-- /run -->
