---
title: Exit codes
description: "fleetreach's exit codes, the CI contract: 0 clean, 1 findings tripped the gate, 2 something could not be read or the run failed."
sidebar:
  order: 2
---

| Code | `scan` | Meaning |
|------|--------|---------|
| `0` | every repo read, nothing tripped the gate | safe to pass |
| `1` | a finding (or, with `--fail-on-warnings`, a warning) tripped the gate | fix or ignore |
| `2` | a repo, source or database could not be read, or the run failed | never a pass |

`2` wins over `1`: a run with findings and an unreadable repo exits 2, so a partial scan is
never mistaken for a complete one.

| Command | `1` | `2` |
|---------|-----|-----|
| `diff` | a new finding trips the gate | a report could not be read |
| `licenses` | a license is denied | a source could not be read |
| `history sla` | a finding is past its deadline | no `[settings.sla]` |
| `vex check` | the document has drifted | |
| `sbom` | | a source could not be fully read (its SBOM is still written, marked incomplete) |
| `--why` | | the package is in no repo |

`--exit-zero` on `diff` makes it report only.
