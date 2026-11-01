---
title: Read the report
description: The views fleetreach prints from one scan (table, impact, blast, packages, fix-first, remediation, ssvc, owners) and the JSON, SARIF and OpenVEX formats.
sidebar:
  label: Reading the report
---

One scan, many answers. `-f <view>` reshapes the same findings for a different question,
and the machine formats carry everything for other tools.

| View | Answers |
|------|---------|
| `table` (default) | What is vulnerable, where, and what fixes it? |
| `impact` | Which advisory hits the most repos? |
| `blast` | Is that reach direct (fix the manifest) or transitive (needs an upstream bump)? |
| `packages` | Which dependency is the biggest liability across the fleet? |
| `fix-first` | What do I patch first? KEV, then severity, then reach. |
| `remediation` | What exactly do I bump, in what order, and how risky is the bump? |
| `ssvc` | Act now or schedule it? Needs [repo context](/fleetreach/docs/guides/prioritise-with-kev-epss-and-ssvc/). |
| `owners` | The fix queue split by team. |
| `json`, `sarif`, `vex`, `packages-json`, `remediation-json` | Machine formats. See [Output formats](/fleetreach/docs/reference/output-formats/). |

## impact: which advisory hits the most repos?

<!-- run: fleetreach scan -f impact | head -n 9 -->
```console
$ fleetreach scan -f impact | head -n 9
┌───────┬───────────────┬─────────────────────┬───────────────────────────────┬──────────────────────────────────────────┐
│ Repos ┆ Severity      ┆ Advisory            ┆ Affected                      ┆ Title                                    │
╞═══════╪═══════════════╪═════════════════════╪═══════════════════════════════╪══════════════════════════════════════════╡
│ 2     ┆ high          ┆ GHSA-2xpw-w6gg-jr37 ┆ data-pipeline, ml-service     ┆ urllib3 streaming API improperly handle… │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ high          ┆ GHSA-35jh-r3h4-6jhm ┆ admin-dashboard, checkout-web ┆ Command Injection in lodash              │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ high 7.5      ┆ GHSA-38jv-5279-wg99 ┆ data-pipeline, ml-service     ┆ Decompression-bomb safeguards bypassed … │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

Advisories are ranked by the number of repos they reach, so the one fix that clears two
repos sorts above a critical in one. Add `--enrich` and repo context to weight each repo by
its SSVC outcome instead (the `Weighted` column).

## blast: direct or transitive?

<!-- run: fleetreach scan -f blast | head -n 9 -->
```console
$ fleetreach scan -f blast | head -n 9
┌───────┬────────┬────────────┬──────────┬───────────────┬─────────────────────┬──────────────────────────────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Fix      ┆ Severity      ┆ Advisory            ┆ Title                                    │
╞═══════╪════════╪════════════╪══════════╪═══════════════╪═════════════════════╪══════════════════════════════════════════╡
│ 2     ┆ 2      ┆ 0          ┆ manifest ┆ high          ┆ GHSA-2xpw-w6gg-jr37 ┆ urllib3 streaming API improperly handle… │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ manifest ┆ high          ┆ GHSA-35jh-r3h4-6jhm ┆ Command Injection in lodash              │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ manifest ┆ high 7.5      ┆ GHSA-38jv-5279-wg99 ┆ Decompression-bomb safeguards bypassed … │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

`manifest` means every affected repo depends on the package directly, so editing their
manifests fixes it. `upstream` means it only arrives through other packages, so the fix is
a bump of the parent (or an override). `mixed` is both.

## packages: the biggest liability

<!-- run: fleetreach scan -f packages | head -n 9 -->
```console
$ fleetreach scan -f packages | head -n 9
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬─────────────────────────────────────────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package                                             │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪═════════════════════════════════════════════════════╡
│ 2     ┆ 2      ┆ 0          ┆ 25         ┆ high     ┆ manifest ┆ -       ┆ axios (npm)                                         │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 10         ┆ high     ┆ manifest ┆ -       ┆ urllib3 (pypi)                                      │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 6          ┆ high     ┆ manifest ┆ -       ┆ lodash (npm)                                        │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

One row per package: how many repos carry it, how many advisories it has, and how it is
fixed. One axios bump clears 25 advisories in two repos.

## remediation: the fix queue

<!-- run: fleetreach scan -f remediation --enrich | head -n 9 -->
```console
$ fleetreach scan -f remediation --enrich | head -n 9
┌────┬──────────────┬───────────────────────────────────────────────────────────────────┬───────────────┬─────────────────────┬───────┬─────────┬───────────────┬────────────────────────┐
│ #  ┆ SSVC         ┆ Action                                                            ┆ Severity      ┆ Resolves            ┆ Repos ┆ Reach   ┆ Exploit       ┆ Bump risk              │
╞════╪══════════════╪═══════════════════════════════════════════════════════════════════╪═══════════════╪═════════════════════╪═══════╪═════════╪═══════════════╪════════════════════════╡
│ 1  ┆ immediate    ┆ bump org.apache.logging.log4j:log4j-core 2.14.1 → 2.25.4          ┆ critical 10.0 ┆ 8 advisories        ┆ 1     ┆ unknown ┆ KEV EPSS 100% ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2  ┆ out-of-cycle ┆ bump tj-actions/changed-files 44.0.0 → 46.0.1 (breaking)          ┆ high 8.6      ┆ GHSA-mrrh-fwg8-r2c3 ┆ 1     ┆ unknown ┆ KEV EPSS 72%  ┆ high                   │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 3  ┆ out-of-cycle ┆ bump smallvec 1.6.0 → 1.6.1                                       ┆ critical 9.8  ┆ RUSTSEC-2021-0003   ┆ 1     ┆ unknown ┆ EPSS 2%       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

Each row is one bump, batched across every repo and advisory it clears. The target is the
smallest version that clears every advisory, never one a later advisory breaks again. A
breaking bump is marked, and a repo on an older line gets that line's own fix as an
alternative. `Bump risk` comes from your fleet: how many repos already run the target. See
[Safe versions and batch targets](/fleetreach/docs/concepts/safe-versions-and-batch-targets/).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | A trustworthy scan; nothing met the `--fail-on` threshold. |
| `1` | A trustworthy scan; a finding met the threshold. |
| `2` | The scan could not be completed: a repo errored, data was too old, the config was bad. Never read this as clean. |
| `3` | A usage error. |

## Coverage notes

Lines starting `note:` on stderr name every source read with less than full coverage, and
the JSON report lists them under `coverage`. A partly read repo still counts as scanned,
but it is never presented as fully clean. `--require-full-coverage` turns any of them into
exit 2. See [Coverage and failing closed](/fleetreach/docs/concepts/coverage-and-fail-closed/).
