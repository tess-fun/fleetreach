---
title: Gate pull requests
description: Fail a pull request on what it adds, not on the backlog it inherited. fleetreach compares the change with its base, attributes each new finding to the lines that brought it in, and flags risky new dependencies before they merge.
sidebar:
  order: 4
---

**The problem.** A gate that fails on every known vulnerability fails every pull request
in a repo with old debt, so people learn to ignore it. A gate that fails on nothing lets a
new vulnerable dependency, or a typosquat, merge on a Friday.

**With fleetreach**, the gate looks at what the change itself does.

## Fail on new findings only

Scan the base and the head, then compare. Only what is new counts:

<!-- run: fleetreach diff before.json report.json | head -n 12 -->
```console
$ fleetreach diff before.json report.json | head -n 12
29 new, 12 fixed, 183 still open.

New (29):

┌──────────┬─────────────────────┬────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Severity ┆ Advisory            ┆ Repos  ┆ Title                                                                                                                                         │
╞══════════╪═════════════════════╪════════╪═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╡
│ critical ┆ GHSA-7rjr-3q55-vv33 ┆ 1 (+1) ┆ Incomplete fix for Apache Log4j vulnerability                                                                                                 │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ critical ┆ GHSA-jfh8-c2jp-5v3q ┆ 1 (+1) ┆ Remote code injection in Log4j                                                                                                                │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ high     ┆ GHSA-57j2-w4cx-62h2 ┆ 1 (+1) ┆ Deeply nested json in jackson-databind                                                                                                        │
```
<!-- /run -->

```sh
fleetreach diff base.json head.json --base origin/main --fail-on high
```

With `--base`, each new finding is traced to the lockfile and manifest lines changed since
the merge base, and labelled `introduced`, `existing` or `unknown`. A finding the change did
not bring in never fails it. Dev-only packages have their own floor (`--fail-on-dev`).

## Catch risky dependencies before they have an advisory

Malware and typosquats are found before any CVE exists. `--signals` flags install scripts,
git and URL dependencies, tag-pinned GitHub Actions and names close to popular packages:

<!-- run: fleetreach scan --signals | tail -n 7 -->
```console
$ fleetreach scan --signals | tail -n 7
┌─────────┬───────────────────────────────┬───────────────────────────────────────────────────────┐
│ Kind    ┆ Advisory                      ┆ Locations                                             │
╞═════════╪═══════════════════════════════╪═══════════════════════════════════════════════════════╡
│ unsound ┆ RUSTSEC-2023-0072             ┆ payments-api/openssl@0.10.38 → 0.10.60 (direct)       │
├╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ notice  ┆ fleetreach:mutable-action-ref ┆ checkout-web/tj-actions/changed-files@44.0.0 (direct) │
└─────────┴───────────────────────────────┴───────────────────────────────────────────────────────┘
```
<!-- /run -->

`--release-age 72h` lists versions published in the last few days, `--health` flags
deprecated, yanked and abandoned packages, and `--capabilities` reports what an npm or PyPI
version can do that its previous release could not (network, shell, native code).

## Wire it in

```yaml
- uses: tess-fun/fleetreach@v1
  with:
    args: "--enrich --fail-on-kev"
```

Findings appear as SARIF annotations on the changed lines. The full workflow, with the base
checkout, is in [CI recipes](/fleetreach/examples/ci-recipes/).

See [Gate on what ships](/fleetreach/docs/guides/gate-on-what-ships/),
[Track drift between scans](/fleetreach/docs/guides/track-drift-between-scans/) and
[Detect supply-chain signals](/fleetreach/docs/guides/detect-supply-chain-signals/).
