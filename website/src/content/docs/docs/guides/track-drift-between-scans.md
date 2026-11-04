---
title: Track drift between scans
description: Compare two saved fleetreach reports to see new, fixed and still-open findings, and fail a pull request only on what it introduced.
sidebar:
  order: 5
---

`fleetreach diff <baseline.json> <current.json>` splits findings into **new**, **fixed**
and **still open**. It answers "did this change make the fleet better or worse?", and gates
CI on new findings only.

```sh
fleetreach scan -f json > current.json
fleetreach diff baseline.json current.json --fail-on high
```

`diff` reads two JSON files and nothing else: no scanning, no advisory data, no network.
Its exit code mirrors `scan`: `1` when a new finding meets `--fail-on`. `--exit-zero` makes
it report-only.

On the demo fleet, between a scan on 1 September and one on 15 October: billing moved to a
newer rack (fixed) and partner-api joined the fleet (new).

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

## Gate a pull request on what it brought in

With `--base`, `diff` asks git which new findings the change is responsible for. Run it in
the checkout, with the history back to the merge base (`fetch-depth: 0` on GitHub Actions):

```sh
fleetreach diff baseline.json current.json --base origin/main --fail-on high
```

```text
Brought in by this change (1):
  high     GHSA-r6q2-hw4h-h46w tar@6.2.1 at package-lock.json:4120 from package.json:18

Already here before this change, not gating (1):
  critical GHSA-3xgq-45jj-v275 cross-spawn@7.0.3 at package-lock.json:1893
```

New findings are compared per occurrence, so an advisory already open in another repo still
counts when this repo gains it. Each one then lands in one of three groups:

| Group | Meaning | Gates |
|-------|---------|-------|
| Brought in | the package at that version is in a file now, and not in that file at the merge base; `from` is the changed manifest line that names its direct dependency, when there is one | yes |
| Already here | every file holding it held it at the merge base, so the advisory is what changed | no |
| Not placed | not found in the checkout: another repo of the report, a Maven or Gradle transitive package with no lockfile, a pin by commit, or a file `diff` cannot read | yes |

`--checkout <dir>` names the checkout when it is not the current directory, and
`--repo <id>` names its repo id when the reports cover several. `--format json` adds an
`attribution` list. Only dependency files are read: a change that removes an ignore or
touches the fleet config brings a finding back without any changed line, so it shows as
already here.

## Keep a baseline

The usual pattern: the default branch saves its report as an artifact (or commits it), and
each pull request diffs against it.

```yaml title=".github/workflows/audit.yml (excerpt)"
- run: fleetreach scan -f json > current.json || true
- run: fleetreach diff baseline/report.json current.json --fail-on high
```

For a fleet-wide record of every run, with trends and time to fix, use the
[scan history](/fleetreach/docs/guides/track-history-and-slas/) instead.
