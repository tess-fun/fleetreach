---
title: Find the fix that clears the most repos
description: Use fleetreach's impact, blast, packages and remediation views to find the dependency bumps that clear the most advisories across the most repositories.
sidebar:
  order: 1
---

Run `fleetreach scan -f packages` to rank vulnerable dependencies by how many repos they
reach, and `-f remediation` for the exact bumps in order. One bump of a shared dependency
often clears the same advisories in many repos at once; these views put those first.

## Rank dependencies by fleet reach

<!-- run: fleetreach scan -f packages | head -n 13 -->
```console
$ fleetreach scan -f packages | head -n 13
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
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

Read it top-down: `axios` carries 25 advisories in two repos, both direct dependencies, so
editing two manifests clears all of them. `time` is `mixed`: one repo depends on it
directly, the other only through `chrono`, so that repo needs a `chrono` bump instead.

## Get the bumps, batched

<!-- run: fleetreach scan -f remediation | head -n 13 -->
```console
$ fleetreach scan -f remediation | head -n 13
┌────┬───────────────────────────────────────────────────────────────────┬───────────────┬─────────────────────┬───────┬─────────┬─────────┬────────────────────────┐
│ #  ┆ Action                                                            ┆ Severity      ┆ Resolves            ┆ Repos ┆ Reach   ┆ Exploit ┆ Bump risk              │
╞════╪═══════════════════════════════════════════════════════════════════╪═══════════════╪═════════════════════╪═══════╪═════════╪═════════╪════════════════════════╡
│ 1  ┆ bump golang.org/x/crypto 0.14.0 → 0.56.0 (breaking)               ┆ critical 10.0 ┆ 22 advisories       ┆ 1     ┆ unknown ┆ -       ┆ high                   │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2  ┆ bump org.apache.logging.log4j:log4j-core 2.14.1 → 2.25.4          ┆ critical 10.0 ┆ 8 advisories        ┆ 1     ┆ unknown ┆ -       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 3  ┆ bump smallvec 1.6.0 → 1.6.1                                       ┆ critical 9.8  ┆ RUSTSEC-2021-0003   ┆ 1     ┆ unknown ┆ -       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 4  ┆ bump google.golang.org/grpc 1.58.2 → 1.83.2                       ┆ critical 9.1  ┆ 6 advisories        ┆ 1     ┆ unknown ┆ -       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 5  ┆ bump nokogiri 1.16.2 → 1.19.4                                     ┆ critical 7.8  ┆ 16 advisories       ┆ 1     ┆ unknown ┆ -       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

Every row is one change: the package, the target version and every advisory and repo it
clears. How the target is chosen:

- It is the smallest version that clears every advisory the row covers, and never one that
  a later advisory affects again.
- A semver-major jump (or a `0.x` minor) is marked `(breaking)`, and where repos sit on an
  older line, that line's own fix is offered too (`or 0.21.2 on 0.21.x`).
- `Bump risk` is `low` within the current major. For a breaking bump it counts how many of
  your repos already run the target: three or more make it `medium`.

## See what the bumps would do first

`fleetreach whatif` reads a saved report and answers "if these bumps land, what clears, what
stays open, and what is new". Nothing is edited and nothing is fetched:

<!-- run: fleetreach whatif --report report.json --top 3 -->
```console
$ fleetreach whatif --report report.json --top 3
what-if: 3 bump(s)
  maven org.apache.logging.log4j:log4j-core -> 2.25.4 (1 repo): clears 8, leaves 0, new 0
  github-actions tj-actions/changed-files -> 46.0.1 (1 repo): clears 1, leaves 0, new not checked
  cargo smallvec -> 1.6.1 (1 repo): clears 1, leaves 0, new not checked

open findings  critical  high medium  low unknown  total
  before         15    86    102   21      33    257
  after          12    84     97   21      33    247

per repo
  checkout-web: 36 -> 35 (cleared 1, new 0)
  partner-api: 25 -> 17 (cleared 8, new 0)
  payments-api: 10 -> 9 (cleared 1, new 0)
```
<!-- /run -->

Each bump raises every copy of the package below the target, in every repo with a finding on
it, and matches the target again against the same advisory data the scan read, in the
ecosystem's own version order:

- **clears** counts findings (one advisory in one repo) left with no affected copy;
- **leaves** counts findings the target does not fix, and says when only some copies moved;
- **new** counts advisories that affect the target but none of the versions it replaces.

Name bumps yourself with `--bump`, as `PACKAGE@VERSION` or `ECOSYSTEM:PACKAGE@VERSION` when
the name is in two ecosystems (`--bump npm:lodash@4.17.21 --bump regex@1.5.5`), add `--repo`
to try them in one repo, or pass a whole plan with `--plan plan.json`. `-f json` gives every
finding by name.

Two limits. Packages the new version pulls in need the registry, so they are left to the
re-scan `fix apply` runs. And Go and GitHub Actions bumps are judged by the fixed ranges in
the report, with no search for new advisories; a warning says so.

## Direct or transitive?

`-f blast` keeps the per-advisory ranking and splits each advisory's repos into direct and
transitive:

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

`upstream` rows cannot be fixed by editing your own manifest; bump the parent package or
add an override.

## Weight by exposure

With repo context in `fleet.toml` and KEV data (`--enrich`), each repo counts by its SSVC
outcome instead of 1, so a package in two internet-facing services outranks one in five
internal tools. See [Prioritise with KEV, EPSS and SSVC](/fleetreach/docs/guides/prioritise-with-kev-epss-and-ssvc/).

## Next

Turn the queue into reviewed changes: [Plan and apply fixes](/fleetreach/docs/guides/plan-and-apply-fixes/).
