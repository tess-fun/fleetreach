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
