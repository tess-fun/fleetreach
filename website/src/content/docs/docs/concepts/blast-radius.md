---
title: Blast radius
description: "How fleetreach measures an advisory's reach across repos, splits it into direct and transitive exposure, and turns that into a fix path: manifest, upstream or mixed."
sidebar:
  order: 2
---

An advisory's blast radius is the number of repos it reaches. Ranking by it puts the fix
that clears the most repos first, even above a more severe finding in a single repo.

<!-- run: fleetreach scan -f blast | head -n 14 -->
```console
$ fleetreach scan -f blast | head -n 14
┌───────┬────────┬────────────┬──────────┬───────────────┬─────────────────────┬──────────────────────────────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Fix      ┆ Severity      ┆ Advisory            ┆ Title                                    │
╞═══════╪════════╪════════════╪══════════╪═══════════════╪═════════════════════╪══════════════════════════════════════════╡
│ 2     ┆ 2      ┆ 0          ┆ manifest ┆ high          ┆ GHSA-2xpw-w6gg-jr37 ┆ urllib3 streaming API improperly handle… │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ manifest ┆ high          ┆ GHSA-35jh-r3h4-6jhm ┆ Command Injection in lodash              │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ manifest ┆ high 7.5      ┆ GHSA-38jv-5279-wg99 ┆ Decompression-bomb safeguards bypassed … │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ manifest ┆ high          ┆ GHSA-3g43-6gmg-66jw ┆ axios Vulnerable to Credential Theft an… │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ manifest ┆ high          ┆ GHSA-43fc-jf86-j433 ┆ Axios is Vulnerable to Denial of Servic… │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ manifest ┆ high          ┆ GHSA-6chq-wfr3-2hj9 ┆ Axios: Header Injection via Prototype P… │
```
<!-- /run -->

Reach is split into **direct** and **transitive**, because how you fix it depends on the
split:

| Fix | Meaning |
|-----|---------|
| `manifest` | every affected repo depends on the package directly: edit or relock |
| `upstream` | it only arrives transitively: bump the parent, or use an override |
| `mixed` | some of each |

`-f packages` rolls the same data up to the package, where one bump often clears several
advisories at once. With repo context and `--enrich`, reach is weighted by each finding's
SSVC outcome, so twelve internal tools rank below three internet-facing services.
