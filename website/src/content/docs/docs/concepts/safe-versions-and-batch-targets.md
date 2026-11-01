---
title: Safe versions and batch targets
description: "How fleetreach picks the version to bump to: safe outside every affected range, one target that clears every advisory on a package, older-line alternatives, and bump risk from what the fleet already runs."
sidebar:
  order: 5
---

The remediation queue gives one action per package, not per advisory: a single target that
clears every advisory that package has, in every repo.

**Safe means outside every range.** A version is safe only if no affected range of any
advisory on the package contains it. Fixing one advisory's range is not enough when
another advisory's range starts above it.

**One batch target.** The target is the lowest version that is safe for all the package's
advisories at once, and never lower than any advisory's own fix.

**Older lines.** When a repo is on an older major line that has its own fix (`4.17.21` on
4.x while the newest is 5.x), that line's fix is listed as an alternative, so the repo gets
a lock bump instead of a breaking upgrade.

**Bump risk from your fleet.** Each target gets a risk:

| Risk | Meaning |
|------|---------|
| `low` | within the current major |
| `medium` | breaking, but at least 3 repos already run the target or newer in its major |
| `high` | breaking, and few repos have made the move |

<!-- run: fleetreach scan -f remediation | head -n 16 -->
```console
$ fleetreach scan -f remediation | head -n 16
┌────┬───────────────────────────────────────────────────────────────────┬───────────────┬─────────────────────┬───────┬─────────┬─────────┬────────────────────────┐
│ #  ┆ Action                                                            ┆ Severity      ┆ Resolves            ┆ Repos ┆ Reach   ┆ Exploit ┆ Bump risk              │
╞════╪═══════════════════════════════════════════════════════════════════╪═══════════════╪═════════════════════╪═══════╪═════════╪═════════╪════════════════════════╡
│ 1  ┆ bump org.apache.logging.log4j:log4j-core 2.14.1 → 2.25.4          ┆ critical 10.0 ┆ 8 advisories        ┆ 1     ┆ unknown ┆ -       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2  ┆ bump smallvec 1.6.0 → 1.6.1                                       ┆ critical 9.8  ┆ RUSTSEC-2021-0003   ┆ 1     ┆ unknown ┆ -       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 3  ┆ bump nokogiri 1.16.2 → 1.19.4                                     ┆ critical 7.8  ┆ 16 advisories       ┆ 1     ┆ unknown ┆ -       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 4  ┆ bump certifi 2022.9.24 → 2026.10.18 (breaking)                    ┆ critical 7.5  ┆ 4 advisories        ┆ 1     ┆ unknown ┆ -       ┆ high · 1 on 2026.10.23 │
│    ┆   or 2022.12.7 on 2022.x (1 repo, 3 left open)                    ┆               ┆                     ┆       ┆         ┆         ┆                        │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 5  ┆ bump minimist 1.2.5 → 1.2.6                                       ┆ critical      ┆ GHSA-xvch-5gv4-984h ┆ 1     ┆ unknown ┆ -       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 6  ┆ bump urllib3 1.26.12 → 2.8.0 (breaking)                           ┆ high 8.1      ┆ 10 advisories       ┆ 2     ┆ unknown ┆ -       ┆ high                   │
│    ┆   or 1.26.19 on 1.x (2 repos, 7 left open)                        ┆               ┆                     ┆       ┆         ┆         ┆                        │
```
<!-- /run -->

`fix plan` turns the queue into edits, and blocks breaking ones unless `--allow-breaking`.
See [Plan and apply fixes](/fleetreach/docs/guides/plan-and-apply-fixes/).
