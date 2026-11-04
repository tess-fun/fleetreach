---
title: Enforce a license policy
description: List the license of every dependency across the fleet and fail on the ones your policy denies, with SPDX expressions, categories and per-package exceptions.
sidebar:
  order: 10
---

`fleetreach licenses` lists the license of every dependency across the fleet and, with a
policy, the ones that break it.

<!-- run: fleetreach licenses -->
```console
$ fleetreach licenses
┌──────────────┬──────────┬──────────┬───────┐
│ License      ┆ Category ┆ Packages ┆ Repos │
╞══════════════╪══════════╪══════════╪═══════╡
│ MIT          ┆ notice   ┆ 63       ┆ 2     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┤
│ ISC          ┆ notice   ┆ 3        ┆ 1     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┤
│ BSD-3-Clause ┆ notice   ┆ 2        ┆ 1     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┤
│ Apache-2.0   ┆ notice   ┆ 1        ┆ 1     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┤
│ (unknown)    ┆ unknown  ┆ 71       ┆ 8     │
└──────────────┴──────────┴──────────┴───────┘
```
<!-- /run -->

Many packages start unknown: lockfiles rarely carry licenses (Composer always does, npm
sometimes) and local caches only hold what was installed on this machine. `--fetch` looks
the rest up on [deps.dev](https://deps.dev), which sends each such package's ecosystem,
name and version to Google, so it only happens when you ask. Answers are cached for good.

## Write a policy

```toml title="fleet.toml"
[settings.licenses]
allow      = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
deny       = ["SSPL-1.0"]
categories = { restricted = "deny", reciprocal = "warn" }  # allow | warn | deny
unknown    = "deny"        # a package with no known license is a violation
scope      = "runtime"     # leave dev-only packages out

[[settings.licenses.exception]]
package = "ring"
allow   = ["OpenSSL"]
reason  = "reviewed by legal 2026-09"
```

An SPDX expression passes if it can be satisfied: `AGPL-3.0-only OR MIT` is fine under a
policy that allows MIT. Without `categories`, forbidden licenses are denied and restricted
ones warned.

| Category | Examples |
|----------|----------|
| forbidden | AGPL, SSPL, BUSL, CC-BY-NC |
| restricted | GPL, LGPL, CC-BY-SA, EUPL |
| reciprocal | MPL, EPL, CDDL |
| notice | MIT, Apache-2.0, BSD, ISC, Zlib |
| unencumbered | CC0, Unlicense, 0BSD |

Exit codes: `0` nothing denied, `1` a license is denied, `2` a source could not be read.
`-f json` lists every package with its license, source and verdict.

## Read the license files

A declared license is what the author wrote in a manifest. `--detect` reads what the package
actually ships: the `LICENSE`, `COPYING` and similar files of every package
already on this machine, in `node_modules`, `vendor`, a virtualenv, and the Cargo, Go and NuGet
caches.

```bash
fleetreach licenses --detect
```

It does two things:

- A package no source knew takes the license its files say, shown with the source
  `license file`. If a file could not be recognized the package stays unknown, since that file
  may say anything.
- A package whose files name a license its declaration does not account for is a mismatch:
  `mismatch: rollup 4.62.4 declares MIT, files also say 0BSD, ISC`. Bundled third-party code is
  the usual cause, and it is what a declaration hides.

`[settings.licenses] mismatch` sets the verdict for a mismatch: `allow`, `warn` (the default) or
`deny`. Every mismatch stays listed under `mismatches` in `-f json` whatever the verdict.

The matcher reads whole license files and short notices, not license headers in source files,
and one file that strings several licenses together can come back with only some of them.
Detection runs on this machine and sends nothing. A package whose files are not here is counted
on stderr and keeps its declared license.
