---
title: Enforce a license policy
description: List the license of every dependency across the fleet, fail on the ones your policy denies, find copyleft that conflicts with a repo's own license, and write attribution files.
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

Exit codes: `0` nothing denied, `1` a license or a conflict is denied, `2` a source could not
be read.
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

The matcher reads whole license files and the standard short notices. It does not read source
file headers or a sentence that names a license in passing, and one file that strings several
licenses together can come back with only some of them.
Detection runs on this machine and sends nothing. A package whose files are not here is counted
on stderr and keeps its declared license.

### Download what is not here

A fresh CI runner has no `node_modules` and no Cargo cache. `--download` fetches those packages:

```bash
fleetreach licenses --detect --download
```

Each archive comes from the public registry and must match the hash in the lockfile, or it is
dropped with a warning. Only the license files are kept, under the user cache, keyed by that hash
and shared by every repo. After that `--detect` alone reads them with no network, so a CI job can
restore that directory and run offline. The archive itself is never unpacked to disk and none of
its code runs.

| Ecosystem | Fetched | Checked against |
|-----------|---------|-----------------|
| npm, pnpm, yarn classic, bun | registry tarball | `integrity` |
| Cargo | crate | `checksum` in `Cargo.lock` |
| PyPI | source distribution | the hash in `uv.lock`, `poetry.lock` or `pylock.toml` |
| RubyGems | gem | `CHECKSUMS` in `Gemfile.lock` |
| Hex | tarball | the outer checksum in `mix.lock` |
| Go | module zip | the tree hash in `go.sum` |

`--download` sends each such package's name and version to its registry, and never a git, path or
private-registry package, nor a Go module under `GOPRIVATE` or `GONOPROXY`. A package with no hash
in its lockfile is not fetched, since nothing would say the file is the one in use. That covers
NuGet, whose `contentHash` skips the signature, and a Python package published as wheels only.

A mismatch needs a declaration to compare with. On a fresh machine, Cargo and Go packages have
none until `--fetch` asks deps.dev for it, so add that flag to compare them as well.

## Copyleft conflicts

Whether GPL is a problem depends on the repo that uses it. Say what each repo is in
`fleet.toml`:

```toml title="fleet.toml"
[[repo]]
id       = "checkout"
path     = "../checkout"
license  = "proprietary"   # or an SPDX expression such as "MIT" or "GPL-2.0-only"
exposure = "open"          # an internet-facing service
```

`licenses` then reports a runtime dependency as a conflict when its license requires (every
way to satisfy its expression names it):

| Rule | When |
|------|------|
| network copyleft | AGPL or SSPL in a repo whose exposure is `open`: network users are owed the source, with no binary ever shipped |
| copyleft in proprietary code | GPL, AGPL, SSPL, OSL or EUPL in a repo whose `license` is `proprietary` |
| copyleft in permissive code | the same in a repo whose license offers only permissive terms, such as `MIT` |
| GPL-2.0-only incompatible | Apache-2.0, GPL-3.0, AGPL-3.0 or LGPL-3.0 in a repo that can only be `GPL-2.0-only` |

```console
conflict (copyleft in proprietary code): checkout npm gpl-dep@1.0.0 (GPL-3.0-or-later): requires GPL-3.0-or-later, and the repo is proprietary: distributing it puts it under GPL-3.0-or-later
```

`MIT OR GPL-3.0-only` requires neither, so it never conflicts. Dev-only packages are never
shipped and never conflict, and LGPL, MPL and other weak copyleft are left out, since they bind
the library rather than the program linking it. A repo under the same terms as its dependency
(an AGPL service using AGPL code) has no conflict. An `exception` that allows a license for a
package also clears conflicts over it.

Exposure comes from the repo, its tag rules or `[settings.context.defaults]`, the same values
`scan` uses for SSVC, so with SSVC on a repo with no exposure counts as `open`. Without
`license` only the network rule can apply.

`[settings.licenses] conflicts` is `warn` by default and can be `deny`, which makes the run exit
`1`, or `allow`. Conflicts are listed under `conflicts` in `-f json`. How the dependency is used
(linked, vendored, or run as a separate program) is not known here, so treat a conflict as a
question for whoever owns the repo, not as a legal finding.

## Write attribution files

`--notice DIR` writes one `<repo>.NOTICE.txt` per repo, ready to ship with a release:

```bash
fleetreach licenses --notice dist/notices
```

Each file holds the license texts of the repo's runtime packages, read from the files they
ship, with packages whose texts are identical grouped under one copy. `NOTICE` files, which
Apache-2.0 asks to be passed on, are reproduced per package. A package whose files are not on
this machine is listed at the end with its declared license, so the file never reads as
complete when it is not. `--notice` implies `--detect`; add `--download` to fetch what is
missing.
