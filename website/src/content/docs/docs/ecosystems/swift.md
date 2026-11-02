---
title: Swift
description: Scan Package.resolved files across a fleet against the osv.dev SwiftURL export, matching packages by repository URL.
sidebar:
  order: 10
---

| | |
|---|---|
| Reads | `Package.resolved` (v1, v2, v3) |
| Advisory data | osv.dev `SwiftURL` export |
| Version rules | SemVer, packages identified by URL |

Advisories come from the osv.dev `SwiftURL` export, kept fresh in `~/.cache/fleetreach/osv/` (or read from `--osv-dir`, or `--swift-vuln-db=file://<path>`). Fetch it ahead of time with `fleetreach db sync`.

It runs no package manager and no install or build script, so it is safe to point at any repository and needs no `--allow-untrusted-builds`. Without advisory data for the ecosystem, the repo is an errored gap, never clean.

Swift packages have no registry name, so a package is its repository URL, normalised
(scheme, `git@` form, `.git` suffix and case) before matching. Pins to a branch or revision with no
version have no release to match and are skipped. Direct dependencies are the
`.package(url:)` declarations in the sibling `Package.swift`.

## Example

The demo fleet's [`notifications-gateway`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/notifications-gateway): a Vapor server's `Package.resolved`. `ecosystems/swift.toml` is a fleet file naming just that repo, and the output is real, generated on frozen advisory data.

<!-- run: fleetreach scan -c ecosystems/swift.toml -f packages -->
```console
$ fleetreach scan -c ecosystems/swift.toml -f packages
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬───────────────────────────────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package                                   │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪═══════════════════════════════════════════╡
│ 1     ┆ 0      ┆ 1          ┆ 1          ┆ medium   ┆ upstream ┆ -       ┆ github.com/apple/swift-nio-extras (swift) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 1          ┆ medium   ┆ manifest ┆ -       ┆ github.com/vapor/vapor (swift)            │
└───────┴────────┴────────────┴────────────┴──────────┴──────────┴─────────┴───────────────────────────────────────────┘
```
<!-- /run -->
