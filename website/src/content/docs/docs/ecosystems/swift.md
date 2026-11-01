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
version have no release to match and are skipped.
