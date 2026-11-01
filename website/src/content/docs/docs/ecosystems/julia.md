---
title: Julia
description: Scan Manifest.toml files across a fleet against the osv.dev Julia export with Julia's VersionNumber rules.
sidebar:
  order: 12
---

| | |
|---|---|
| Reads | `Manifest.toml` (format 1 and 2) |
| Advisory data | osv.dev `Julia` export |
| Version rules | Julia `VersionNumber` |

Advisories come from the osv.dev `Julia` export, kept fresh in `~/.cache/fleetreach/osv/` (or read from `--osv-dir`, or `--julia-vuln-db=file://<path>`). Fetch it ahead of time with `fleetreach db sync`.

It runs no package manager and no install or build script, so it is safe to point at any repository and needs no `--allow-untrusted-builds`. Without advisory data for the ecosystem, the repo is an errored gap, never clean.

Direct dependencies come from the sibling `Project.toml`. The
comparator was validated against Julia's own `VersionNumber`.
