---
title: Hex (Elixir and Erlang)
description: Scan mix.lock files across a fleet against the osv.dev Hex export.
sidebar:
  order: 11
---

| | |
|---|---|
| Reads | `mix.lock` |
| Advisory data | osv.dev `Hex` export |
| Version rules | SemVer (Elixir `Version`) |

Advisories come from the osv.dev `Hex` export, kept fresh in `~/.cache/fleetreach/osv/` (or read from `--osv-dir`, or `--hex-vuln-db=file://<path>`). Fetch it ahead of time with `fleetreach db sync`.

It runs no package manager and no install or build script, so it is safe to point at any repository and needs no `--allow-untrusted-builds`. Without advisory data for the ecosystem, the repo is an errored gap, never clean.

Git and path dependencies in `mix.lock` have no Hex release and are skipped.
