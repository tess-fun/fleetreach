---
title: npm
description: "Scan npm, pnpm, Yarn and Bun lockfiles across a fleet without running a package manager: full transitive trees, dev scope, import-graph reachability and lock-only fixes."
sidebar:
  order: 3
---

| | |
|---|---|
| Reads | `package-lock.json`, `pnpm-lock.yaml` (v6, v9), `yarn.lock` (v1 and Berry), `bun.lock` |
| Advisory data | osv.dev `npm` export |
| Version rules | SemVer |
| Fix apply | `npm update <pkg> --package-lock-only --ignore-scripts` |
| Reachability | module import graph with witness chains |

A package is direct when the root `package.json` names it; everything else is transitive,
with the path that pulls it in. Packages marked `"dev": true` are dev scope, unless a
runtime dependency also reaches them. The binary `bun.lockb` cannot be read and is reported
as a partial coverage gap; `bun install --save-text-lockfile` writes the text format.

Advisories come from the osv.dev `npm` export, kept fresh in `~/.cache/fleetreach/osv/` (or read from `--osv-dir`, or `--npm-vuln-db=file://<path>`). Fetch it ahead of time with `fleetreach db sync`.

It runs no package manager and no install or build script, so it is safe to point at any repository and needs no `--allow-untrusted-builds`. Without advisory data for the ecosystem, the repo is an errored gap, never clean.

With `--signals`, npm packages that run install scripts, come from git or a URL, or are one
edit from a popular package name are flagged. See
[Detect supply-chain signals](/fleetreach/docs/guides/detect-supply-chain-signals/).

Validated at 100% recall with zero false cleans on 565 real lockfiles against the full npm
export, using real lockfiles generated with node and npm as the oracle.
