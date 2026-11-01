---
title: Packagist (PHP)
description: Scan composer.lock files across a fleet with Composer's own version ordering, including Magento-style patch releases, against the osv.dev Packagist export.
sidebar:
  order: 6
---

| | |
|---|---|
| Reads | `composer.lock`, with direct dependencies from `composer.json` |
| Advisory data | osv.dev `Packagist` export |
| Version rules | Composer `version_compare` |

Advisories come from the osv.dev `Packagist` export, kept fresh in `~/.cache/fleetreach/osv/` (or read from `--osv-dir`, or `--packagist-vuln-db=file://<path>`). Fetch it ahead of time with `fleetreach db sync`.

It runs no package manager and no install or build script, so it is safe to point at any repository and needs no `--allow-untrusted-builds`. Without advisory data for the ecosystem, the repo is an errored gap, never clean.

Composer orders `dev < alpha < beta < RC < stable < patch`, so `2.4.5-p1` sorts **above**
`2.4.5`, the opposite of SemVer. `packages-dev` are dev scope. Names are compared
case-insensitively.

The comparator agrees with the real `composer/semver` library on 185,000 version pairs.
