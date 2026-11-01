---
title: Detect supply-chain signals
description: Flag install scripts, git and URL dependencies, unexpected registries, missing checksums, tag-pinned GitHub Actions, typosquats, brand-new releases and packages new to the fleet.
sidebar:
  order: 16
---

`--signals` adds supply-chain warnings from the lockfiles already read, with no network.
They are warnings, never vulnerabilities, and gate only with `--fail-on-warnings`.

<!-- run: fleetreach scan --signals | tail -n 7 -->
```console
$ fleetreach scan --signals | tail -n 7
┌─────────┬───────────────────────────────┬───────────────────────────────────────────────────────┐
│ Kind    ┆ Advisory                      ┆ Locations                                             │
╞═════════╪═══════════════════════════════╪═══════════════════════════════════════════════════════╡
│ unsound ┆ RUSTSEC-2023-0072             ┆ payments-api/openssl@0.10.38 → 0.10.60 (direct)       │
├╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ notice  ┆ fleetreach:mutable-action-ref ┆ checkout-web/tj-actions/changed-files@44.0.0 (direct) │
└─────────┴───────────────────────────────┴───────────────────────────────────────────────────────┘
```
<!-- /run -->

It flags:

- packages that run an install script;
- packages fetched from git, a URL or a path;
- packages from a registry outside the public ones (add yours with
  `[settings.signals] registries = ["npm.example.com"]`; lookalike hosts are caught);
- registry packages with no checksum;
- third-party GitHub Actions pinned to a tag or branch their owner can move, instead of a
  commit SHA (the `tj-actions/changed-files` attack);
- possible typosquats: npm, PyPI and Cargo names one edit from a popular package they are
  not. The popular names are bundled, so nothing is sent anywhere.

## Brand-new releases

```sh
fleetreach scan --release-age 72h
```

flags dependency versions published less than 72 hours ago, which is what you want to know
during a worm outbreak. Publish times come from deps.dev (each package's name and version is
sent; answers are cached). A version deps.dev cannot date is listed, never assumed old.

## New to the fleet

With `--history-dir`, `--signals` also flags packages whose name no earlier recorded run has
read. The first recorded run is the baseline and flags nothing.

## Malware

Known malware (OSV `MAL-` records) needs no flag: it is always critical, never hidden by
`--min-severity`, and the fix queue says to remove the package and rotate credentials.
