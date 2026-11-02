---
title: GitHub Actions
description: Scan .github/workflows across a fleet for vulnerable and compromised actions such as tj-actions/changed-files, flag tag pins their owner can move, and rewrite them to fixed tags.
sidebar:
  order: 9
---

| | |
|---|---|
| Reads | `.github/workflows/*.yml` `uses:` references |
| Advisory data | osv.dev `GitHub Actions` export |
| Version rules | the tag as SemVer |
| Fix apply | the `uses:` reference rewritten to the fixed tag |

Advisories come from the osv.dev `GitHub Actions` export, kept fresh in `~/.cache/fleetreach/osv/` (or read from `--osv-dir`, or `--ghactions-vuln-db=file://<path>`). Fetch it ahead of time with `fleetreach db sync`.

It runs no package manager and no install or build script, so it is safe to point at any repository and needs no `--allow-untrusted-builds`. Without advisory data for the ecosystem, the repo is an errored gap, never clean.

Workflows are scanned in every repo that has them, alongside its packages. Only
version-pinned references are matched: SHA pins and branch pins are skipped and counted.
With `--signals`, third-party actions pinned to a tag or branch rather than a commit SHA are
flagged, because the owner can move the tag (the `tj-actions/changed-files` compromise, which
is on CISA's KEV list).

## Example

The demo fleet's [`checkout-web`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/checkout-web): its workflows only, with `ecosystem = "actions"` in the fleet file. `ecosystems/github-actions.toml` is a fleet file naming just that repo, and the output is real, generated on frozen advisory data.

<!-- run: fleetreach scan -c ecosystems/github-actions.toml -f packages -->
```console
$ fleetreach scan -c ecosystems/github-actions.toml -f packages
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬───────────────────────────────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package                                   │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪═══════════════════════════════════════════╡
│ 1     ┆ 1      ┆ 0          ┆ 1          ┆ high     ┆ manifest ┆ -       ┆ actions/download-artifact (githubactions) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 1          ┆ high     ┆ manifest ┆ -       ┆ tj-actions/changed-files (githubactions)  │
└───────┴────────┴────────────┴────────────┴──────────┴──────────┴─────────┴───────────────────────────────────────────┘
```
<!-- /run -->
