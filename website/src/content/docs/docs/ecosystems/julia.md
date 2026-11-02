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

Since Julia 1.11 the manifest also records the version of each standard library. Most have
no advisories, but the binary libraries Julia ships (`LibCURL_jll`, `OpenSSL_jll`,
`LibSSH2_jll` and others) do, and they are matched like any package. The fix for those is a
newer Julia, so they show as transitive, with an upstream fix. Older manifests leave
standard libraries without a version, and they are skipped.

## Example

The demo fleet's [`forecasting`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/forecasting): a Julia project on CSV, DataFrames and HTTP. `ecosystems/julia.toml` is a fleet file naming just that repo, and the output is real, generated on frozen advisory data.

<!-- run: fleetreach scan -c ecosystems/julia.toml -f packages -->
```console
$ fleetreach scan -c ecosystems/julia.toml -f packages
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬─────────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package             │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪═════════════════════╡
│ 1     ┆ 0      ┆ 1          ┆ 35         ┆ critical ┆ upstream ┆ -       ┆ LibCURL_jll (julia) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 34         ┆ critical ┆ upstream ┆ -       ┆ OpenSSL_jll (julia) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 7          ┆ critical ┆ upstream ┆ -       ┆ MbedTLS_jll (julia) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 6          ┆ critical ┆ upstream ┆ -       ┆ LibGit2_jll (julia) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 12         ┆ high     ┆ manifest ┆ -       ┆ Libtiff_jll (julia) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 10         ┆ high     ┆ upstream ┆ -       ┆ LibSSH2_jll (julia) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 2          ┆ high     ┆ upstream ┆ -       ┆ nghttp2_jll (julia) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 1          ┆ medium   ┆ upstream ┆ -       ┆ Zlib_jll (julia)    │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 1          ┆ low      ┆ upstream ┆ -       ┆ p7zip_jll (julia)   │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 16         ┆ unknown  ┆ manifest ┆ -       ┆ HTTP (julia)        │
└───────┴────────┴────────────┴────────────┴──────────┴──────────┴─────────┴─────────────────────┘
```
<!-- /run -->
