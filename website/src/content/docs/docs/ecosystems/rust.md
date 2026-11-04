---
title: Rust
description: "Scan Cargo.lock files across a fleet with the RustSec advisory database: unmaintained and unsound crates, yanked versions, toolchain advisories, phantom optional dependencies and sound reachability."
sidebar:
  order: 1
---

fleetreach started as a Rust tool and Rust has the deepest support. It reads `Cargo.lock`
with the `rustsec` engine against the [RustSec advisory database](https://rustsec.org), then
adds what only GitHub carries from the osv.dev `crates.io` export.

| | |
|---|---|
| Reads | `Cargo.lock` (workspaces included) |
| Advisory data | RustSec `advisory-db` (cloned and refreshed; `--db <path>` for a local copy), and the osv.dev `crates.io` export (`--osv-dir`, or `--crates-vuln-db=file://<path>`) |
| Version rules | SemVer |
| Fix apply | `cargo update -p <pkg>@<from> --precise <to>` |
| Reachability | heuristic (no build) or sound static MIR analysis |

Beyond vulnerabilities it reports RustSec's informational kinds as warnings: `unmaintained`,
`unsound` and `notice`, plus yanked crate versions. The Rust toolchain's own advisories are
checked against the installed `rustc`.

## RustSec and GitHub

Hundreds of crates.io advisories exist only in GitHub's database, so RustSec alone misses them.
A crate RustSec already reported an advisory for keeps RustSec's finding, under its RUSTSEC id,
and is not reported again. GitHub's record still counts where its range or crate list is wider
than RustSec's, because the two disagreeing is no reason to read clean. An advisory RustSec
withdrew stays withdrawn. As with RustSec, git and private-registry crates are not matched: a
fork is not the crate an advisory describes.

Without the export the scan still answers from RustSec, and the repo shows a partial coverage
gap. Fetch it ahead of time with `fleetreach db sync`.

## Built or not?

`--resolve-features` asks `cargo tree` which optional dependencies are really compiled with
the default features. A finding on one that never is gets `⚠ not in default build`, and
`--ignore-phantom` drops it. Both need buildable source.

## Proving reachability

`--reachability=static` compiles each crate with a pinned nightly driver and proves whether
the advisory's affected functions can be called, with a witness chain. A `NotReachable`
verdict is sound and becomes `not_affected` in VEX and SARIF. See
[Check reachability](/fleetreach/docs/guides/check-reachability/).

## Example

The demo fleet's [`payments-api`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/payments-api): a Rust service's `Cargo.lock`. `ecosystems/rust.toml` is a fleet file naming just that repo, and the output is real, generated on frozen advisory data.

<!-- run: fleetreach scan -c ecosystems/rust.toml -f packages -->
```console
$ fleetreach scan -c ecosystems/rust.toml -f packages
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬──────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package  │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪══════════╡
│ 1     ┆ 1      ┆ 0          ┆ 1          ┆ critical ┆ manifest ┆ -       ┆ smallvec │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 1          ┆ high     ┆ manifest ┆ -       ┆ regex    │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 1          ┆ medium   ┆ upstream ┆ -       ┆ time     │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 6          ┆ unknown  ┆ manifest ┆ -       ┆ openssl  │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 1          ┆ unknown  ┆ manifest ┆ -       ┆ chrono   │
└───────┴────────┴────────────┴────────────┴──────────┴──────────┴─────────┴──────────┘
```
<!-- /run -->
