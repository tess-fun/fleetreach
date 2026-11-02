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

`mix.exs` is code, so it is not read. Instead, `mix.lock` records each package's own
dependencies, and a package that no other package requires is direct. An optional
requirement does not count: mix installs an optional dependency only when something requires
it, so if no package does, the project itself must. A package the project names that is also
required by another package shows as transitive.

## Example

The demo fleet's [`chat-svc`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/chat-svc): a Phoenix app's `mix.lock`. `ecosystems/hex.toml` is a fleet file naming just that repo, and the output is real, generated on frozen advisory data.

<!-- run: fleetreach scan -c ecosystems/hex.toml -f packages -->
```console
$ fleetreach scan -c ecosystems/hex.toml -f packages
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬───────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package           │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪═══════════════════╡
│ 1     ┆ 0      ┆ 1          ┆ 7          ┆ high     ┆ upstream ┆ -       ┆ cowlib (hex)      │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 4          ┆ high     ┆ upstream ┆ -       ┆ plug (hex)        │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 3          ┆ high     ┆ upstream ┆ -       ┆ cowboy (hex)      │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 3          ┆ high     ┆ manifest ┆ -       ┆ phoenix (hex)     │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 1          ┆ high     ┆ manifest ┆ -       ┆ plug_cowboy (hex) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 9          ┆ medium   ┆ manifest ┆ -       ┆ jose (hex)        │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 1          ┆ unknown  ┆ upstream ┆ -       ┆ plug_crypto (hex) │
└───────┴────────┴────────────┴────────────┴──────────┴──────────┴─────────┴───────────────────┘
```
<!-- /run -->
