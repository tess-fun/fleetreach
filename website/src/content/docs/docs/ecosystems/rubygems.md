---
title: RubyGems (Ruby)
description: Scan Gemfile.lock files across a fleet with a faithful Gem::Version comparator, not SemVer, against the osv.dev RubyGems export.
sidebar:
  order: 5
---

| | |
|---|---|
| Reads | `Gemfile.lock` (direct set from its `DEPENDENCIES` section) |
| Advisory data | osv.dev `RubyGems` export |
| Version rules | `Gem::Version`, as RubyGems 3.3 and later compare |

Advisories come from the osv.dev `RubyGems` export, kept fresh in `~/.cache/fleetreach/osv/` (or read from `--osv-dir`, or `--rubygems-vuln-db=file://<path>`). Fetch it ahead of time with `fleetreach db sync`.

It runs no package manager and no install or build script, so it is safe to point at any repository and needs no `--allow-untrusted-builds`. Without advisory data for the ecosystem, the repo is an errored gap, never clean.

Ruby versions are not SemVer: `1.0.a` is a prerelease and segments compare as RubyGems
does. About a third of RubyGems advisories list affected versions with no range, so the
enumerated list is always consulted. Platform gems (`nokogiri-1.16.2-x86_64-linux`) are
matched by their version.

## Example

The demo fleet's [`billing`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/billing): a Rack app's `Gemfile.lock`. `ecosystems/rubygems.toml` is a fleet file naming just that repo, and the output is real, generated on frozen advisory data.

<!-- run: fleetreach scan -c ecosystems/rubygems.toml -f packages -->
```console
$ fleetreach scan -c ecosystems/rubygems.toml -f packages
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬─────────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package             │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪═════════════════════╡
│ 1     ┆ 1      ┆ 0          ┆ 16         ┆ critical ┆ manifest ┆ -       ┆ nokogiri (rubygems) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 23         ┆ high     ┆ manifest ┆ -       ┆ rack (rubygems)     │
└───────┴────────┴────────────┴────────────┴──────────┴──────────┴─────────┴─────────────────────┘
```
<!-- /run -->
