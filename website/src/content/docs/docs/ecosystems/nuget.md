---
title: NuGet (.NET)
description: Scan .NET projects across a fleet from packages.lock.json, project.assets.json, packages.config or csproj files, with central package management and NuGet version rules.
sidebar:
  order: 7
---

| | |
|---|---|
| Reads, first found | `packages.lock.json`, `obj/project.assets.json`, `packages.config`, `*.csproj` `PackageReference` |
| Advisory data | osv.dev `NuGet` export |
| Version rules | four-part `NuGetVersion` |

Advisories come from the osv.dev `NuGet` export, kept fresh in `~/.cache/fleetreach/osv/` (or read from `--osv-dir`, or `--nuget-vuln-db=file://<path>`). Fetch it ahead of time with `fleetreach db sync`.

It runs no package manager and no install or build script, so it is safe to point at any repository and needs no `--allow-untrusted-builds`. Without advisory data for the ecosystem, the repo is an errored gap, never clean.

Most .NET projects have no lockfile. `obj/project.assets.json` (written by `dotnet restore`)
gives the full graph; project files alone give direct dependencies only, labelled
direct-only coverage. Central package management is read (`Directory.Packages.props`,
`GlobalPackageReference`, `VersionOverride`), and `$(Property)` values from the project and
the nearest `Directory.Build.props`. Conditions are not evaluated, an `<Import>` of another
file is named as a gap, and floating versions (`1.*`) are listed, never guessed.

Validated against `NuGet.Versioning` itself.

## Example

The demo fleet's [`reporting-svc`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/reporting-svc): a .NET 8 service with a `packages.lock.json`. `ecosystems/nuget.toml` is a fleet file naming just that repo, and the output is real, generated on frozen advisory data.

<!-- run: fleetreach scan -c ecosystems/nuget.toml -f packages -->
```console
$ fleetreach scan -c ecosystems/nuget.toml -f packages
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬──────────────────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package                      │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪══════════════════════════════╡
│ 1     ┆ 1      ┆ 0          ┆ 11         ┆ high     ┆ manifest ┆ -       ┆ sixlabors.imagesharp (nuget) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 1          ┆ high     ┆ manifest ┆ -       ┆ newtonsoft.json (nuget)      │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 1          ┆ high     ┆ manifest ┆ -       ┆ npgsql (nuget)               │
└───────┴────────┴────────────┴────────────┴──────────┴──────────┴─────────┴──────────────────────────────┘
```
<!-- /run -->
