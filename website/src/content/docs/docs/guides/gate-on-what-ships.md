---
title: Gate on what ships
description: How fleetreach tells dev and build-only packages from runtime ones in each ecosystem, and how to give them their own gate.
sidebar:
  order: 6
---

A vulnerable test framework and a vulnerable web server are not the same risk. fleetreach
marks each occurrence `runtime` or `dev`, shows it in JSON as `scope: dev` and in SBOMs as
`scope: excluded`, and can gate the two differently.

```sh
fleetreach scan --fail-on low --fail-on-dev high    # dev packages gate from high up
fleetreach scan --fail-on-dev never                 # dev packages are reported, never gate
fleetreach scan --ignore-dev-deps                   # dev packages leave the report
```

Or once for the fleet, in `fleet.toml`:

```toml
[settings.gate.scope]
dev = "critical"   # or low, medium, high, never
```

`--fail-on-dev` wins over the file, and without either a dev package gates like any other.
`diff --base` takes the same flag.

Three things never move. Known malware answers to `--fail-on` wherever it sits, because
installing it can be enough. A finding of unknown severity on a dev package still fails, unless
the floor is `never`. And `--fail-on-kev` and `--fail-on-ssvc` look at every package.

## What counts as dev

A package is dev when only dev dependencies lead to it. Anything a runtime dependency also
needs stays runtime, and anything fleetreach cannot read stays runtime too: `dev` can take a
finding out of a gate, so it needs evidence.

| Ecosystem | Dev means | Stays runtime |
|-----------|-----------|---------------|
| npm, PyPI, Composer | the lockfile's dev groups | |
| Maven | `test` and `provided` scope | |
| Gradle | test configurations | |
| Cargo | not reached through `[dependencies]` from the workspace | everything, if a workspace member's manifest is missing or a `members` glob is not a trailing `*`. `Cargo.lock` keeps no edge kinds, so build dependencies of third-party crates count as runtime |
| Bundler | every group is `development` or `test` | gems in other groups, or with no `Gemfile` beside the lockfile |
| Hex | `only:` leaves out `:prod` | `runtime: false` alone, and a computed `only:`. With a shipping git dep, whose dependencies `mix.lock` does not list, only what `mix.exs` itself declares dev-only is dev |
| NuGet | `PrivateAssets="all"`, `Publish="false"`, runtime assets excluded, or a test project | `PrivateAssets` naming anything less than `all` |
| Go | only `_test.go` files build it | everything, unless the source of every dependency is in `vendor/` or the module cache |
| Swift, Julia | never | everything: their lockfiles do not mark test dependencies |
| GitHub Actions | never | everything: a CI action runs with your secrets |

## Go needs the dependency source

A module your tests import directly can also be imported by something you ship, and `go.mod`
does not say so. fleetreach follows imports through the source of every package, under all
build tags, so run `go mod download` before the scan. If a package's source is missing, or
`go.mod` says `go 1.16` or older, the repo stays at runtime.

## NuGet and `dotnet build`

`dotnet publish` and `dotnet pack` leave out a `PrivateAssets="all"` package, even one the code
calls at runtime. A plain `dotnet build` still copies it to `bin/`. If you deploy `bin/`, keep
the default gate.
