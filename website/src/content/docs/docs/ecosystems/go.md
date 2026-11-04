---
title: Go
description: "Scan Go modules across a fleet: govulncheck for call-level confirmation, or a toolchain-free go.mod matcher against the osv.dev Go export that compiles nothing."
sidebar:
  order: 2
---

Go has two modes.

| | govulncheck | Toolchain-free |
|---|---|---|
| Reads | the compiled module | `go.mod` |
| Advisory data | vuln.go.dev (or `--go-vuln-db file://<mirror>`) | osv.dev `Go` export |
| Needs | `govulncheck` on `PATH` and `--allow-untrusted-builds` | nothing |
| Reachability | calls confirmed: `reachable` | module level, `unknown` |
| Severity | `unknown` | GitHub's band |

When `govulncheck` is not available, or builds are not allowed, the module-level matcher
reads `go.mod` (including `// indirect` requirements and `replace` directives, and
pseudo-versions) and matches it against the export `fleetreach db sync` keeps with the
others. A `GO-` record and its GHSA twin collapse into one finding.

The Go team's records carry no severity, so a `GO-` record takes the band of the GitHub records
sharing an id with it, the worst if they disagree. Most of the standard library's have none, and
stay `unknown`, which fails every `--fail-on` floor.

`govulncheck` compiles the module, so it runs inside the build sandbox (`--build-sandbox`),
which denies network; a confined scan needs a local `--go-vuln-db` mirror.

## Fixing

`fix apply` runs `go get <module>@v<to>` in each module that requires it, then
`go list -deps -test ./...` to record checksums, with `GOTOOLCHAIN=local` and `GOWORK=off`.
Go downloads module sources but never runs them. When an update raises the module's `go`
directive, the commit and pull request say so.

## Example

The demo fleet's [`inventory-svc`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/inventory-svc): a Go service's `go.mod`, read without the Go toolchain. `ecosystems/go.toml` is a fleet file naming just that repo, and the output is real, generated on frozen advisory data.

<!-- run: fleetreach scan -c ecosystems/go.toml -f packages -->
```console
$ fleetreach scan -c ecosystems/go.toml -f packages
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬─────────────────────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package                         │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪═════════════════════════════════╡
│ 1     ┆ 0      ┆ 1          ┆ 23         ┆ critical ┆ upstream ┆ -       ┆ golang.org/x/crypto (go)        │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 6          ┆ critical ┆ manifest ┆ -       ┆ google.golang.org/grpc (go)     │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 21         ┆ medium   ┆ manifest ┆ -       ┆ golang.org/x/net (go)           │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 1          ┆ medium   ┆ manifest ┆ -       ┆ github.com/gin-gonic/gin (go)   │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 1          ┆ medium   ┆ manifest ┆ -       ┆ google.golang.org/protobuf (go) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 2          ┆ unknown  ┆ upstream ┆ -       ┆ golang.org/x/text (go)          │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 0      ┆ 1          ┆ 1          ┆ unknown  ┆ upstream ┆ -       ┆ golang.org/x/sys (go)           │
└───────┴────────┴────────────┴────────────┴──────────┴──────────┴─────────┴─────────────────────────────────┘
```
<!-- /run -->
