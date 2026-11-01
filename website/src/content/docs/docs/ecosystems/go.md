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
| Advisory data | vuln.go.dev (or `--go-vuln-db file://<mirror>`) | osv.dev `Go` export, `GO-` records only |
| Needs | `govulncheck` on `PATH` and `--allow-untrusted-builds` | nothing |
| Reachability | calls confirmed: `reachable` | module level, `unknown` |

When `govulncheck` is not available, or builds are not allowed, the module-level matcher
reads `go.mod` (including `// indirect` requirements and `replace` directives, and
pseudo-versions) and matches it against the export `fleetreach db sync` keeps with the
others. Only `GO-` records count, so the export's GHSA copies are not counted twice.

`govulncheck` compiles the module, so it runs inside the build sandbox (`--build-sandbox`),
which denies network; a confined scan needs a local `--go-vuln-db` mirror.

## Fixing

`fix apply` runs `go get <module>@v<to>` in each module that requires it, then
`go list -deps -test ./...` to record checksums, with `GOTOOLCHAIN=local` and `GOWORK=off`.
Go downloads module sources but never runs them. When an update raises the module's `go`
directive, the commit and pull request say so.
