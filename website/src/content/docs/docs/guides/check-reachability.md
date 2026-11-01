---
title: Check reachability
description: Find out whether vulnerable code is actually reached, with import-graph witness chains for npm and Python and a sound MIR call-graph analysis for Rust.
sidebar:
  order: 12
---

An advisory says a package contains vulnerable code; reachability asks whether your code
gets to it. fleetreach has two tiers, both opt-in, and only ever suppresses a finding on a
verdict it can stand behind.

## Heuristic and import graphs (no build)

```sh
fleetreach scan --reachability
```

- **npm** builds a module import graph from every `require` and `import` (and from
  `node_modules` when present) and reports a reached package with a witness chain. Tools run
  from `package.json` scripts or workflow steps count as entry points.
  `--npm-prune-unreachable` also marks unreached packages `NotReachable`; that negative is
  best-effort (a dynamic `require(expr)` can defeat it), so it is a separate opt-in.
- **Python** does the same over a repo's virtualenv, mapping modules to distributions
  through their `RECORD` files, so `import yaml` is PyYAML. It is positive-only: an
  unreached distribution stays `unknown`.
- **Other ecosystems** grep your source for imports of each direct dependency, and for Rust
  for the advisory's affected function names. A match raises a finding to reachable; no
  match never lowers it.

The table's `Reach` column shows the chain, for example
`imported via fastapi → starlette → python-multipart`.

## Sound static analysis for Rust

```sh
fleetreach scan --reachability=static --allow-untrusted-builds --reach-driver <path>
```

A MIR call-graph analysis over the compiled crate closure proves whether a vulnerable
function is callable, with a witness chain. `NotReachable` is returned only when there is no
path in an over-approximating call graph, so it is trusted enough to suppress: such a
finding drops to the end of the fix queue, becomes `not_affected` in VEX and SARIF, and is
`defer` in SSVC.

:::caution[It compiles the repos]
Building Rust runs each repo's build scripts and procedural macros, which is arbitrary code
with your privileges. It needs `--allow-untrusted-builds` and the separately built
`fleetreach-reach-driver`. Only point it at repositories you trust, or run it in a sandbox.
:::

## Go

With `govulncheck` on `PATH` (and `--allow-untrusted-builds`, since it compiles the module),
Go findings that are called are marked reachable. Without it, Go is matched at module level
from the osv.dev export, compiling nothing.
