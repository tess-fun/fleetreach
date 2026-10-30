# Reachability

A dependency advisory tells you a crate *contains* a vulnerable function — but
most of the time your code never calls it, so the finding is noise. Reachability
asks whether that function is actually reachable from your code.

fleetreach has two tiers, both opt-in. The acceptable error direction is always
over-reporting: a finding is only ever *suppressed* by a verdict it can stand
behind.

## Heuristic (`--reachability`)

`--reachability` (bare, or `=heuristic`) is a labelled source-presence
*heuristic* that greps your source and never builds anything. For Rust it greps
for the advisory's affected function names; for the toolchain-free feeders it
greps for an import of each **direct** dependency.

The heuristic only ever *raises* a finding to reachable on a positive match — it
never marks a finding unreachable, so a missed import can't hide a vulnerability.
All 12 ecosystems produce a reachability signal this way.

### npm import graph

Under `--reachability`, npm uses a build-free *module import graph* instead of
the flat grep: it parses every `require`/`import` in your source (and, when
`node_modules` is present, in each installed package), then reports a vulnerable
package as `Reachable` with a witness import-chain. Tools the project runs count
as entry points too: a package whose executable appears in a `package.json`
script or a `.github/workflows` step (`"test": "vitest run"`, `npx stylelint`)
is reached, along with everything it imports, even though nothing imports it.
`--npm-prune-unreachable` additionally marks a package `NotReachable` when no
import path or command reaches it. That negative is best-effort sound (a dynamic
`require(expr)`, or a tool started from a Makefile or another ecosystem's build,
can make it wrong), which is why it is a separate opt-in.

### Python import graph

PyPI gets the same kind of package import graph. It reads every `import` in your
source and, when the repo holds a virtualenv (any directory with a
`pyvenv.cfg`, such as `.venv`), in every installed distribution, mapping module
names to distributions through their `*.dist-info/RECORD` (so `import yaml` is
PyYAML and `google.cloud.storage` is google-cloud-storage). A reached
distribution is `Reachable` with a witness chain such as
`fastapi → starlette → python-multipart`, found even when the import is optional
or comes from a dependency that is not on the lockfile's reported path. A
distribution that loads plugins through entry points reaches every distribution
that registers one.

It is positive-only: an unreached distribution stays `Unknown`. Python imports
dynamically often enough, and large applications load so much of their
dependencies, that an import-level "not reachable" would rarely be both true and
useful. Without a virtualenv, a direct dependency your code imports still gets a
one-step witness.

The table shows the chain in the Reach column (`imported via a → b → c`) for npm
and Python alike.

## Static (`--reachability=static`)

`--reachability=static` is a **sound** MIR call-graph analysis that proves
whether a vulnerable function is callable, with a witness chain. A
`NotReachable` verdict here is trusted enough to suppress: it returns
`NotReachable` only when there is genuinely no path from a root to the sink in
the (over-approximating) call graph. Every uncertainty resolves to `Reachable`
or `Unknown`, never a false `NotReachable`.

> ⚠️ **`--reachability=static` compiles each scanned repo.** Building Rust runs
> the repo's (and its dependencies') `build.rs` scripts and proc-macros — i.e.
> **arbitrary code, with your full user privileges**. This is unlike the rest of
> fleetreach, which only *reads* `Cargo.lock`. Because of that it is gated behind
> an explicit `--allow-untrusted-builds` and prints a warning before any build.
> **Only point it at repositories you trust.** For untrusted code, run it inside
> a sandbox/container with no network and no secrets.

It also needs the pinned-nightly `fleetreach-reach-driver` built and passed via
`--reach-driver`. The driver links `rustc_private` and reads rustc's own
monomorphization set, so the node universe is sound by codegen rather than a
hand-audited walk.

## Go

A Go repo (a `go.mod` with no `Cargo.lock`) is scanned by `govulncheck`, which
compiles the module and confirms call sites. A confirmed call is marked
`reachable` (the analysis is sound-positive); present-but-uncalled stays
`unknown`, never a false "not reachable". Because it compiles, Go scanning needs
`--allow-untrusted-builds`. A degraded toolchain-free **module-level** mode reads
`go.mod` and matches against a vuln.go.dev mirror without compiling anything.
