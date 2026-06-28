# fleetreach

[![crates.io](https://img.shields.io/crates/v/fleetreach-cli.svg)](https://crates.io/crates/fleetreach-cli)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#msrv)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

**A fleet-native dependency security auditor.** Point it at many repositories at
once and get one deduplicated, ranked, CI-pipeable view of which dependencies
across your whole fleet carry known advisories (plus supply-chain warnings:
unmaintained, unsound, notice; and advisories against the Rust toolchain
itself). On top of that you get blast-radius analysis (which single fix clears
the most repos, split direct versus transitive), a batched remediation queue,
`--why` provenance across the fleet, drift tracking between scans, and SARIF /
JSON / OpenVEX output. One binary: no server to run, no SBOM pipeline to wire up.

It covers 12 ecosystems (Rust, Go, npm, PyPI, RubyGems, Packagist, NuGet, Julia,
Swift, Hex, Maven, GitHub Actions), and for Rust it adds a sound MIR-based
reachability analysis that proves whether a vulnerable function is actually
callable.

It is **not** a scanner or an advisory database. It is an orchestration and
correlation layer over audited data sources: the
[`rustsec`](https://crates.io/crates/rustsec) engine for Rust (the same library
`cargo-audit` is built on) and the [OSV](https://osv.dev) database for every
other ecosystem. The trust boundary is "structured advisory data plus your own
config", never raw HTML, and it fails closed: a gap it cannot scan is never
reported clean.

## How it compares

`fleetreach` deliberately occupies a niche the popular scanners leave open:
lightweight, CLI-native, **fleet-wide** auditing.

- **vs `osv-scanner` (Google), Trivy, Grype.** Those scan one project at a time
  and answer "is *this project* vulnerable?". `fleetreach` scans many repos in
  one pass and answers the fleet question: *which single fix clears the most
  repos, and how do I sequence the work?* (the `impact` / `blast` / `packages` /
  `remediation` views). It keeps a smaller surface on purpose: no container or OS
  scanning (use Trivy/Grype for that), and no advisory database of its own.
- **vs OWASP Dependency-Track.** That is the portfolio incumbent, but it is a
  *server you operate*: stand up the platform, ingest CycloneDX SBOMs, host a
  database and a web UI. `fleetreach` is a single binary you run from CI or a
  shell against a `fleet.toml`. No server, no SBOM pipeline, no state to host.
- **For Rust specifically.** It adds a *sound* static reachability mode (a MIR
  call-graph analysis with a witness chain) that most open-source scanners lack,
  on top of a fail-closed CI contract where a falsely-clean report is treated as
  the worst possible output.

If you want container scanning, a hosted dashboard, or single-repo CI checks, the
tools above fit better. If you want one command that answers "what is my
*fleet's* dependency risk, and what do I fix first", that is what this is for.

## Installation

Install the `fleetreach` binary straight from the repository (not yet published to
crates.io):

```sh
cargo install --git https://github.com/tess-fun/fleetreach fleetreach-cli --features network   # with DB fetch + enrichment
```

The default build is **pure-Rust** (no vendored-C TLS stack): it has no network
support and expects a local advisory-db clone via `--db <PATH>`. The opt-in
`network` feature adds advisory-DB fetch and KEV/EPSS/NVD enrichment (pulling a
`rustls` TLS stack). Install with `--features network` for the usual fetch-on-run
behavior; omit it for a minimal, dependency-light, offline (`--db`) build.

Or build from source:

```sh
git clone https://github.com/tess-fun/fleetreach
cargo install --path crates/cli --features network   # omit --features network for the pure-Rust offline build
```

## Usage

```sh
fleetreach scan -c fleet.toml          # human table (default)
fleetreach scan -c fleet.toml -f json  # machine payload on stdout, clean for | jq
fleetreach scan -c fleet.toml -f sarif # SARIF 2.1.0 for GitHub code scanning
fleetreach scan -c fleet.toml -f impact      # advisories ranked by repos affected
fleetreach scan -c fleet.toml -f blast       # blast radius split direct vs transitive
fleetreach scan -c fleet.toml -f packages    # dependencies ranked by fleet reach
fleetreach scan -c fleet.toml -f fix-first   # advisories ranked by what to patch first
fleetreach scan -c fleet.toml -f remediation # the fix queue: what to bump, batched
fleetreach scan -c fleet.toml -f packages-json    # the packages rollup as JSON
fleetreach scan -c fleet.toml -f remediation-json # the fix queue as JSON
fleetreach scan --why serde            # how does `serde` get into the tree?

fleetreach scan -c fleet.toml --npm-vuln-db file://./npm-osv  # also audit npm repos
fleetreach scan -c fleet.toml --pypi-vuln-db file://./pypi-osv # also audit Python repos
fleetreach scan -c fleet.toml --packagist-vuln-db file://./packagist-osv # also audit PHP/Composer repos
fleetreach scan -c fleet.toml --rubygems-vuln-db file://./rubygems-osv # also audit Ruby repos
fleetreach scan -c fleet.toml --nuget-vuln-db file://./nuget-osv  # also audit .NET/NuGet repos
fleetreach scan -c fleet.toml --julia-vuln-db file://./julia-osv  # also audit Julia repos
fleetreach scan -c fleet.toml --swift-vuln-db file://./swift-osv  # also audit Swift repos
fleetreach scan -c fleet.toml --hex-vuln-db file://./hex-osv      # also audit Elixir/Hex repos
fleetreach scan -c fleet.toml --ghactions-vuln-db file://./gha-osv # also audit GitHub Actions pins
fleetreach scan -c fleet.toml --maven-vuln-db file://./maven-osv # also audit Java (gradle.lockfile/pom.xml)
fleetreach diff old.json new.json      # what changed between two scans
```

The `impact` view answers the fleet-scale question (*which fix clears the most
repos?*) by ranking advisories on how many of your crates they hit. The
examples below come from a ten-repo example fleet (see
[`examples/demo-fleet.toml`](examples/demo-fleet.toml)):

```
Repos  Severity      Advisory            Affected                  Title
2      medium 6.2    RUSTSEC-2020-0071   payments-api, scheduler   Potential segfault in time
1      critical 9.8  RUSTSEC-2021-0003   ingest-worker             SmallVec::insert_many overflow
1      critical 9.8  RUSTSEC-2021-0097   ls-replacement            SM2 decryption buffer overflow
1      high 8.6      RUSTSEC-2024-0013   ls-replacement            libgit2 memory corruption
1      high 7.5      RUSTSEC-2022-0013   search-svc                regex repetition DoS
```

The lead row is a *medium*, not a critical: the `time` segfault is the one
advisory present in two repos, so a single bump clears both `payments-api` and
`scheduler`. That ordering is the question single-repo tooling cannot answer.

The `blast` view keeps that same ranking but splits each advisory's reach into
**direct** vs **transitive** repos and adds a fix-path hint, because *how* you fix
it depends on the split: an advisory hitting most of its repos transitively can't be
fixed by editing those repos' manifests (you need an upstream bump or a dependency
override → `upstream`), whereas a direct one can (`manifest`). A corpus study of the
real Go ecosystem found ~3 in 4 vulnerable-dependency exposures are transitive, so a
plain affected-repo count hides the fix strategy.

```
Repos  Direct  Transitive  Fix       Severity      Advisory            Title
2      1       1           mixed     unknown       RUSTSEC-2025-0004   ssl select_next_proto UAF
1      1       0           manifest  critical 9.8  RUSTSEC-2021-0003   SmallVec::insert_many overflow
1      0       1           upstream  medium 6.2    RUSTSEC-2020-0071   Potential segfault in time
```

The `packages` view rolls those rows up one level — to the *dependency*. One package
often carries many advisories across many repos, and a single bump clears them all, so
this answers "which dependency is my biggest fleet liability?". It ranks vulnerable
dependencies by fleet reach, with the same direct/transitive split plus how many
advisories one bump would resolve:

```
Repos  Direct  Transitive  Advisories  Severity  Fix       Package
3      0       3           2           medium    upstream  time
2      1       1           7           unknown   mixed     openssl
1      1       0           1           critical  manifest  smallvec
```

Here a single `openssl` bump clears seven advisories — the rollup the per-advisory
views can't show. (`-f json` carries `dependency_kind` per occurrence, and SARIF
results gain a `dependencyKind` property, so a CI consumer gets the same signal.)

The `fix-first` view answers the complementary question (*what do I patch
first?*). It is severity-dominant: actively-exploited (KEV) findings lead, then
strict severity bands, and only *within* a band does blast radius break the tie.
That keeps a critical CVE in one repo above an unsound-but-low lint hitting
thousands — the opposite trade-off from `impact`, which would float the
wide-but-informational warning to the top.

The `remediation` view goes one step further. Where `fix-first` ranks *which
advisory*, this prints *what to do about it*: the concrete dependency bump. Each
row is **batched**, so a single `bump tokio 1.0 → 1.38` row clears every advisory
that one upgrade resolves across every repo, and breaking (semver-major) jumps are
flagged so low-churn fixes can go first. Advisories with no published fix are
called out honestly (`no fix: …`) rather than dressed up as an upgrade. When static
reachability has run (`--reachability=static`), advisories that are *soundly*
unreachable drop to an informational tail (shown, but never queued as work), so
dead-code findings never crowd out the bumps that matter.

### Tracking drift over time

`fleetreach diff <baseline.json> <current.json>` compares two saved reports (each
from `scan -f json`) and splits the findings into **new**, **fixed**, and
**still-open** — the question a single scan can't answer: *did this branch make the
fleet better or worse?* New advisories are regressions; fixed ones are wins; a
still-open advisory that shrank or grew its repo footprint shows the `±` blast-radius
drift. It is pure (no scanning, DB, or network — just two JSON files), so it drops
into CI as a cheap gate:

```
1 new, 1 fixed, 1 still open.

New (1):
  critical  RUSTSEC-2026-9999  2 (+2)  brand new critical
```

The exit code mirrors `scan`: `0` clean, `1` a *new* finding tripped the gate, `2` a
file could not be read. `--fail-on <severity>` sets the floor a new vulnerability must
reach to gate (default `low`; Unknown always counts, fail-closed), `--fail-on-warnings`
also gates on a newly introduced warning, and `--exit-zero` makes it report-only.
`-f json` emits the full structured diff for automation.

### GitHub Action

Drop findings into the Security tab and PR annotations with the bundled
composite action (see [`.github/workflows/audit-example.yml`](.github/workflows/audit-example.yml)):

```yaml
- uses: tess-fun/fleetreach@v1
  with:
    args: "--enrich --resolve-features"
```

`fleet.toml` lists the repos to scan:

```toml
[[repo]]
id   = "core-lib"
path = "../core-lib"            # repo root; Cargo.lock located within

[[repo]]
id   = "services"
path = "../services"
glob = true                     # discover **/Cargo.lock under the tree
glob_max_depth = 4              # bounded; default 3

[[repo]]
id        = "billing-api"
path      = "../billing-api"    # a go.mod repo; scanned via govulncheck
ecosystem = "go"                # optional; auto-detected from the manifests

[[repo]]
id        = "web-frontend"
path      = "../web-frontend"   # a package-lock.json repo; toolchain-free OSV match
ecosystem = "npm"               # optional; auto-detected from the manifests

[[repo]]
id        = "ml-service"
path      = "../ml-service"     # a uv.lock/poetry.lock/Pipfile.lock repo; toolchain-free
ecosystem = "pypi"              # optional; auto-detected from the manifests

[[repo]]
id        = "storefront"
path      = "../storefront"     # a composer.lock repo; toolchain-free OSV match
ecosystem = "packagist"         # optional; auto-detected from the manifests

[[repo]]
id        = "payments-dotnet"
path      = "../payments-dotnet" # a packages.lock.json repo; toolchain-free OSV match
ecosystem = "nuget"             # optional; auto-detected from the manifests

[[repo]]
id        = "sim-pipeline"
path      = "../sim-pipeline"   # a Manifest.toml repo; toolchain-free OSV match
ecosystem = "julia"             # optional; auto-detected from the manifests

[[repo]]
id        = "ios-client"
path      = "../ios-client"     # a Package.resolved repo; toolchain-free OSV match
ecosystem = "swift"             # optional; auto-detected from the manifests

[[repo]]
id        = "billing-api"
path      = "../billing-api"    # a Gemfile.lock repo; toolchain-free OSV match
ecosystem = "rubygems"          # optional; auto-detected from the manifests

[[repo]]
id        = "chat-service"
path      = "../chat-service"   # a mix.lock repo; toolchain-free OSV match
ecosystem = "hex"               # optional; auto-detected from the manifests

[[repo]]
id        = "analytics-jvm"
path      = "../analytics-jvm"  # a gradle.lockfile/pom.xml repo; toolchain-free OSV match
ecosystem = "maven"             # optional; auto-detected from the manifests

[[repo]]
id        = "ci-config"
path      = "../ci-config"      # a .github/workflows repo; scans pinned `uses:` actions
ecosystem = "githubactions"     # set explicitly to scan a package repo's workflows too

[[settings.ignore]]
id     = "RUSTSEC-2020-0071"
reason = "dev-dependency only, not in any shipped path"   # REQUIRED, non-empty
```

A repo with a `go.mod` (and no `Cargo.lock`) is scanned by `govulncheck` and folds
into the same fleet report, so a mixed Rust+Go fleet yields one unified, blast-radius
and reachability-aware remediation queue. Because govulncheck compiles the module, Go
scanning needs `--allow-untrusted-builds` and a `govulncheck` binary (`--govulncheck`,
or on `PATH`/`$GOPATH/bin`); without them a Go repo is reported as an errored gap
rather than silently skipped. A confirmed Go call site is marked `reachable` (the
analysis is sound-positive), while present-but-uncalled stays `unknown`, never a false
"not reachable".

No Go toolchain? A degraded **module-level** mode reads `go.mod` and matches each
dependency against a vuln.go.dev mirror (`--go-vuln-db=file://<mirror>`) — it compiles
nothing, so no `--allow-untrusted-builds` is needed. It is module-level only (findings
are `unknown` reachability, no symbol analysis) and can't see Go stdlib advisories, but
its matching has been validated differentially against govulncheck on real modules with
**zero false-cleans**.

Every other ecosystem is scanned the same **toolchain-free** way: `fleetreach` reads the
lockfile (the full transitive tree, already pinned to exact versions) and matches each
package against an **OSV mirror** passed as `--<ecosystem>-vuln-db=file://<path>`, pointed
at the osv.dev export `all.zip` (per ecosystem at
`https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`, read directly with
no unzip needed) or a directory of unzipped records. It runs no package manager and no
install or build scripts, so like the Go module-level mode it is safe by construction and
needs no `--allow-untrusted-builds`; without a mirror the repo is an honest errored gap,
never silently skipped. Severity comes from the GHSA band or a CVSS vector, direct versus
transitive comes from the lockfile, and findings are `unknown` reachability unless a
reachability mode runs.

| Ecosystem | Lockfile(s) | Flag | Version semantics |
|-----------|-------------|------|-------------------|
| npm | `package-lock.json` | `--npm-vuln-db` | SemVer |
| PyPI | `uv.lock` / `poetry.lock` / `Pipfile.lock` | `--pypi-vuln-db` | PEP 440 (PEP 503 names) |
| RubyGems | `Gemfile.lock` | `--rubygems-vuln-db` | `Gem::Version` |
| Packagist | `composer.lock` | `--packagist-vuln-db` | Composer `version_compare` |
| NuGet | `packages.lock.json` | `--nuget-vuln-db` | four-part `NuGetVersion` |
| Julia | `Manifest.toml` | `--julia-vuln-db` | `VersionNumber` |
| Swift | `Package.resolved` | `--swift-vuln-db` | URL-identified SemVer |
| Hex | `mix.lock` | `--hex-vuln-db` | SemVer |
| Maven | `gradle.lockfile` / `pom.xml` | `--maven-vuln-db` | `ComparableVersion` |
| GitHub Actions | `.github/workflows/*.yml` | `--ghactions-vuln-db` | tag SemVer |

A few specifics that do not fit a cell. Where an advisory enumerates affected versions
instead of a range (notably malware `MAL-` records), the matcher consults both lists. PyPI
normalizes names per PEP 503, so `Flask` and `flask` match. For GitHub Actions only
version-pinned `uses:` references are matched (e.g. the `tj-actions/changed-files`
supply-chain advisory), while SHA and branch pins are skipped as honest gaps. Each bespoke
comparator is validated differentially against the real upstream library where one exists:
the Maven comparator agrees with Apache Maven's own `ComparableVersion` over 710,000+ version
pairs, and npm/PyPI/RubyGems matching was validated at 100% recall with zero false-cleans
against the OSV exports.

A mixed-ecosystem fleet — Rust, Go, and any of the toolchain-free feeders — folds into one
unified, blast-radius-ranked remediation queue.

Key flags: `--db <PATH>` (use a local advisory-db clone), `--offline`,
`--max-db-age 7d`, `--min-severity high`, `--fail-on critical`,
`--fail-on-warnings`. See `fleetreach scan --help`.

### Prioritize by real-world risk

`--enrich` annotates each finding with **CISA KEV** (actively exploited in the
wild) and **FIRST EPSS** (exploit probability), re-ranks them into an action
queue, and adds a `Risk` column:

```
Severity      Risk      Advisory            Fix                       Title
critical 9.8  epss 88%  RUSTSEC-2021-0097   openssl-src → 111.16.0    SM2 decryption buffer overflow
high 7.5      epss 71%  RUSTSEC-2022-0014   openssl-src → 111.18.0    infinite loop in BN_mod_sqrt
high 7.4      epss 50%  RUSTSEC-2021-0098   openssl-src → 111.16.0    ASN.1 read buffer overruns
high 7.5      epss 14%  RUSTSEC-2022-0013   regex 1.5.4 → 1.5.5       regex repetition DoS
critical 9.8  epss 2%   RUSTSEC-2021-0003   smallvec 1.6.0 → 0.6.14   SmallVec::insert_many overflow
```

The two `critical 9.8`s are tied by CVSS, but EPSS breaks the tie: the openssl
overflow (88% exploit probability) rises to the top of the queue while the
smallvec one (2%) falls near the bottom. A finding that is on CISA's
known-exploited list renders as `KEV epss NN%` in the `Risk` column.

Gate on it with `--fail-on-kev` (fail if anything is actively exploited) or
`--min-epss 0.5`. Both feeds can be supplied offline via `--kev-file` /
`--epss-file`.

Every finding shows its **dependency provenance**: whether the flagged package
is a direct or transitive dependency, and the chain that pulls it in:

```
fleetreach/proc-macro-error2@2.0.1 (via fleetreach-scan → … → defmt-macros)
```

The full chain is in the JSON (`occurrences[].dependency_path`), so you can see
*who pulls a package in* without reaching for `cargo tree -i`. `--why <crate>`
asks that question across the whole fleet at once:

```
$ fleetreach scan --why serde
cli-tools — serde 1.0.228 (direct):
  ripgrep → serde
docs-builder — serde 1.0.228 (transitive):
  guide-helper → serde_json → serde
file-finder — serde 1.0.228 (transitive):
  fd-find → globset → bstr → serde
```

With **`--resolve-features`** (opt-in, needs the repo's buildable source), each
finding is also marked built vs. a phantom `Cargo.lock`-only optional dependency
that is never compiled; the table flags those with `⚠ not in default build` and
the JSON adds `occurrences[].active`. Default scans stay lockfile-only and
portable.

This repo dogfoods itself: the committed [`fleet.toml`](fleet.toml) points at the
repo root, so `fleetreach scan` from here audits fleetreach's own dependency
tree (it reports zero vulnerabilities).

## Exit codes (CI contract)

Evaluated top-down, first match wins:

| Code | Meaning |
|------|---------|
| `3`  | Usage / argument error. |
| `2`  | Could not complete a trustworthy scan: invalid config · advisory DB unloadable · DB older than `--max-db-age` · zero repos scanned · **any repo errored** (a gap means we cannot claim the fleet is clean). |
| `1`  | Trustworthy scan; a finding tripped the gate (`--fail-on`, or `--fail-on-warnings`). |
| `0`  | Trustworthy scan; nothing met the failure threshold. |

A falsely-clean report is the worst possible output, so the tool never exits `0`
unless it completed a scan it can stand behind.

## Design decisions (fail-closed)

`fleetreach` errs toward noise over silence: when it cannot *prove* something is
safe, it surfaces it rather than passing quietly.

- **Unknown-severity vulnerabilities always gate.** An advisory with no CVSS
  score is reported as `unknown` severity. It still trips `--fail-on` and still
  survives `--min-severity` filtering; we cannot prove it sits below the
  threshold, so we never silently drop it.
- **`--db-rev` requires `--db`.** Pinning the advisory DB to an exact commit
  works only against a local advisory-db git clone (`rustsec` 0.33 exposes no
  open-at-revision constructor; the pin is performed by checking out the clone).
- **`--max-db-age` refuses when age is unknown.** If the DB carries no commit
  timestamp, freshness cannot be verified, so the run exits `2` rather than
  assuming the DB is current.

## Architecture

```
cli  →  report  →  correlate  →  scan  →  core
```

Dependencies point strictly inward. `core` (the domain model and JSON wire
contract) has no in-workspace dependencies and no `rustsec` types in its public
API, so future enrichment lands as additive fields without breaking
`schema_version: 1`. `scan` is the only crate that touches `rustsec`. Every
crate forbids `unsafe` and denies the `unwrap`/`expect`/`panic` family on
externally-derived values.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full data flow and the
fail-closed spine, and [CHANGELOG.md](CHANGELOG.md) for release notes.

## Reachability

`--reachability` (bare, or `=heuristic`) is a labelled source-presence
*heuristic* that greps your source and never builds anything. For Rust it greps
for the advisory's affected function names; for the toolchain-free feeders it
greps for an import/use of each **direct** dependency — exact for npm/Julia/RubyGems
(coordinate = import name), and via a per-ecosystem name heuristic for
PyPI/NuGet/Maven/Packagist/Swift/Hex (dist→module, package-id→namespace,
group→Java-package, vendor/pkg→PSR-4, repo→Swift-module, `foo_bar`→`FooBar`). For
GitHub Actions a `uses:` reference is an active CI step (sound-positive). The
heuristic only ever *raises* a finding to reachable on a positive match — it never
marks a Tier-C finding unreachable, so a missed import can't hide a vulnerability
(and `--reachable-only` never drops one on a grep miss). All 12 ecosystems now
produce a reachability signal (Go via govulncheck; Cargo also has a sound static
mode below).

**npm import graph.** Under `--reachability`, npm uses a build-free *module import
graph* instead of the flat grep: it parses every `require`/`import` in your source
and (when `node_modules` is present) in each installed package, then reports a
vulnerable package as `Reachable` with a witness import-chain (`your-dep → … →
vuln`) — including transitive packages. `--npm-prune-unreachable` additionally
marks a package `NotReachable` when `node_modules` is present and no import path
reaches it (so `--reachable-only` drops it). That negative is best-effort sound: a
dynamic `require(expr)` or a framework autoload it can't see may make a
`NotReachable` wrong, which is why it is a separate explicit opt-in.

`--reachability=static` is a sound MIR call-graph analysis that proves whether a
vulnerable function is callable, with a witness chain.

> ⚠️ **`--reachability=static` COMPILES each scanned repo.** Building Rust runs
> the repo's (and its dependencies') `build.rs` scripts and proc-macros, i.e.
> **arbitrary code, with your full user privileges**. This is unlike the rest of
> fleetreach, which only *reads* `Cargo.lock`. Because of that it is gated behind
> an explicit `--allow-untrusted-builds` and prints a warning before any build.
> **Only point it at repositories you trust.** For untrusted code, run it inside
> a sandbox/container with no network and no secrets. It also needs the pinned
> nightly `fleetreach-reach-driver` built and passed via `--reach-driver`.

## MSRV

The minimum supported Rust version is **1.89** (driven by the dependency
closure, not just `rustsec`), verified in CI.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
