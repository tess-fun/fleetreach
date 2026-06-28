# fleetreach

**See how far every vulnerability reaches across your fleet.**

`fleetreach` audits many repositories in one pass and produces a single
deduplicated, ranked, CI-pipeable view of which dependencies carry known
advisories, plus supply-chain warnings (unmaintained, unsound, notice) and
advisories against the Rust toolchain itself. One binary, no server, no SBOM
pipeline.

It covers **12 ecosystems** (Rust, Go, npm, PyPI, RubyGems, Packagist, NuGet,
Julia, Swift, Hex, Maven, GitHub Actions), and for Rust it adds a sound
MIR-based reachability analysis that proves whether a vulnerable function is
actually callable.

## The fleet question

Single-project scanners answer *"is this repo vulnerable?"*. fleetreach answers
the question a fleet actually has: **which one fix clears the most repos, and in
what order do I work?**

That ranking falls out of correlating advisories *across* repos. One bump to a
shared dependency can clear the same advisory in many repos at once; a
transitive-only exposure needs an upstream bump rather than a manifest edit. The
report surfaces both.

## What it is, and isn't

fleetreach is **not** a scanner or an advisory database. It is an orchestration
and correlation layer over audited data sources: the
[`rustsec`](https://crates.io/crates/rustsec) engine for Rust (the same library
`cargo-audit` is built on) and the [OSV](https://osv.dev) database for every
other ecosystem. The trust boundary is "structured advisory data plus your own
config", never raw HTML.

It **fails closed**: a gap it cannot scan is never reported clean. A
falsely-clean report is the worst possible output for a security tool, so the
tool never exits `0` unless it completed a scan it can stand behind.

## How it compares

| | Scans | Answers | Reachability | Shape |
|---|---|---|---|---|
| **fleetreach** | many repos, one pass | which fix clears the most repos, ranked | sound (Rust) | single binary |
| osv-scanner · Trivy · Grype | one project | "is this project vulnerable?" | experimental / none | binary |
| OWASP Dependency-Track | a portfolio | similar, but as a platform | no | a server you run |

If you want container scanning, a hosted dashboard, or single-repo CI checks,
those tools fit better. If you want one command that answers *"what is my
fleet's dependency risk, and what do I fix first"*, that is what this is for.

Next: [install it](./installation.md), then [run your first
scan](./quickstart.md).
