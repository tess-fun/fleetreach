<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/fleetreach-logo-inverse.svg">
    <img alt="fleetreach" src="assets/brand/fleetreach-logo.svg" height="48">
  </picture>
</h1>

[![crates.io](https://img.shields.io/crates/v/fleetreach-cli.svg)](https://crates.io/crates/fleetreach-cli)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#license)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

**Fleet-wide dependency security audit.** fleetreach scans every repository in your
organisation in one run, across 12 ecosystems, and tells you which fix clears the most of
them, who owns it, and what changed since the last run. One binary, no server, and never a
false clean.

**[Documentation](https://tess-fun.github.io/fleetreach/)** ·
[Install](https://tess-fun.github.io/fleetreach/docs/getting-started/installation/) ·
[First scan](https://tess-fun.github.io/fleetreach/docs/getting-started/first-scan/) ·
[Guides](https://tess-fun.github.io/fleetreach/docs/guides/find-the-fix-that-clears-the-most-repos/) ·
[Compare](https://tess-fun.github.io/fleetreach/compare/osv-scanner/) ·
[Changelog](CHANGELOG.md)

A real run on a demo fleet of nine services in six languages, with CISA KEV and EPSS:

<!-- run: fleetreach scan -f remediation --enrich | head -n 9 -->
```console
$ fleetreach scan -f remediation --enrich | head -n 9
┌────┬──────────────┬───────────────────────────────────────────────────────────────────┬───────────────┬─────────────────────┬───────┬─────────┬───────────────┬────────────────────────┐
│ #  ┆ SSVC         ┆ Action                                                            ┆ Severity      ┆ Resolves            ┆ Repos ┆ Reach   ┆ Exploit       ┆ Bump risk              │
╞════╪══════════════╪═══════════════════════════════════════════════════════════════════╪═══════════════╪═════════════════════╪═══════╪═════════╪═══════════════╪════════════════════════╡
│ 1  ┆ immediate    ┆ bump org.apache.logging.log4j:log4j-core 2.14.1 → 2.25.4          ┆ critical 10.0 ┆ 8 advisories        ┆ 1     ┆ unknown ┆ KEV EPSS 100% ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2  ┆ out-of-cycle ┆ bump tj-actions/changed-files 44.0.0 → 46.0.1 (breaking)          ┆ high 8.6      ┆ GHSA-mrrh-fwg8-r2c3 ┆ 1     ┆ unknown ┆ KEV EPSS 72%  ┆ high                   │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 3  ┆ out-of-cycle ┆ bump smallvec 1.6.0 → 1.6.1                                       ┆ critical 9.8  ┆ RUSTSEC-2021-0003   ┆ 1     ┆ unknown ┆ EPSS 2%       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/tess-fun/fleetreach/main/scripts/install.sh | sh
brew install tess-fun/tap/fleetreach
cargo install fleetreach-cli --features network
```

Prebuilt binaries for Linux, macOS and Windows with checksums and attestations, and a
container image. See [Installation](https://tess-fun.github.io/fleetreach/docs/getting-started/installation/).

## Quick start

```toml
# fleet.toml: local checkouts, or a whole GitHub or GitLab org
[[repo]]
id   = "payments-api"
path = "../payments-api"

[[source]]
kind = "github"
org  = "acme"
```

```sh
fleetreach scan                      # every finding, every repo
fleetreach scan -f packages          # which bump clears the most repos
fleetreach scan --enrich -f ssvc     # act now, or schedule it?
fleetreach scan --why lodash         # every repo that has it, and the chain that pulls it in
```

Exit codes are the CI contract: `0` clean, `1` findings, `2` something could not be read.

## What it does

- **Ranks fixes across the fleet.** Impact, blast radius (direct vs transitive) and a
  batched fix queue: one bump per package that clears every advisory it has, with a bump
  risk taken from what the fleet already runs.
- **Prioritises by real risk.** CISA KEV, FIRST EPSS, and CISA/CERT SSVC decisions from each
  repo's exposure and impact.
- **Opens verified fixes.** `fix plan` and `fix apply` make lock-only bumps on branches,
  re-scan each one, and open pull or merge requests on GitHub or GitLab.
- **Tracks it over time.** History with no database, SLAs, time to fix, notifications to
  Slack or webhooks, one issue per owner, and a static HTML report.
- **Produces the evidence.** CycloneDX 1.7 and SPDX 2.3 SBOMs, OpenVEX, SARIF for GitHub code
  scanning, and license policy checks.
- **Proves reachability.** Import-graph witness chains for npm and Python, and a sound MIR
  call-graph analysis for Rust.
- **Flags supply-chain risk.** Install scripts, git dependencies, tag-pinned actions,
  typosquats, brand-new releases and known malware.

## Ecosystems

| | Reads |
|---|---|
| Rust | `Cargo.lock` (RustSec) |
| Go | `go.mod` (osv.dev, or `govulncheck`) |
| npm | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` |
| Python | `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml`, `requirements*.txt` |
| Java | `gradle.lockfile`, `pom.xml` (resolved like Maven, without Maven), Gradle builds and version catalogs (read, not run) |
| Ruby, PHP, .NET | `Gemfile.lock`, `composer.lock`, NuGet lock and project files |
| GitHub Actions | `.github/workflows/*.yml` |
| Swift, Elixir, Julia | `Package.resolved`, `mix.lock`, `Manifest.toml` |

Each ecosystem uses a port of its own version comparator, checked against the real one
(Maven's over 710,000 version pairs). Nothing is built and no package code runs, so it is
safe to point at any repository. See
[Ecosystems](https://tess-fun.github.io/fleetreach/docs/ecosystems/) and
[Accuracy](https://tess-fun.github.io/fleetreach/docs/concepts/accuracy/).

## In CI

```yaml
- uses: actions/checkout@v4
- uses: tess-fun/fleetreach@v1
  with:
    args: "--enrich --fail-on-kev"
```

Findings go to the GitHub Security tab as SARIF. For a whole org, run one scheduled job over
a `[[source]]`: see [GitHub Actions](https://tess-fun.github.io/fleetreach/docs/integrations/github-actions/)
and [GitLab CI](https://tess-fun.github.io/fleetreach/docs/integrations/gitlab-ci/).

## How it compares

osv-scanner, Trivy and Grype answer "is this project vulnerable?" one target at a time, and
also scan container images, which fleetreach does not. Dependabot and Renovate keep each repo
current. Dependency-Track is a server you feed SBOMs. fleetreach reads all your repositories
directly and answers fleet questions, and works alongside each of them (it writes the SBOMs
for Dependency-Track and the OpenVEX that Trivy and Grype read).
[Detailed, dated comparisons](https://tess-fun.github.io/fleetreach/compare/osv-scanner/).

## Design

- **Fails closed.** A repo it cannot read is an error, a partly read source is labelled, and
  exit code `2` means "not complete". A false clean is the worst output a security tool can
  give.
- **Reads, never runs.** Lockfiles and manifests only. The two features that compile code
  (`--reachability=static`, Go's `govulncheck`) need `--allow-untrusted-builds`.
- **No server, no lock-in.** Files in, files out: JSON, SARIF, OpenVEX, CycloneDX, SPDX, HTML.
- **Audited data.** RustSec and OSV, plus KEV, EPSS and Vulnrichment. Works offline.

The workspace is pure Rust with `unsafe` forbidden; see [ARCHITECTURE.md](ARCHITECTURE.md).

## For AI agents

The documentation is published as [`llms.txt`](https://tess-fun.github.io/fleetreach/llms.txt)
and [`llms-full.txt`](https://tess-fun.github.io/fleetreach/llms-full.txt), with a Markdown
copy of every page. `fleetreach scan -f json` and `remediation-json` are stable inputs for
agents that triage or fix dependencies.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The website lives in [`website/`](website/), and its
examples are real output regenerated by `npm run examples`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. MSRV is Rust 1.89.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
