<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/fleetreach-logo-inverse.svg">
    <img alt="fleetreach" src="assets/brand/fleetreach-logo.svg" height="48">
  </picture>
</h1>

[![crates.io](https://img.shields.io/crates/v/fleetreach-cli.svg)](https://crates.io/crates/fleetreach-cli)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.97-blue)](#license)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

**Dependency risk for everything you ship.** fleetreach reads every repository and
container image you own, across 12 ecosystems and 20+ Linux distributions. It ranks what to
fix by exploitation, reachability and exposure, opens the verified fix, and writes the SBOM,
VEX and SLA evidence that shows it was done. One binary, offline, no server, and never a
false clean.

**[Documentation](https://tess-fun.github.io/fleetreach/)** ·
[Install](https://tess-fun.github.io/fleetreach/docs/getting-started/installation/) ·
[First scan](https://tess-fun.github.io/fleetreach/docs/getting-started/first-scan/) ·
[Guides](https://tess-fun.github.io/fleetreach/docs/guides/find-the-fix-that-clears-the-most-repos/) ·
[Compare](https://tess-fun.github.io/fleetreach/compare/osv-scanner/) ·
[Changelog](CHANGELOG.md)

A real run on a demo fleet of nine services in six languages: 211 findings become 38 bumps,
ranked by CISA KEV, EPSS and each repo's exposure, and 2 of them are for today:

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
cargo install fleetreach-cli --features network,serve
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

- **Inventory.** Lockfiles in 12 ecosystems, container images on 20+ distributions, Go and
  Rust binaries, jars and gems inside images, and SBOMs from other tools. Lists repos from
  GitHub, GitLab, Gitea, Forgejo, Bitbucket and Azure DevOps.
- **Detect.** OSV, RustSec, vendor feeds and Red Hat and SUSE CSAF VEX, known malware, and
  supply-chain signals: install scripts, typosquats, tag-pinned actions, brand-new releases,
  deprecated or abandoned packages, and what a new version can do that the last could not.
- **Prioritise.** CISA KEV, EPSS, public exploits and SSVC decisions from each repo's
  exposure. Import chains from your own code in eight ecosystems, and call graphs for Rust,
  Java and .NET that can set aside what is never called.
- **Fix.** A batched queue (one bump per package that clears every advisory it has, in
  every repo), `whatif` to see what a bump clears and adds before any edit, and `fix apply`
  pull requests on six forges, each re-scanned before it is pushed.
- **Decide.** Triage decisions as files in git; VEX read from OpenVEX, CycloneDX, CSAF and
  signed OCI attestations, and written back in forms Trivy and Grype honour.
- **Prove.** CycloneDX 1.7, SPDX 2.3 and SPDX 3 SBOMs with NTIA checks, license policy and
  NOTICE files, SARIF, and a coverage record that names anything that was not read.
- **Operate.** History with no database, SLAs that never reset, time to fix, drift between
  scans, pull-request gates on what a change adds, Slack and webhook notifications, one issue
  per owner, an HTML report and a local triage UI (`fleetreach serve`).

Use cases with real output: [vulnerability programs](https://tess-fun.github.io/fleetreach/use-cases/platform-security-teams/),
[cutting alert noise](https://tess-fun.github.io/fleetreach/use-cases/reduce-alert-noise/),
[container images](https://tess-fun.github.io/fleetreach/use-cases/container-images/),
[pull-request gates](https://tess-fun.github.io/fleetreach/use-cases/pull-request-gate/),
[incident response](https://tess-fun.github.io/fleetreach/use-cases/incident-response/),
[compliance evidence](https://tess-fun.github.io/fleetreach/use-cases/compliance-and-sboms/),
[audits](https://tess-fun.github.io/fleetreach/use-cases/consultancies-and-audits/) and
[open-source maintainers](https://tess-fun.github.io/fleetreach/use-cases/open-source-maintainers/).

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
| Container images | `docker save` and OCI archives, root filesystems, `docker://` registries: dpkg, apk and rpm packages and the language packages inside |

Each ecosystem uses a port of its own version comparator, checked against the real one
(Maven's over 710,000 version pairs, and dpkg, apk-tools and rpm over 1.7 million), and
the Maven resolver matches real Maven on 3,555 of 3,555 packages from 14 real repositories. Nothing is built and no package code runs, so it is
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

osv-scanner, Trivy and Grype answer "is this project vulnerable?" one target at a time.
Dependabot and Renovate keep each repo
current. Dependency-Track is a server you feed SBOMs. fleetreach reads all your repositories
and images directly and answers fleet questions, and works alongside each of them (it writes the SBOMs
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
[MIT license](LICENSE-MIT) at your option. MSRV is Rust 1.97.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
