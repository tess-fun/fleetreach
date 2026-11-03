---
title: Ecosystems
description: The 12 ecosystems fleetreach scans, plus container images, the lockfiles it reads for each, where advisories come from, and the version rules it applies.
sidebar:
  order: 0
  label: Overview
---

| Ecosystem | Reads | Advisories | Version rules |
|-----------|-------|------------|---------------|
| [Rust](/fleetreach/docs/ecosystems/rust/) | `Cargo.lock` | RustSec | SemVer |
| [Go](/fleetreach/docs/ecosystems/go/) | `go.mod` (or the compiled module) | osv.dev or vuln.go.dev | Go module versions |
| [npm](/fleetreach/docs/ecosystems/npm/) | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` | osv.dev | SemVer |
| [PyPI](/fleetreach/docs/ecosystems/pypi/) | `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml`, `requirements*.txt` | osv.dev | PEP 440 |
| [RubyGems](/fleetreach/docs/ecosystems/rubygems/) | `Gemfile.lock` | osv.dev | `Gem::Version` |
| [Packagist](/fleetreach/docs/ecosystems/packagist/) | `composer.lock` | osv.dev | Composer |
| [NuGet](/fleetreach/docs/ecosystems/nuget/) | `packages.lock.json`, `project.assets.json`, `packages.config`, `*.csproj` | osv.dev | `NuGetVersion` |
| [Maven](/fleetreach/docs/ecosystems/maven/) | `gradle.lockfile`, `pom.xml` | osv.dev | `ComparableVersion` |
| [GitHub Actions](/fleetreach/docs/ecosystems/github-actions/) | `.github/workflows/*.yml` | osv.dev | tag SemVer |
| [Swift](/fleetreach/docs/ecosystems/swift/) | `Package.resolved` | osv.dev | SemVer by URL |
| [Hex](/fleetreach/docs/ecosystems/hex/) | `mix.lock` | osv.dev | SemVer |
| [Julia](/fleetreach/docs/ecosystems/julia/) | `Manifest.toml` | osv.dev | `VersionNumber` |
| [Container images](/fleetreach/docs/ecosystems/container-images/) | dpkg, apk and rpm databases in an image | osv.dev distro exports | dpkg, apk-tools, rpm |

Every ecosystem except Go with `govulncheck` is read **without a toolchain**: no package
manager, no install script, no build. That makes fleetreach safe to point at any repository.

A polyglot repo is scanned in every ecosystem it has. A repo whose ecosystem has no advisory
data is an errored gap, never clean.

## Why each has its own comparator

Each ecosystem orders versions by its own rules. Composer sorts `2.4.5-p1` above `2.4.5`,
Maven treats `1.0-final` as `1.0`, Ruby's `1.0.a` is a prerelease. A SemVer comparator
applied everywhere would misorder them and miss vulnerable versions. Each comparator here is
a port of the ecosystem's own, checked against it. See
[Accuracy and validation](/fleetreach/docs/concepts/accuracy/).

Data for every OSV-backed ecosystem lives in one cache, synced with `fleetreach db sync`.
