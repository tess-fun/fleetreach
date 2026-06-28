# Ecosystems

fleetreach covers 12 ecosystems. Rust uses the `rustsec` advisory engine; Go
uses `govulncheck` (plus a toolchain-free fallback); the other ten are
**toolchain-free** OSV feeders.

## Toolchain-free OSV feeders

Every non-Rust ecosystem is scanned the same way: fleetreach reads the lockfile
(the full transitive tree, already pinned to exact versions) and matches each
package against an **OSV mirror** passed as `--<ecosystem>-vuln-db=file://<path>`
— point it at the osv.dev export `all.zip` (read directly, no unzip needed) or a
directory of unzipped records.

It runs no package manager and no install/build scripts, so it is **safe by
construction** and needs no `--allow-untrusted-builds`. Without a mirror the repo
is an honest errored gap, never silently skipped. Severity comes from the GHSA
band or a CVSS vector; direct vs transitive comes from the lockfile; findings are
`unknown` reachability unless a reachability mode runs.

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

The osv.dev exports live at
`https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`.

## Why bespoke comparators

Each ecosystem orders versions by its own rules, and a stock SemVer comparator
would mis-order most of them and silently false-clean. So each feeder ships a
faithful port of the ecosystem's real comparator, validated differentially
against the upstream library where one exists — for example the Maven comparator
agrees with Apache Maven's own `ComparableVersion` over 710,000+ version pairs,
and npm/PyPI/RubyGems matching was validated at 100% recall with zero
false-cleans against the OSV exports.

A few specifics: where an advisory enumerates affected versions instead of a
range (notably malware `MAL-` records), the matcher consults both; PyPI
normalizes names per PEP 503 so `Flask` and `flask` match; and for GitHub Actions
only version-pinned `uses:` references are matched (e.g. the
`tj-actions/changed-files` supply-chain advisory), while SHA and branch pins are
skipped as honest gaps.
