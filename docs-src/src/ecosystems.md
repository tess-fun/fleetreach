# Ecosystems

fleetreach covers 12 ecosystems. Rust uses the `rustsec` advisory engine; Go
uses `govulncheck` (plus a toolchain-free fallback); the other ten are
**toolchain-free** OSV feeders.

## Toolchain-free OSV feeders

Every non-Rust ecosystem is scanned the same way: fleetreach reads the lockfile
(the full transitive tree, already pinned to exact versions) and matches each
package against the osv.dev export for its ecosystem (`all.zip`, read directly).

Where the export comes from, per ecosystem:

1. `--<ecosystem>-vuln-db=file://<path>` (or its env var), if given.
2. `--osv-dir <dir>`, `FLEETREACH_OSV_DIR` or `[settings.osv] dir`: a directory laid
   out like the osv.dev bucket, `<dir>/<Ecosystem>/all.zip` (OSV-Scanner's offline
   layout too).
3. The default cache, `~/.cache/fleetreach/osv/`, which network builds keep fresh
   (re-checked every 6 hours, `[settings.osv] refresh`; turned off by `--offline` or
   `FLEETREACH_OSV_SYNC=off`).

`fleetreach db sync` fetches exports ahead of time (`--all`, `--ecosystems`, or the
ecosystems in `fleet.toml`; `--osv-dir` to build an air-gapped mirror), and
`fleetreach db status` shows what is present and how old it is. `--max-db-age` checks
every export used, from the upstream `Last-Modified` recorded at download or the file's
mtime.

It runs no package manager and no install/build scripts, so it is **safe by
construction** and needs no `--allow-untrusted-builds`. Without a mirror the repo
is an honest errored gap, never silently skipped. Severity comes from the GHSA
band or a CVSS vector; direct vs transitive comes from the lockfile; findings are
`unknown` reachability unless a reachability mode runs.

| Ecosystem | Lockfile(s) | Flag | Version semantics |
|-----------|-------------|------|-------------------|
| npm | `package-lock.json` / `pnpm-lock.yaml` (v6, v9) / `yarn.lock` (v1, berry) | `--npm-vuln-db` | SemVer |
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
