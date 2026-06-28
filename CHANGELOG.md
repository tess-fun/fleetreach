# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-06-28

### Changed

- Crate `homepage` now points at the project website
  (<https://tess-fun.github.io/fleetreach/>) instead of the repository.

### Fixed

- `reach-driver`: migrated to rustc's current `EarlyBinder::bind(cx, value)` API and bumped the
  pinned nightly to `2026-06-27` (the churn canary flagged the `rustc_private` drift).
- CI: resolved first-run failures — a Linux-only sandbox compile error, cargo-deny license/wildcard
  policy, the reach-driver toolchain-component install, the cargo-rdme intra-doc-link toolchain, and
  the VEX round-trip consumer install (pinned release binaries; trivy bumped to a fetchable version).

### Added

- Project website: a hand-built landing page and an mdBook documentation site, deployed to GitHub
  Pages (<https://tess-fun.github.io/fleetreach/>).
- `scripts/release.sh` — one-command version bump, test, tag, and publish of all crates.

## [1.0.0] - 2026-06-27

### Added

- **Maven (Java) ecosystem support** (`fleetreach-maven`) — a twelfth ecosystem through the
  shared finding model. A Java repo is scanned **toolchain-free** from a **`gradle.lockfile`**
  (Gradle dependency locking — the full resolved transitive closure) or, failing that, a
  **`pom.xml`** (best-effort: direct dependencies with a literal `<version>`; a `${property}`
  or version range cannot be resolved without running Maven and is skipped). Dependencies are
  matched against an OSV mirror passed as `--maven-vuln-db=file://<path>` — either the osv.dev
  Maven export `all.zip` read directly or a directory of OSV JSON records (also via the
  `MAVENVULNDB` env var); overridable with `ecosystem = "maven"`/`"gradle"`/`"java"`.
  Coordinates `group:artifact` are matched verbatim. Versions follow Apache Maven's
  `ComparableVersion`, **not** SemVer (qualifiers order `alpha < beta < milestone < rc <
  snapshot < <release> < sp`; `ga`/`final`/`release` alias the release; integers compare as
  arbitrary precision so Jenkins-style `2646.v…` build numbers order numerically; `.X` is
  treated like `-X`), so the matcher uses a faithful `ComparableVersion` port. It runs no
  `mvn`/`gradle`, so like the other Tier-C feeders it is safe by construction and needs no
  `--allow-untrusted-builds`; without a mirror a Maven repo is an honest errored gap. The
  comparator was validated **differentially against Apache Maven's own `ComparableVersion`**:
  **710,000+ version-pair comparisons agree 100%** (the corpus surfaced and fixed the Maven 3.9
  "treat `.X` as `-X`" parsing behavior). Validated end-to-end on real `gradle.lockfile`
  (DataDog dd-trace-java) and `pom.xml` (commons-lang, guava, dubbo) files, flagging
  jackson-databind / log4j-core / commons-text advisories with zero parse errors.

- **GitHub Actions ecosystem support** (`fleetreach-ghactions`) — an eleventh ecosystem
  through the shared finding model. A repo's `.github/workflows/*.yml` (and a root
  `action.yml`) are scanned **toolchain-free**: `fleetreach` extracts every
  `uses: owner/repo@ref` reference and matches the version-tag pins against an OSV mirror
  passed as `--ghactions-vuln-db=file://<path>` — either the osv.dev GitHub Actions export
  `all.zip` read directly or a directory of OSV JSON records (also via the `GHACTIONSVULNDB`
  env var). Action identity is `owner/repo[/subpath]` (case-insensitive); a partial tag is
  padded (`v4` → `4.0.0`, as the OSV ranges treat it), while a branch (`@main`) or commit-SHA
  pin has no semantic version and is skipped as an honest gap. This catches pins to
  known-compromised actions such as the `tj-actions/changed-files` supply-chain advisory
  (everything below `46.0.1`). Auto-detected only for a workflow-only repo (a package repo is
  scanned for its package ecosystem); set `ecosystem = "githubactions"`/`"actions"`/`"gha"` to
  scan a package repo's workflows too. Validated end-to-end on real workflow files from major
  projects (rust-lang/rust, tokio, next.js, react, home-assistant, …) with zero parse errors,
  correctly flagging the tj-actions advisory and skipping SHA/branch pins.

- **Hex (Elixir/Erlang) ecosystem support** (`fleetreach-hex`) — a tenth ecosystem through
  the shared finding model. A repo with a `mix.lock` (auto-detected, or overridable with
  `ecosystem = "hex"`/`"elixir"`) is scanned **toolchain-free**: `fleetreach` reads the
  lockfile's pinned dependencies and matches each against an OSV mirror passed as
  `--hex-vuln-db=file://<path>` — either the osv.dev Hex export `all.zip` read directly or a
  directory of OSV JSON records (also via the `HEXVULNDB` env var). Hex versions are plain
  SemVer, so the shared comparator is reused; the Hex-specific part is the lockfile —
  `mix.lock` is an Elixir map literal (not JSON/TOML), so a small hand-rolled scan reads the
  `{:hex, :name, "version", …}` tuples and skips `{:git, …}`/`{:path, …}` dependencies.
  Package names are lowercase, matched verbatim. Severity comes from the GHSA band or a
  CVSS_V3 vector. It runs no `mix`/Elixir and no build, so like the other Tier-C feeders it
  is safe by construction and needs no `--allow-untrusted-builds`; without a mirror a Hex
  repo is an honest errored gap. The lockfile parser was validated against real `mix.lock`
  files from 12 well-known Elixir projects (phoenix, ecto, plug, absinthe, oban, broadway,
  …) with zero parse errors. A mixed multi-ecosystem fleet folds into one unified
  remediation queue.

- **Swift ecosystem support** (`fleetreach-swift`) — a ninth ecosystem through the shared
  finding model. A repo with a `Package.resolved` (auto-detected, or overridable with
  `ecosystem = "swift"`) is scanned **toolchain-free**: `fleetreach` reads the lockfile's
  pinned dependency graph (both the v1 and v2/v3 formats) and matches each package against an
  OSV mirror passed as `--swift-vuln-db=file://<path>` — either the osv.dev SwiftURL export
  `all.zip` read directly or a directory of OSV JSON records (also via the `SWIFTVULNDB` env
  var); the sibling `Package.swift`'s `.package(url:)` declarations mark the direct set. Swift
  versions are plain SemVer, so the shared comparator is reused; the Swift-specific part is
  **package identity by source URL** — the OSV `SwiftURL` ecosystem keys advisories on a
  normalized URL (`github.com/apple/swift-nio`), so the full clone URL from `Package.resolved`
  is normalized (scheme/`git@`/`.git`/trailing-slash stripped, lowercased) before matching.
  Severity comes from the GHSA band or a CVSS_V3 vector. It runs no `swift`/SwiftPM and no
  build, so like the other Tier-C feeders it is safe by construction and needs no
  `--allow-untrusted-builds`; without a mirror a Swift repo is an honest errored gap.
  Validated end-to-end against the SwiftPackageIndex master list: all **11,188 real package
  URLs** normalize and scan without panic, and the OSV-affected packages correctly match
  their real clone URLs. A mixed multi-ecosystem fleet folds into one unified remediation
  queue.

- **Julia ecosystem support** (`fleetreach-julia`) — an eighth ecosystem through the shared
  finding model. A repo with a `Manifest.toml` (auto-detected, or overridable with
  `ecosystem = "julia"`) is scanned **toolchain-free**: `fleetreach` reads the manifest's
  pinned dependency tree (both the v1 and v2 manifest formats) and matches each package
  against an OSV mirror passed as `--julia-vuln-db=file://<path>` — either the osv.dev Julia
  export `all.zip` read directly or a directory of OSV JSON records (also via the
  `JULIAVULNDB` env var); the sibling `Project.toml`'s `[deps]` keys mark the direct set.
  Julia's `VersionNumber` looks like SemVer but **build metadata is significant for
  ordering** (binary `_jll` packages carry a build counter such as `8.15.0+0`, and the
  majority of Julia advisory bounds key on it), which strict SemVer ignores — so the matcher
  uses a faithful `VersionNumber` comparator. Package names are case-sensitive. Severity
  comes from the GHSA band or a CVSS_V3 vector. It runs no `julia`/`Pkg` and no build, so
  like the other Tier-C feeders it is safe by construction and needs no
  `--allow-untrusted-builds`; without a mirror a Julia repo is an honest errored gap. The
  comparator was validated **differentially against Julia's own `VersionNumber`**: all
  sampled version strings parse identically and **69,483 version-pair comparisons agree
  100%**, including the JLL build-counter cases. A mixed multi-ecosystem fleet folds into one
  unified remediation queue.

- **NuGet (.NET) ecosystem support** (`fleetreach-nuget`) — a seventh ecosystem through the
  shared finding model. A repo with a `packages.lock.json` (auto-detected, or overridable
  with `ecosystem = "nuget"`/`"dotnet"`) is scanned **toolchain-free**: `fleetreach` reads
  the lockfile's pinned transitive tree (which records each package's `Direct`/`Transitive`
  type) and matches each package against an OSV mirror passed as `--nuget-vuln-db=file://<path>`
  — either the osv.dev NuGet export `all.zip` read directly or a directory of OSV JSON
  records (also via the `NUGETVULNDB` env var). Versions follow NuGet's scheme: SemVer 2.0
  with a **four-component** numeric core (`Major.Minor.Patch.Revision`) and **case-insensitive**
  prerelease labels, which the stock three-component `semver` crate cannot represent. Package
  ids are matched case-insensitively. Severity comes from the GHSA band or, when absent, a
  CVSS_V3 vector. It runs no `dotnet`/`nuget` and no build, so like the other Tier-C feeders
  it is safe by construction and needs no `--allow-untrusted-builds`; without a mirror a
  NuGet repo is an honest errored gap. The comparator was validated **differentially against
  .NET's own `NuGet.Versioning` library**: 21,537/21,537 version strings parse identically
  and **167,539 version-pair comparisons agree 100%**, drawn from the OSV NuGet data plus the
  top-600 packages on nuget.org. A mixed Rust + Go + npm + PyPI + RubyGems + Packagist +
  NuGet fleet folds into one unified remediation queue.

- **Packagist (Composer/PHP) ecosystem support** (`fleetreach-packagist`) — a sixth
  ecosystem through the shared finding model. A repo with a `composer.lock` (auto-detected,
  and overridable with `ecosystem = "packagist"`/`"composer"`/`"php"`) is scanned
  **toolchain-free**: `fleetreach` reads the lockfile's pinned transitive tree (the sibling
  `composer.json`'s `require`/`require-dev` mark which deps are direct) and matches each
  package against an OSV mirror passed as `--packagist-vuln-db=file://<path>` — either the
  osv.dev Packagist export `all.zip` read directly or a directory of OSV JSON records (also
  via the `PACKAGISTVULNDB` env var). Versions are compared with PHP's `version_compare`
  semantics, **not** SemVer: the stability ladder is `dev < alpha < beta < RC < <stable> <
  patch`, so `alpha`/`beta`/`RC` prereleases sort below their release but a `patch` level
  (`2.4.5-p1`, Magento's scheme) sorts **above** it — a SemVer comparator would mis-order
  every `-pN` version. Package names are Composer's case-insensitive `vendor/name`.
  Severity comes from the GHSA band or, when absent, a CVSS_V3 vector (which also yields a
  base score). It runs no `composer`/`php` and no build, so like the Go/npm/PyPI/RubyGems
  Tier-C modes it is safe by construction and needs no `--allow-untrusted-builds`; without a
  mirror a Packagist repo is an honest errored gap. The comparator was validated
  **differentially against the real `composer/semver` library** on 185,537 version pairs
  drawn from the 3,000 most-installed packages (**100% agreement**, after the corpus
  surfaced and fixed three faithfulness gaps: `+build` metadata is ignored, the numeric core
  is normalized to four components before the stability tail, and a bare `>=X` bound includes
  the prereleases of `X` — Composer's `-dev` floor, which a plain `>=` would false-clean for
  a prerelease pinned at an `introduced` boundary). End-to-end it scanned a 2,996-repo
  corpus of generated `composer.lock` files with **100% recall and 100% precision** against
  `composer/semver` (0 false-cleans, 0 false-positives, 0 panics), including the Magento
  `2.4.8-p1` patch-level case correctly flagged in the `[2.4.8-beta1, 2.4.8-p2)` window. A
  mixed Rust + Go + npm + PyPI + RubyGems + Packagist fleet folds into one unified
  remediation queue.

- **RubyGems (Ruby) ecosystem support** (`fleetreach-rubygems`) — a fifth ecosystem through
  the shared finding model. A repo with a `Gemfile.lock` (auto-detected, and overridable with
  `ecosystem = "rubygems"`/`"ruby"`) is read for its pinned transitive tree and matched against
  an OSV mirror passed as `--rubygems-vuln-db=file://<path>` — either the osv.dev RubyGems
  export `all.zip` read directly or a directory of OSV JSON records (also via the
  `RUBYGEMSVULNDB` env var). Versions are compared as `Gem::Version`, **not** SemVer: any
  letter segment is a prerelease, segments are arbitrary-length, and trailing zeros are
  insignificant (a faithful port of modern RubyGems' `canonical_segments`). Gem names are
  matched verbatim (case-sensitive, unnormalized), and only rubygems.org sources are matched
  (`GIT`/`PATH` and private-registry pins are skipped). Because RubyGems advisories often
  enumerate affected versions instead of a range, the matcher consults both. Severity comes
  from the GHSA band or a CVSS_V3 vector (which also yields a base score). It runs no
  `bundler`/`gem` and no build, so like the Go/npm/PyPI Tier-C modes it is safe by
  construction and needs no `--allow-untrusted-builds`; without a mirror a RubyGems repo is an
  honest errored gap. Validated against the osv.dev RubyGems export with **100% recall and
  100% precision** (2,775 sampled advisories) and differentially against real Ruby's
  `Gem::Version` (405,924 version pairs, zero disagreements with the modern canonical
  algorithm).

- **PyPI (Python) ecosystem support** (`fleetreach-pypi`) — a fourth ecosystem through
  the shared finding model. A repo with a `uv.lock`, `poetry.lock`, or `Pipfile.lock`
  (auto-detected in that order, and overridable with `ecosystem = "pypi"`/`"python"`) is
  scanned **toolchain-free**: `fleetreach` reads the lockfile's pinned transitive tree and
  matches each package against an OSV mirror passed as `--pypi-vuln-db=file://<path>` —
  either the osv.dev PyPI export `all.zip` read directly or a directory of OSV JSON
  records (also via the `PYPIVULNDB` env var). Versions are compared as **PEP 440**
  (epochs, `.post`/`.dev`, pre-releases) and names matched after **PEP 503**
  normalization. Because PyPI advisories frequently enumerate affected versions instead
  of a range (notably the `MAL-` malware records), the matcher consults both the
  `ECOSYSTEM` ranges and the explicit `versions` list. Severity comes from the GHSA band
  or, when absent, a CVSS_V3 vector (which also yields a base score). It runs no
  `pip`/`poetry`/`uv` and no build, so like the Go/npm Tier-C modes it is safe by
  construction and needs no `--allow-untrusted-builds`; without a mirror a PyPI repo is an
  honest errored gap. Validated against the OSV PyPI export with **100% recall / zero
  false-cleans** on 3,000 sampled advisories and 100% precision at the fix boundary, and
  end-to-end against real `uv`/`poetry`/`pipenv` lockfiles. A mixed Rust + Go + npm + PyPI
  fleet folds into one unified remediation queue.

### Changed

- The shared OSV range matcher (`fleetreach_core::osv`) is now generic over the version
  type, so the Go/npm SemVer feeders and the new PyPI PEP 440 feeder share one
  event-walking skeleton (the place where a missed case is a false-clean). Behavior for
  Go and npm is unchanged.

## [1.0.0] - 2026-06-27

First stable release. Fleet-wide, reachability-aware dependency advisory auditing across
three ecosystems (Cargo, Go, npm) through one agnostic core, with a fail-closed spine
(an unreadable repo is an honest gap, never a clean scan) and ten output views plus a
`diff` subcommand for tracking drift.

### Added

- **npm ecosystem support** (`fleetreach-npm`) — a third ecosystem through the shared
  finding model. A repo with a `package-lock.json` (and no `Cargo.lock`/`go.mod`) is
  scanned **toolchain-free**: `fleetreach` reads the lockfile (the full transitive tree,
  already pinned to exact versions) and matches each package against an OSV mirror passed
  as `--npm-vuln-db=file://<path>` — either the osv.dev npm export `all.zip` read
  directly (one file, ~3x faster than the unzipped directory and no unzip step) or a
  directory of OSV JSON records. It runs no `npm` and no install scripts, so like the Go
  Tier-C mode it is safe by construction and needs no `--allow-untrusted-builds`. Supports
  lockfileVersion 1/2/3; findings carry the GitHub Advisory Database severity band (so
  they rank and gate like Rust ones) at `unknown` reachability, with direct/transitive
  from the lockfile. Without a mirror an npm repo is an honest errored gap, never
  silently skipped. A mixed Rust + Go + npm fleet folds into one unified remediation
  queue. Falls back to the `NPMVULNDB` env var.
- **`fleetreach diff <baseline.json> <current.json>`** — a first-class subcommand
  that compares two saved JSON reports and splits findings into **new**, **fixed**,
  and **still-open**, with each surviving advisory's blast-radius drift (`±repos`).
  Answers "did this branch make the fleet better or worse?" — a question a single
  scan can't. Pure (no scanning, DB, or network), so it's a cheap CI gate: exit `1`
  when a *new* finding trips `--fail-on <severity>` (default `low`; Unknown fails
  closed), `--fail-on-warnings` to also gate new warnings, `--exit-zero` for
  report-only. `-f json` emits the structured diff (`new`/`fixed`/`still_open` with
  `repos_added`/`repos_removed`). Generalizes the scan `--baseline` flag, which only
  keeps new findings from a live scan and never reports what was fixed.
- **`-f blast`** — a blast-radius view that splits each advisory's affected-repo
  count into **direct** vs **transitive** reach and prints a fix-path hint
  (`manifest` if every affected repo depends on it directly, `upstream` if every
  exposure is transitive, else `mixed`). Same ranking as `-f impact`; the split tells
  you *how* to fix, not just how wide. Motivated by a corpus study: across a real
  ecosystem the large majority of vulnerable-dependency exposures are transitive,
  which a plain affected count hides.
- **`-f packages`** — a package-impact rollup: vulnerable *dependencies* ranked by
  fleet reach, each row carrying its direct/transitive split and the number of
  advisories one bump would resolve. Answers "which dependency is my biggest
  liability?" (e.g. a single `openssl` bump clearing seven advisories shows as one
  row). Also available programmatically as `to_packages_json`.
- **`-f packages-json` / `-f remediation-json`** — the package-impact rollup and the
  remediation fix queue as JSON, so automation can consume those views from the binary
  (previously library-only). The full `-f json` payload is unchanged.
- **SARIF `dependencyKind`** — each SARIF result now carries a `properties.dependencyKind`
  (`direct`/`transitive`), giving CI security tooling the same fix-path signal as
  `-f blast` without parsing message text (`-f json` already exposes it per occurrence).
- **Affected functions** — when an advisory scopes itself to specific
  functions/types (vulnerable *at the installed version*), they are surfaced:
  `affected_functions` in JSON, an `affects fn:` line in the table, and a
  `functions:` line in `--explain`. Turns "crate X has a bug" into "...in *these*
  functions — do you call any?".
- **`--reachability`** (heuristic, opt-in) — greps your repos' source for those
  function names: `in source` / `not found` (a `Reach` column + `reachable` in
  JSON). It only scans *your* code, so a `not found` never proves the vuln is
  unreachable — it's a hint. `--reachable-only` drops the not-found ones
  (fail-closed: unknown is always kept). Not static call-graph analysis.
- **Fleet impact view (`-f impact`)** — the cross-repo angle only a fleet tool
  can show: advisories ranked by how many repos they hit (`RUSTSEC-X — 12 repos`),
  so you can see which fix clears the most repos. KEV is flagged inline.
- **Fix-first view (`-f fix-first`)** — the remediation queue: a severity-dominant
  ranking (KEV, then severity band, then blast radius) so real CVEs stay above
  high-spread informational warnings. The `#` column is the fix order; the
  `Exploit` column surfaces KEV/EPSS. The complement to `-f impact`.
- **Go ecosystem scanning (mixed fleets)**: a `fleet.toml` repo with a `go.mod`
  (and no `Cargo.lock`) is scanned by `govulncheck`, and its findings flow through
  the *same* correlate / rank / remediation pipeline as Rust crates, so a mixed
  Rust+Go fleet produces one unified, reachability-aware fix queue. Ecosystem is
  auto-detected (Rust-first: a `Cargo.lock` wins) or set explicitly with
  `ecosystem = "go"` per `[[repo]]`. Reachability is the mirror of the Rust engine:
  govulncheck is sound-positive, so a confirmed call is `Reachable` (the queue can
  trust it), but present-but-uncalled is `Unknown`, never a false "not reachable".
  Go scanning runs `govulncheck` (which compiles the module), so it requires
  `--allow-untrusted-builds` and a `govulncheck` binary (`--govulncheck`, or found
  on `PATH`/`$GOPATH/bin`); without them a Go repo is an honest errored gap, never
  silently skipped. Go advisories carry CVE/GHSA aliases, so `--enrich` backfills
  their severity / KEV / EPSS too.
- **Go toolchain-free scanning (Tier-C)**: when no `govulncheck` is available (no
  `--allow-untrusted-builds`, or no binary), a Go repo is still scanned by matching
  its `go.mod` module versions against an OSV DB mirror (`--go-vuln-db=file://<mirror>`)
  directly. This compiles nothing, so it needs **no untrusted-build consent** — it
  reads files and compares versions. Module-level only (`Unknown` reachability, engine
  `fleetreach-tier-c`), and it feeds the same pipeline + `--enrich`. Direct/transitive
  is read from `go.mod`. Without a mirror, no-toolchain stays an honest errored gap.
- **Go direct vs. transitive** dependency classification, read deterministically from
  `go.mod` (`require` without `// indirect` is direct), so Go findings distinguish
  direct from transitive the way Cargo ones do.
- **Source-aware VEX subcomponent PURLs**: a non-crates.io dependency (a git or
  alternate-registry source) is a different artifact than the registry crate of the
  same `name@version`, so its `-f vex` subcomponent PURL now carries the source as a
  qualifier (`?vcs_url=git+<url>@<rev>` / `?repository_url=<index>`). crates.io and
  local-path deps keep the bare `pkg:cargo/name@version` PURL, byte-identical to before,
  so the validated registry-suppression path is unchanged. (Consumer matching on the
  qualifiers is not yet validated against Grype/Trivy; it only adds precision for the
  rare non-registry case.)
- **Remediation view (`-f remediation`)**: the actionable fix queue. Where
  `fix-first` ranks *which advisory*, this prints *what to do*: the concrete
  dependency bump, **batched** so one row (`bump tokio 1.0 → 1.38`) clears every
  advisory that single upgrade resolves across every repo. Breaking (semver-major)
  jumps are flagged; the upgrade target never recommends a downgrade even when the
  advisory's safe set spans an older line; no-fix advisories are called out
  honestly. Ordering is severity-dominant, and within a severity band a
  *confirmed-reachable* batch leads before blast radius breaks the tie (decisive
  for Go, whose advisories carry no CVSS). When `--reachability=static` has run,
  *soundly* unreachable advisories drop to an informational tail (shown, never
  queued). The same data is available as JSON via
  `fleetreach_report::to_remediation_json`.
- **SARIF output + GitHub Action** — `-f sarif` emits SARIF 2.1.0 (rule per
  advisory, result per occurrence, `security-severity` for GitHub's badge, fix
  hint in the message). A composite `action.yml` installs fleetreach, scans, and
  uploads to GitHub code scanning, so findings land in the Security tab and on
  PRs. See `.github/workflows/audit-example.yml`.
- **Fix targets & `--why`** — each finding's location now shows the upgrade
  target inline (`foo@1.1.9 → 1.2.3`), the lower bound of the patched range — the
  exact `cargo update -p foo --precise 1.2.3`. `fleetreach scan --why <pkg>`
  prints how a package (any package, not just an advisory'd one) enters each
  repo's dependency tree, then exits.
- **Exploit-risk enrichment (`--enrich`)** — annotate findings with CISA KEV
  (actively exploited in the wild) and FIRST EPSS (exploit probability), matched
  by CVE alias. Findings re-rank into an action queue (KEV first, then EPSS), the
  table gains a `Risk` column (`KEV epss 87%`), and the JSON adds inline `kev` /
  `epss`. New gates: `--fail-on-kev` and `--min-epss <P>`. Offline via
  `--kev-file` / `--epss-file`. Opt-in; default scans stay offline-capable.

- **Dependency provenance** — each in-repo finding now records the chain from a
  root crate down to the flagged package (`dependency_path` in JSON), and an
  accurate `direct`/`transitive` classification. The table shows a triage hint
  (`(direct)` or `(via … → parent)`) so you can see *who pulls a package in*
  without reaching for `cargo tree -i`. The field is additive and omitted when
  empty, so `schema_version: 1` consumers are unaffected.
- **`--resolve-features`** (opt-in) — for repos with buildable source, marks each
  finding as actually built or a phantom `Cargo.lock`-only optional dependency
  (off-by-default feature, never compiled), via a feature-aware `cargo tree`. The
  table flags phantoms with `⚠ not in default build`; the JSON adds
  `occurrences[].active`. Default scans stay lockfile-only and portable.
- **`--ignore-phantom`** (opt-in, implies `--resolve-features`) — suppresses
  findings whose packages are never compiled, so CI doesn't gate on optional deps
  that aren't in the build. The count suppressed is reported on stderr;
  unknown-build-status findings are always kept (fail-closed).

## [0.1.0] - 2026-06-24

Initial release. Fleet-wide Rust dependency advisory audit built on `rustsec`.

### Added

- **Fleet scanning** — `fleetreach scan` reads a `fleet.toml`, scans each repo's
  `Cargo.lock` (with bounded-depth `glob` discovery for monorepos), and reports
  vulnerabilities and supply-chain warnings as separate streams.
- **Cross-repo correlation** — findings are deduplicated across the fleet by
  canonical RUSTSEC id, with a per-occurrence verdict (the same advisory can be
  patched in one repo and not another).
- **Toolchain advisories** — `rustsec`'s `rust` collection is matched against the
  installed toolchain.
- **Output** — human table (default, with severity color on a TTY) and machine
  JSON (`-f json`, `schema_version: 1`), with payload on stdout and the summary
  on stderr. Color is never emitted in JSON or piped output.
- **CI contract** — exit codes `0`/`1`/`2`/`3` with a fail-closed precedence: any
  un-scannable repo, stale DB, or invalid config exits `2`, never `0`.
- **Determinism** — `--db`/`--offline`/`--max-db-age`; byte-identical JSON across
  runs (the clock is injected via provenance).
- **Inspection & diffing** — `--explain <ID>` dumps one advisory; `--baseline`
  surfaces only findings new since a prior report.
- **Provenance** — every report records tool/rustsec versions, DB commit and
  timestamp, host OS/arch, and generation time.

### Security / engineering

- `#![forbid(unsafe_code)]` and a denied `unwrap`/`expect`/`panic` family on
  externally-derived values, workspace-wide.
- `proptest` over the correlation engine and the assemble pipeline; `cargo-fuzz`
  targets on the two untrusted-byte surfaces (`fleet.toml`, lockfile content);
  black-box tests over the compiled binary's exit-code and stream contract.

[Unreleased]: https://github.com/tess-fun/fleetreach/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tess-fun/fleetreach/releases/tag/v0.1.0
