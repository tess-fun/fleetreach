---
title: fleetreach scan
description: "fleetreach scan: Scan the fleet for advisories. Every flag, from the binary's help."
sidebar:
  order: 1
---

Scan the fleet for advisories

```text
Scan the fleet for advisories

Usage: fleetreach scan [OPTIONS]

Options:
  -c, --config <CONFIG>
          The fleet config [default: ./fleet.toml; without one, the current repo is scanned as a one-repo fleet, or with only `--image`, just the images]

      --repo <DIR>
          Scan only this directory as a one-repo fleet, without a fleet.toml

  -f, --format <FORMAT>
          Possible values:
          - table
          - json
          - sarif:            SARIF 2.1.0 for GitHub code scanning
          - impact:           Blast-radius view: advisories ranked by repos affected
          - blast:            Blast view: blast radius split into direct vs transitive reach, with a fix-path hint (manifest / upstream / mixed)
          - packages:         Package-impact view: vulnerable dependencies ranked by fleet reach (which one bump clears the most), with the direct/transitive split and advisory count
          - packages-json:    The package-impact rollup as JSON (the `packages` view, machine-readable)
          - fix-first:        Fix-first view: advisories ranked by remediation priority (KEV, then severity, then blast radius)
          - remediation:      Remediation view: the actionable fix queue — batched dependency bumps, reachability-gated, fix-first-ordered
          - remediation-json: The remediation fix queue as JSON (the `remediation` view, machine-readable)
          - vex:              OpenVEX 0.2.0 suppression document (§14)
          - ssvc:             SSVC view: findings grouped by deployer decision (immediate → defer), each with its decision vector. Needs repo context in fleet.toml and --enrich
          - owners:           Owners view: the remediation queue split by each repo's `owner`
          
          [default: table]

      --db <DB>
          use a local advisory-db clone instead of fetching

      --db-rev <DB_REV>
          pin advisory DB to an exact commit (requires --db)

      --offline
          never fetch; require cache/--db

      --max-db-age <MAX_DB_AGE>
          exit 2 if the usable DB is older than DUR, e.g. 7d

      --min-severity <MIN_SEVERITY>
          report only at/above this severity
          
          [possible values: low, medium, high, critical]

      --fail-on <FAIL_ON>
          fail if any vuln at/above [default: low, or off when --fail-on-ssvc is given alone]
          
          [possible values: low, medium, high, critical]

      --fail-on-warnings
          also fail if any warning is present

      --signals
          add supply-chain signals as warnings: install scripts, non-registry sources, unexpected registries, missing checksums, third-party GitHub Actions on movable tags

      --maven-fetch
          resolve pom.xml with POMs fetched when they are not in ~/.m2, from the mirror of Maven Central that settings.xml names, else Maven Central (sends each artifact's coordinates there); without it, only local repositories are used

      --maven-settings <FILE>
          the Maven settings.xml whose mirror --maven-fetch uses (default: ~/.m2/settings.xml when present)

      --release-age <DUR>
          warn on dependency versions published less than DUR ago, e.g. 72h (looks publish times up on deps.dev, which sends each package's name and version; cached)

      --require-full-coverage
          exit 2 if any source was read with less than full coverage (a pom.xml without a resolved graph, a lockfile format fleetreach cannot read), as for an errored repo

      --resolve-features
          mark findings built/phantom via cargo tree (needs buildable source)

      --ignore-phantom
          suppress findings on phantom (unbuilt optional) deps; implies --resolve-features

      --ignore-dev-deps
          suppress findings on dev/build-only deps (npm devDependencies, uv/poetry dev groups, Pipfile dev-packages, composer require-dev)

      --vex-oci
          read OpenVEX attached to images pulled from registries; a document sets findings aside when --vex-oci-key signed it

      --vex-oci-key <PUBLIC_KEY>
          cosign public key whose signature on attached VEX is accepted (repeatable); implies --vex-oci

      --vex-oci-unsigned
          accept attached VEX no key signed, as Trivy does: anyone who can push to the repository can then hide findings; implies --vex-oci

      --enrich
          enrich findings with CISA KEV + EPSS (network)

      --kev-file <PATH>
          KEV catalog JSON file (offline enrich)

      --epss-file <PATH>
          EPSS CSV file (offline enrich)

      --fail-on-kev
          fail if any finding is in the CISA KEV catalog

      --min-epss <P>
          report only findings with EPSS >= P

      --fail-on-ssvc <OUTCOME>
          fail if any SSVC decision is at or above OUTCOME (needs repo context in fleet.toml; implies --enrich)
          
          [possible values: defer, scheduled, out-of-cycle, immediate]

      --vulnrichment-dir <DIR>
          a local clone of github.com/cisagov/vulnrichment, for CISA's SSVC Exploitation and Automatable per CVE (with --enrich they are fetched from GitHub instead, cached)

      --reachability [<MODE>]
          reachability: bare/`heuristic` greps your source (safe, no build); `static` is a sound call-graph analysis that COMPILES each repo — running its build scripts and proc-macros (see --allow-untrusted-builds). Needs --reach-driver.

          Possible values:
          - heuristic: Grep the repo's own source for affected-function names (zero-build)
          - static:    Sound call-graph reachability over the compiled crate closure

      --reachable-only
          drop findings proven/assumed unreachable; implies --reachability

      --npm-prune-unreachable
          npm only: under --reachability, build a module import graph and mark a vulnerable package NotReachable when node_modules is present and no import path reaches it. Best-effort sound — a dynamic require()/framework autoload it cannot see may make a NotReachable wrong (this flag is your acknowledgement). Implies --reachability.

      --allow-untrusted-builds
          REQUIRED to acknowledge that --reachability=static executes the scanned repos' build scripts and proc-macros (arbitrary code). Only scan repos you trust.

      --reach-driver <PATH>
          path to the built fleetreach-reach-driver (required for --reachability=static)

      --govulncheck <PATH>
          path to the govulncheck binary for scanning Go repos (default: search PATH and $GOPATH/bin). Go scanning also requires --allow-untrusted-builds (govulncheck compiles the module), and the build is confined per --build-sandbox.

      --go-vuln-db <URL>
          vulnerability DB for govulncheck (Go), passed as `-db` (default: vuln.go.dev). A `file://<mirror>` lets a confined (network-denied) Go scan run offline; falls back to the GOVULNDB env var.

      --npm-vuln-db <URL>
          OSV vulnerability DB for the toolchain-free npm matcher, as `file://<path>` to either the osv.dev npm export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. npm scanning builds nothing, so it needs no --allow-untrusted-builds; without this an npm repo is an honest gap.

      --pypi-vuln-db <URL>
          OSV vulnerability DB for the toolchain-free PyPI matcher, as `file://<path>` to either the osv.dev PyPI export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. PyPI scanning reads uv.lock/poetry.lock/Pipfile.lock and builds nothing, so it needs no --allow-untrusted-builds; without this a PyPI repo is an honest gap.

      --rubygems-vuln-db <URL>
          OSV vulnerability DB for the toolchain-free RubyGems matcher, as `file://<path>` to either the osv.dev RubyGems export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. RubyGems scanning reads Gemfile.lock and builds nothing, so it needs no --allow-untrusted-builds; without this a RubyGems repo is an honest gap.

      --packagist-vuln-db <URL>
          OSV vulnerability DB for the toolchain-free Packagist (Composer/PHP) matcher, as `file://<path>` to either the osv.dev Packagist export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. Packagist scanning reads composer.lock and builds nothing, so it needs no --allow-untrusted-builds; without this a Packagist repo is an honest gap.

      --nuget-vuln-db <URL>
          OSV vulnerability DB for the toolchain-free NuGet (.NET) matcher, as `file://<path>` to either the osv.dev NuGet export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. NuGet scanning reads packages.lock.json and builds nothing, so it needs no --allow-untrusted-builds; without this a NuGet repo is an honest gap.

      --julia-vuln-db <URL>
          OSV vulnerability DB for the toolchain-free Julia matcher, as `file://<path>` to either the osv.dev Julia export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. Julia scanning reads Manifest.toml and builds nothing, so it needs no --allow-untrusted-builds; without this a Julia repo is an honest gap.

      --swift-vuln-db <URL>
          OSV vulnerability DB for the toolchain-free Swift matcher, as `file://<path>` to either the osv.dev SwiftURL export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. Swift scanning reads Package.resolved and builds nothing, so it needs no --allow-untrusted-builds; without this a Swift repo is an honest gap.

      --hex-vuln-db <URL>
          OSV vulnerability DB for the toolchain-free Hex (Elixir) matcher, as `file://<path>` to either the osv.dev Hex export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. Hex scanning reads mix.lock and builds nothing, so it needs no --allow-untrusted-builds; without this a Hex repo is an honest gap.

      --ghactions-vuln-db <URL>
          OSV vulnerability DB for the toolchain-free GitHub Actions matcher, as `file://<path>` to either the osv.dev GitHub Actions export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. It reads .github/workflows/*.yml and matches version-pinned `uses:` actions, building nothing, so it needs no --allow-untrusted-builds; without this a workflow repo is an honest gap.

      --crates-vuln-db <URL>
          OSV vulnerability DB for the crates.io advisories RustSec does not carry, as `file://<path>` to either the osv.dev crates.io export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. RustSec still answers without it, and the repo is marked partial.

      --maven-vuln-db <URL>
          OSV vulnerability DB for the toolchain-free Maven (Java) matcher, as `file://<path>` to either the osv.dev Maven export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. It reads gradle.lockfile (preferred) or pom.xml and builds nothing, so it needs no --allow-untrusted-builds; without this a Maven repo is an honest gap.

      --sync
          list every [[source]] afresh and clone or refresh its checkouts before scanning (otherwise the cached listing and existing checkouts are used)

      --osv-dir <DIR>
          one directory holding the osv.dev exports for every toolchain-free ecosystem, laid out like the osv.dev bucket: <DIR>/<Ecosystem>/all.zip (or an unzipped <DIR>/<Ecosystem>/). A per-ecosystem --<eco>-vuln-db flag still wins. Also FLEETREACH_OSV_DIR or settings.osv.dir. Without it, the default cache (~/.cache/fleetreach/osv) is used and, in network builds, kept fresh automatically (set FLEETREACH_OSV_SYNC=off or --offline to stop that).

      --image <PATH>
          also scan this container image: a `docker save` or OCI-layout tarball, an OCI-layout directory, or a root filesystem (directory or tarball). Repeatable; its id is the file name. Its OS packages are matched against the osv.dev distro export for its release (synced per distro, or from --osv-dir), its lockfiles and installed Python and npm packages with the language matchers. With only --image, no fleet.toml is needed.

      --distro-ignore-unimportant
          drop Debian advisories the security tracker marks unimportant and Ubuntu ones it rates negligible (by default they are reported, with that urgency in the title)

      --build-sandbox <MODE>
          confine the untrusted build (--reachability=static AND govulncheck for Go repos, both of which compile scanned code): `auto` sandboxes when a mechanism is available (sandbox-exec/bwrap/firejail) else warns; `require` fails without one; `off` runs unconfined. Confinement denies network + writes outside a scratch dir. A confined Go scan is therefore offline: `auto` falls back to an online unconfined scan unless --go-vuln-db=file://<mirror> is set, while `require` needs the mirror or fails closed.

          Possible values:
          - auto:    Confine if a mechanism is available, else warn and run unconfined
          - off:     Never confine — run the build with full user privileges
          - require: Confine, or refuse to build (→ Unknown) if no mechanism is available
          
          [default: auto]

      --features <FEATURES>
          cargo features to enable when building for --reachability=static (comma-separated or repeated). Part of the reachability cache key.

      --all-features
          build with --all-features for --reachability=static

      --no-default-features
          build with --no-default-features for --reachability=static

      --vex-author <S>
          OpenVEX mandatory author (overrides settings.vex.author)

      --vex-role <S>
          OpenVEX document author role

      --vex-id <IRI>
          explicit OpenVEX document @id (default: content hash)

      --vex-timestamp <RFC3339>
          pin the OpenVEX timestamp (default: advisory-db commit time)

      --vex-scope <SCOPE>
          OpenVEX product scope (§7 edge 4)
          
          [possible values: runtime, build]

      --vex-only-sound
          omit human-asserted VEX statements, keeping only machine-sound ones

      --vex-alias-rustbinary
          also emit pkg:rustbinary subcomponents for binary-scanning consumers (§4.2)

      --vex-include-fixed
          emit `fixed` VEX statements for already-patched occurrences

      --vex-version <N>
          OpenVEX document version (§9.3); bump when statements change
          
          [default: 1]

      --vex-supersedes <IRI>
          prior OpenVEX document @id this one supersedes (§9.3)

      --baseline <BASELINE>
          prior JSON report; report only findings new since it

      --history-dir <HISTORY_DIR>
          Record this run in a scan history directory (a gzipped snapshot plus an index; see `fleetreach history`). Refuses the flags that drop findings from the report, which would otherwise be recorded as fixed

      --explain <ID>
          print full detail for one advisory and exit

      --why <PKG>
          show how a package enters the fleet's dependency trees and exit

  -q, --quiet
          suppress the summary line

  -v, --verbose
          per-repo progress to stderr

  -h, --help
          Print help (see a summary with '-h')
```
