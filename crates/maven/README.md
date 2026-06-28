# fleetreach-maven

[![crates.io](https://img.shields.io/crates/v/fleetreach-maven.svg)](https://crates.io/crates/fleetreach-maven)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-maven)](https://docs.rs/fleetreach-maven)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-maven.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

Maven (Java) ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that
turns a repo's `gradle.lockfile` (or `pom.xml`) plus an offline OSV vulnerability DB into
the shared `VulnFinding` model, so the existing correlate / report / remediation pipeline
works on Maven artifacts unchanged.

Maven has no single universal lockfile, so two inputs are read: a **`gradle.lockfile`**
(Gradle dependency locking — the full resolved transitive closure, the high-fidelity input)
or, failing that, a **`pom.xml`** (best-effort — the direct dependencies whose `<version>`
is a literal; a `${property}` or version range cannot be resolved without running Maven and
is skipped). It runs no `mvn`/`gradle` and no plugin, so it is **safe by construction**: no
untrusted-build consent and no sandbox.

One thing is Maven-specific. Versions follow Apache Maven's `ComparableVersion`, **not**
SemVer: qualifiers order `alpha < beta < milestone < rc < snapshot < <release> < sp`
(`-rc`/`-milestone` sort below the release, `-sp` above), `ga`/`final`/`release` are aliases
for the release (`1.0.RELEASE == 1.0`), integers compare as arbitrary precision (so
Jenkins-style `2646.v…` build numbers order numerically), and `.X` is treated like `-X` for
a string qualifier. Matching uses a faithful `ComparableVersion` port (the
false-clean-critical part); the stored finding keeps a best-effort SemVer rendering for the
shared model. Coordinates `group:artifact` are matched verbatim (case-sensitive).

Consistent with the feeder contract, every finding is package-level `Unknown` reachability
(engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is carried where the
record has it — the GHSA band, or a band + base score derived from a CVSS_V3 vector — and
otherwise left `Unknown` for `--enrich` to backfill via CVE aliases.

```rust
use fleetreach_maven::{maven_db_path, MavenDb, scan_offline};
use fleetreach_core::RepoId;
use std::path::Path;

let root = maven_db_path("file:///opt/maven/all.zip").expect("a file:// mirror");
let db = MavenDb::load(&root)?;
let findings = scan_offline(Path::new("/srv/app"), &db, &RepoId("app".into()))?;
```

## Minimum supported Rust version

1.89. An MSRV increase is treated as a minor-version bump.

<!-- cargo-rdme end -->

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](../../LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
