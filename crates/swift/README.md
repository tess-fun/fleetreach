# fleetreach-swift

[![crates.io](https://img.shields.io/crates/v/fleetreach-swift.svg)](https://crates.io/crates/fleetreach-swift)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-swift)](https://docs.rs/fleetreach-swift)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-swift.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

Swift ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that turns a
repo's `Package.resolved` plus an offline OSV vulnerability DB into the shared
`VulnFinding` model, so the existing correlate / report / remediation pipeline works on
Swift packages unchanged.

Like the other Tier-C feeders it needs no build: `Package.resolved` already pins the full
dependency graph to exact versions. It reads the lockfile and compares versions against OSV
`SEMVER` ranges, running no Swift tool and no package build, so it is **safe by
construction**: no untrusted-build consent and no sandbox.

Swift versions are plain SemVer, so this reuses the shared SemVer comparator (no bespoke
version logic, like npm). The Swift-specific part is **package identity**: a Swift package
is named by its **source URL**, and the OSV `SwiftURL` ecosystem keys advisories on a
normalized form (`github.com/apple/swift-nio`). `Package.resolved` records the full clone
URL, so both sides are run through [`normalize_package_url`](https://docs.rs/fleetreach-swift/latest/fleetreach_swift/lockfile/fn.normalize_package_url.html) (strip scheme/`git@`/`.git`/
trailing slash, lowercase) before matching.

`Package.resolved` does not record which dependencies are direct, so the sibling
`Package.swift`'s `.package(url:)` declarations mark the direct/transitive split when
present.

Consistent with the feeder contract, every finding is package-level `Unknown` reachability
(engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is carried where the
record has it — the GHSA band, or a band + base score derived from a CVSS_V3 vector — and
otherwise left `Unknown` for `--enrich` to backfill via CVE aliases.

```rust
use fleetreach_swift::{swift_db_path, SwiftDb, scan_offline};
use fleetreach_core::RepoId;
use std::path::Path;

let root = swift_db_path("file:///opt/swift/all.zip").expect("a file:// mirror");
let db = SwiftDb::load(&root)?;
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
