# fleetreach-nuget

[![crates.io](https://img.shields.io/crates/v/fleetreach-nuget.svg)](https://crates.io/crates/fleetreach-nuget)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-nuget)](https://docs.rs/fleetreach-nuget)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-nuget.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

NuGet (.NET) ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that
turns a repo's `packages.lock.json` plus an offline OSV vulnerability DB into the shared
`VulnFinding` model, so the existing correlate / report / remediation pipeline works on
NuGet packages unchanged.

Like the npm/PyPI/RubyGems/Packagist feeders it needs no build: `packages.lock.json`
already pins the full transitive tree to exact versions and records whether each package
is a direct or transitive dependency. It reads the lockfile and compares versions against
OSV `ECOSYSTEM` ranges, running no .NET tool and no package build, so it is **safe by
construction**: no untrusted-build consent and no sandbox.

One thing is NuGet-specific. A NuGet version is SemVer 2.0 with a **four-component**
numeric core (`Major.Minor.Patch.Revision`, e.g. `1.1.1.1`) and **case-insensitive**
prerelease labels; trailing zeros and `+build` metadata are insignificant. The stock
three-component `semver` crate cannot represent that, so matching uses a faithful
`NuGetVersion` comparator (the false-clean-critical part) via the shared
`fleetreach_core::osv` skeleton; the stored finding keeps a SemVer rendering for the shared
model. Package ids are case-insensitive, matched lowercased.

Consistent with the feeder contract, every finding is package-level `Unknown` reachability
(engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is carried where the
record has it — the GHSA band, or a band + base score derived from a CVSS_V3 vector — and
otherwise left `Unknown` for `--enrich` to backfill via CVE aliases.

```rust
use fleetreach_nuget::{nuget_db_path, NuGetDb, scan_offline};
use fleetreach_core::RepoId;
use std::path::Path;

// Load the OSV mirror once (the osv.dev `NuGet/all.zip` directly, or an unzipped
// directory), then scan each repo against it.
let root = nuget_db_path("file:///opt/nuget/all.zip").expect("a file:// mirror");
let db = NuGetDb::load(&root)?;
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
