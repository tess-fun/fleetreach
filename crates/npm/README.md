# fleetreach-npm

[![crates.io](https://img.shields.io/crates/v/fleetreach-npm.svg)](https://crates.io/crates/fleetreach-npm)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-npm)](https://docs.rs/fleetreach-npm)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-npm.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

npm ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that turns
a repo's `package-lock.json` plus an offline OSV vulnerability DB into the shared
`VulnFinding` model, so the existing correlate / report / remediation pipeline works
on npm packages unchanged.

Unlike the Go feeder — where `govulncheck` is the primary, build-based engine and
the offline matcher is a fallback — npm needs no build at all: the lockfile already
pins the full transitive tree to exact versions, so the matcher is the *only* tier.
It parses the lockfile and compares versions against OSV SEMVER ranges, running no
`npm` and no package install scripts, so it is **safe by construction**: no
untrusted-build consent and no sandbox, the same positioning win the Go Tier-C has.

Consistent with the feeder contract, every finding is package-level `Unknown`
reachability (engine `fleetreach-tier-c`) and **never** `NotReachable` — there is no
call-graph evidence, only a version match. Severity *is* carried, mapped from the
GitHub Advisory Database band in the OSV record, so npm findings rank and gate like
Rust ones rather than collapsing to `unknown`.

```rust
use fleetreach_npm::{npm_db_path, NpmDb, scan_offline};
use fleetreach_core::RepoId;
use std::path::Path;

// Load the OSV mirror once (the osv.dev `all.zip` directly, or an unzipped
// directory), then scan each repo against it.
let root = npm_db_path("file:///opt/npm/all.zip").expect("a file:// mirror");
let db = NpmDb::load(&root)?;
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
