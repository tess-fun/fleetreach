# fleetreach-scan

[![crates.io](https://img.shields.io/crates/v/fleetreach-scan.svg)](https://crates.io/crates/fleetreach-scan)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-scan)](https://docs.rs/fleetreach-scan)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-scan.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

The only fleetreach crate that touches `rustsec`: load the advisory DB, scan a
lockfile, and map the engine's types onto `fleetreach-core`.

`fleetreach-scan` wraps the audited `rustsec` engine (the library `cargo-audit`
is built on). No `rustsec` type appears in this crate's public API, so the
engine stays a quarantined dependency and callers see only `core` types. It
scans one `Cargo.lock` (and optionally the toolchain), recording one
occurrence per finding; cross-repo grouping lives in `fleetreach-correlate`.

## Usage

```sh
cargo add fleetreach-scan
```

```rust
use std::path::Path;

use fleetreach_core::RepoId;
use fleetreach_scan::{scan_lockfile, AdvisoryDb};

// Open a local advisory-db clone (always available). With the `network`
// feature, `AdvisoryDb::fetch()` clones the default DB from GitHub instead.
let db = AdvisoryDb::open(Path::new("advisory-db"))?;
let scan = scan_lockfile(&db, &RepoId("app".into()), Path::new("Cargo.lock"))?;
for vuln in &scan.vulnerabilities {
    println!("{}  {}", vuln.advisory_id, vuln.title);
}
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
