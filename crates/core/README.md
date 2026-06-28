# fleetreach-core

[![crates.io](https://img.shields.io/crates/v/fleetreach-core.svg)](https://crates.io/crates/fleetreach-core)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-core)](https://docs.rs/fleetreach-core)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-core.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

Domain types for fleetreach: the stable, I/O-free contract every other crate maps onto.

`fleetreach-core` defines the model a fleet scan produces — `FleetReport`,
`VulnFinding`, `Occurrence`, `Severity` — and their serde shape. It
performs **no I/O** and exposes **no `rustsec` types**, so downstream
enrichment (EPSS, reachability, SARIF) lands as additive fields without
breaking `schema_version: 1` consumers. `semver` values stay typed and
serialize to strings only at the JSON boundary.

## Usage

```sh
cargo add fleetreach-core
```

The per-occurrence verdict — is the *installed* version still vulnerable? — is
computed against the advisory's patched range, fail-closed:

```rust
use fleetreach_core::semver::{Version, VersionReq};
use fleetreach_core::{DependencyKind, Occurrence, RepoId, Severity};

// Severity is ordered worst-last, so `iter().max()` yields the fleet maximum.
assert!(Severity::Critical > Severity::High);

let occurrence = Occurrence::InRepo {
    repo: RepoId("app".into()),
    package: "jiff".into(),
    installed: Version::new(0, 1, 1),
    patched: vec![VersionReq::parse(">=0.1.2").unwrap()],
    dependency_kind: DependencyKind::Transitive,
    dependency_path: vec![],
    active: None,
    source: Default::default(),
};
assert!(occurrence.is_vulnerable()); // installed is below the patched range
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
