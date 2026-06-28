# fleetreach-correlate

[![crates.io](https://img.shields.io/crates/v/fleetreach-correlate.svg)](https://crates.io/crates/fleetreach-correlate)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-correlate)](https://docs.rs/fleetreach-correlate)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-correlate.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

Fold per-repo, single-occurrence findings into deduplicated fleet-wide findings.

`fleetreach-correlate` groups vulnerabilities by RUSTSEC id and warnings by
`(kind, id)`, conserving every occurrence (never dropped or invented) and
merging them into the group. The output is totally ordered (severity desc,
then id) with each finding's occurrences sorted, so identical inputs render
byte-identically. The per-occurrence verdict stays in `fleetreach-core`: the
same advisory can apply to different versions across the fleet, one already
patched, one not.

## Usage

```sh
cargo add fleetreach-correlate
```

```rust
use fleetreach_correlate::correlate;
// The same advisory in two repos folds into one finding with two occurrences.
let correlated = correlate(vec![finding("app"), finding("svc")], vec![]);
assert_eq!(correlated.vulnerabilities.len(), 1);
assert_eq!(correlated.vulnerabilities[0].occurrences.len(), 2);
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
