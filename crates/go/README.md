# fleetreach-go

[![crates.io](https://img.shields.io/crates/v/fleetreach-go.svg)](https://crates.io/crates/fleetreach-go)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-go)](https://docs.rs/fleetreach-go)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-go.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

Go ecosystem feeder for fleetreach: turn `govulncheck` output into the shared
`VulnFinding` model so the existing correlate / report / remediation pipeline
works on Go modules unchanged.

The interesting part is the reachability mapping, and it is the mirror image of
the Rust engine. `govulncheck` is **sound-positive**: a symbol-level call trace
is strong evidence the vulnerable code is actually called. But the *absence* of
a symbol-level finding is only "not observed", not proven unreachable (calls via
`reflect`/`unsafe` are invisible to the analysis). So this feeder may emit
`Reachable` (with the trace as the witness) but **never** `NotReachable`;
everything present-but-not-confirmed-called maps to `Unknown`, which the
remediation gate keeps in the active queue. The Rust engine suppresses
provably-dead findings; this confirms provably-live ones, into the same queue
from the opposite end.

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
