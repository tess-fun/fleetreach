# fleetreach-report

[![crates.io](https://img.shields.io/crates/v/fleetreach-report.svg)](https://crates.io/crates/fleetreach-report)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-report)](https://docs.rs/fleetreach-report)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-report.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

Render a `FleetReport` to a human table, JSON, SARIF, or OpenVEX — side-effect free.

`fleetreach-report` is the presentation layer: every function takes a
`fleetreach_core::FleetReport` and returns a `String`. It never writes to a
stream, decides an exit code, or emits color unless the caller asks — so
stream routing and TTY detection stay in the binary. It covers the machine
formats a CI pipeline consumes (`to_json`, `to_sarif`, `to_vex` for OpenVEX
suppression) alongside the human `to_table`, blast-radius `to_impact`, its
direct-vs-transitive `to_blast` split (with a manifest/upstream fix hint), the
package-level `to_packages` rollup (which dependency is the biggest fleet
liability; also `to_packages_json`), remediation-priority `to_fix_first`, the
actionable fix-queue `to_remediation` views, and a two-report comparison
(`diff_reports` → `to_diff_table`/`to_diff_json`) that splits new from fixed from
still-open findings for tracking fleet drift over time.

## Usage

```sh
cargo add fleetreach-report
```

```rust
use fleetreach_report::to_table;
// Render the fleet report as a plain-text table (no color for piped output).
let table = to_table(&report(), false);
assert!(table.contains("RUSTSEC-2024-0001"));
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
