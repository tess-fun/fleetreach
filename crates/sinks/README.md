# fleetreach-sinks

[![crates.io](https://img.shields.io/crates/v/fleetreach-sinks.svg)](https://crates.io/crates/fleetreach-sinks)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-sinks)](https://docs.rs/fleetreach-sinks)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/fleetreach-sinks.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

Vulnerable-function (sink) data from artifact diffs (spec 16, row 13).

The first source is the JVM: the difference between the last affected and the first fixed
jar of an advisory is a superset of its fix. [`diff_jars`](https://docs.rs/fleetreach-sinks/latest/fleetreach_sinks/fn.diff_jars.html) compares the two at the method
level after normalization, so rebuild noise (line tables, local variable tables,
constant-pool order, compiler-numbered lambdas) is not reported as a change.

Jars are data: they are unzipped and parsed, never loaded or run.

Neither jar diffs nor fix-commit diffs give sinks precise enough to act on unreviewed (the
E2 and E2b experiments in spec 16), so sinks are curated data: [`propose`](https://docs.rs/fleetreach-sinks/latest/fleetreach_sinks/propose/) turns a fix
into a `proposed` [`record`](https://docs.rs/fleetreach-sinks/latest/fleetreach_sinks/record/), a person reviews it, and only reviewed records may ever
support "not reached".

The proposer reads Java, Python and JavaScript/TypeScript fixes: the `java` and `python`
modules are small hand-written readers, `js` uses `oxc_parser`. Records are for Maven, PyPI
or npm; Python and JS sinks are module or file paths plus a function name, and only ever
produce witnesses, since name-based call graphs in those languages are positive-only.

The curated records under `data/` are built into the crate: [`record::bundled`](https://docs.rs/fleetreach-sinks/latest/fleetreach_sinks/record/fn.bundled.html) returns
them, checked as [`record::load_dir`](https://docs.rs/fleetreach-sinks/latest/fleetreach_sinks/record/fn.load_dir.html) checks a directory.

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
