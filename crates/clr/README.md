# fleetreach-clr

[![crates.io](https://img.shields.io/crates/v/fleetreach-clr.svg)](https://crates.io/crates/fleetreach-clr)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-clr)](https://docs.rs/fleetreach-clr)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/fleetreach-clr.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

.NET assemblies for call graphs (spec 16, row 13): an in-house ECMA-335 reader.

Assemblies are data: the PE file is parsed, its metadata tables and IL method bodies read,
and nothing is loaded or run. `read` gives every type the assembly defines, with each
method's calls, object creations, delegate targets, string literals and static field
accesses, named the way the runtime's own reflection names them (`Namespace.Outer+Inner`,
with the generic arity suffix, as in `List` and a backtick and `1`).

The reader is checked against .NET's own `System.Reflection.Metadata` on every method of
every assembly in a .NET SDK and a NuGet package cache: same types, same methods, same
instructions in the same order. A file outside the format (a truncated table, an opcode
the standard does not define, a token past its table) is an error, never a partial answer.

`graph::analyze` builds a rapid type analysis call graph over a service's assemblies,
and `verdict::judge` answers one curated sink record against it, as `fleetreach-jvm`
does for class files. The graph is checked against what the runtime itself ran: on 11
apps built from real NuGet packages, every method the JIT compiled in their assemblies is
in the graph (`docs/differential/clr/jit`).

`propose` drafts sink records for NuGet advisories from the IL diff of a package's last
vulnerable and first fixed release, narrowed to the types whose source files the fix
commits changed. A draft is `proposed` until a person reviews it.

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
