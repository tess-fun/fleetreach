# fleetreach-reach

[![crates.io](https://img.shields.io/crates/v/fleetreach-reach.svg)](https://crates.io/crates/fleetreach-reach)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-reach)](https://docs.rs/fleetreach-reach)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-reach.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

Sound static reachability over a Rust call graph, with a witness chain.

A dependency advisory tells you a crate *contains* a vulnerable function, but
most of the time your code never calls it, so the finding is noise.

`fleetreach-reach` decides whether a sink (the vulnerable function) is
reachable from your roots over the compiled call graph, and reports the call
chain when it is. Because it backs a security tool, it is **sound for the
negative claim**: it returns `NotReachable` only when there is genuinely no
path from a root to the sink in the (over-approximating) graph. Every
uncertainty resolves to `Reachable` or `Unknown`, never a false
`NotReachable`. That trustworthy negative is what an optimizing call graph
(which under-approximates) cannot give you, and what lets a `NotReachable`
verdict actually suppress noise.

## Usage

```sh
cargo add fleetreach-reach
```

Given a call graph (built inline here; in practice emitted by the driver),
`analyze` returns a `Verdict` per sink, with the shortest witness chain when
it is reachable:

```rust
use fleetreach_reach::{analyze, parse_graph, Verdict};

// A tiny graph: `main` calls a vulnerable function directly.
let graph = parse_graph(
    r#"{
        "schema": 2,
        "nodes": [
            {"id": 0, "label": "main",          "symbol": "s0"},
            {"id": 1, "label": "vulnerable_fn", "symbol": "s1"}
        ],
        "edges": [{"from": 0, "to": 1, "kind": "direct"}],
        "roots": [0],
        "sinks": [1]
    }"#,
)?;

let analysis = analyze(&graph)?;
let Verdict::Reachable { witness } = &analysis.verdicts[0].verdict else {
    unreachable!("the sink is called directly from a root");
};
assert_eq!(witness.join(" -> "), "main -> vulnerable_fn");
```

## How it works

Nodes are monomorphized function instances. Edges are `Direct` calls,
`Virtual` (`dyn`) dispatch, `Indirect` (fn-pointer) calls, and an `Opaque`
frontier for FFI / inline asm / unresolved indirection. A query runs two BFS
passes from the roots: a sink reached through analyzable edges is `Reachable`
(with a witness); one reachable only across the opaque frontier is `Unknown`;
one reached by neither is `NotReachable`.

This is the analysis half of the `fleetreach` `--reachability=static` engine:
the companion `fleetreach-reach-driver` compiles the target under a pinned
nightly and reads rustc's own monomorphization set, so the node universe is
sound by codegen rather than a hand-audited walk, and this crate merges the
per-crate fragments and answers the query.

## Minimum supported Rust version

1.89. An MSRV increase is treated as a minor-version bump.

## Safety

This crate sets `#![forbid(unsafe_code)]`; all `rustc_private` use is
quarantined in the separate `fleetreach-reach-driver` binary.

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
