# Contributing to fleetreach

Thanks for your interest. A few notes to keep contributions smooth.

## Building and testing

```sh
cargo test --workspace          # stable suite
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

The static-reachability engine has a separate, nightly-pinned driver that is
excluded from the stable workspace:

```sh
( cd crates/reach-driver && cargo build )                 # needs nightly-2026-06-01
cargo test -p fleetreach-reach --test e2e -- --ignored    # real-build e2e
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the overall data flow.

## Conventions

- Every crate forbids `unsafe` and denies the `unwrap`/`expect`/`panic` family on
  externally-derived values; CI enforces `clippy -D warnings`.
- Library crate READMEs are generated from `lib.rs` doc comments with
  [`cargo-rdme`](https://crates.io/crates/cargo-rdme) — edit the `//!` docs, then
  run `cargo rdme` in that crate. CI fails if a README is stale.
- The soundness spine for reachability: never emit a false `NotReachable`. When in
  doubt, widen to `Reachable`/`Unknown`.

## Submitting changes

Open an issue for anything non-trivial first. Keep commits focused and tests
green. By submitting a contribution you agree to license it under the project's
dual MIT / Apache-2.0 terms (see the README license section).
