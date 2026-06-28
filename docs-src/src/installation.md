# Installation

```sh
cargo install fleetreach-cli --features network
```

This installs the `fleetreach` binary with network support (advisory-DB fetch
plus KEV/EPSS/NVD enrichment).

## The `network` feature

The default build is **pure-Rust** — no vendored-C TLS stack. It has no network
support and expects a local advisory-db clone passed with `--db <PATH>`. The
opt-in `network` feature adds advisory-DB fetch and KEV/EPSS/NVD enrichment
(pulling a `rustls` TLS stack).

- Install **with** `--features network` for the usual fetch-on-run behavior.
- Omit it for a minimal, dependency-light, offline (`--db`) build.

## From source

```sh
git clone https://github.com/tess-fun/fleetreach
cd fleetreach
cargo install --path crates/cli --features network
```

## Minimum supported Rust version

The MSRV is **1.89**, driven by the whole dependency closure (not just
`rustsec`) and verified in CI.

## Static reachability (optional)

The `--reachability=static` mode needs a separately built nightly driver
(`fleetreach-reach-driver`). It links `rustc_private`, so it is not published to
crates.io — build it from the repository when you want sound static
reachability. See [Reachability](./reachability.md).
