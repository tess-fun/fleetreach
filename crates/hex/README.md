# fleetreach-hex

[![crates.io](https://img.shields.io/crates/v/fleetreach-hex.svg)](https://crates.io/crates/fleetreach-hex)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-hex)](https://docs.rs/fleetreach-hex)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-hex.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

Hex (Elixir/Erlang) ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher
that turns a repo's `mix.lock` plus an offline OSV vulnerability DB into the shared
`VulnFinding` model, so the existing correlate / report / remediation pipeline works on Hex
packages unchanged.

Like the other Tier-C feeders it needs no build: `mix.lock` already pins every dependency
to an exact version. It reads the lockfile and compares versions against OSV `SEMVER`
ranges, running no Elixir tool and no package build, so it is **safe by construction**: no
untrusted-build consent and no sandbox.

Hex versions are plain SemVer, so this reuses the shared SemVer comparator (no bespoke
version logic, like npm). The Hex-specific part is the lockfile: `mix.lock` is an Elixir
map literal (not JSON/TOML), so a small hand-rolled scan reads the `{:hex, :name, "version",
…}` tuples; `{:git, …}`/`{:path, …}` dependencies have no Hex release and are skipped.
Package names are lowercase, matched verbatim. `mix.lock` does not record which
dependencies are direct (that lives in `mix.exs`), so every package is reported transitive.

Consistent with the feeder contract, every finding is package-level `Unknown` reachability
(engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is carried where the
record has it — the GHSA band, or a band + base score derived from a CVSS_V3 vector — and
otherwise left `Unknown` for `--enrich` to backfill via CVE aliases.

```rust
use fleetreach_hex::{hex_db_path, HexDb, scan_offline};
use fleetreach_core::RepoId;
use std::path::Path;

let root = hex_db_path("file:///opt/hex/all.zip").expect("a file:// mirror");
let db = HexDb::load(&root)?;
let findings = scan_offline(Path::new("/srv/app"), &db, &RepoId("app".into()))?;
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
