# fleetreach-ghactions

[![crates.io](https://img.shields.io/crates/v/fleetreach-ghactions.svg)](https://crates.io/crates/fleetreach-ghactions)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-ghactions)](https://docs.rs/fleetreach-ghactions)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-ghactions.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

GitHub Actions ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that
turns a repo's workflow files plus an offline OSV vulnerability DB into the shared
`VulnFinding` model, so the existing correlate / report / remediation pipeline works on
pinned GitHub Actions unchanged.

It reads `.github/workflows/*.yml` (and a root `action.yml`/`action.yaml`), extracts each
`uses: owner/repo@ref` reference, and matches the version-tag pins against OSV `ECOSYSTEM`
ranges, running nothing — so it is **safe by construction**: no untrusted-build consent
and no sandbox.

Two things are GitHub-Actions-specific. Identity is `owner/repo[/subpath]` (case-
insensitive, matched lowercased). And the `@ref` is a git tag, branch, or commit SHA:
only a **version tag** (`v4`, `4.1.1`) can be matched against the semantic ranges — a
partial tag is padded (`v4` → `4.0.0`, the way the OSV ranges treat it) — while a branch
(`@main`) or a commit SHA has no semantic version and is skipped (an honest gap, since
resolving a SHA to its release would need the network).

Consistent with the feeder contract, every finding is package-level `Unknown` reachability
(engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is carried where the
record has it — the GHSA band, or a band + base score derived from a CVSS_V3 vector — and
otherwise left `Unknown` for `--enrich` to backfill via CVE aliases.

```rust
use fleetreach_ghactions::{ghactions_db_path, GhActionsDb, scan_offline};
use fleetreach_core::RepoId;
use std::path::Path;

let root = ghactions_db_path("file:///opt/gha/all.zip").expect("a file:// mirror");
let db = GhActionsDb::load(&root)?;
let findings = scan_offline(Path::new("/srv/repo"), &db, &RepoId("repo".into()))?;
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
