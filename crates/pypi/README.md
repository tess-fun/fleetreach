# fleetreach-pypi

[![crates.io](https://img.shields.io/crates/v/fleetreach-pypi.svg)](https://crates.io/crates/fleetreach-pypi)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-pypi)](https://docs.rs/fleetreach-pypi)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-pypi.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

PyPI ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that turns
a repo's Python lockfile plus an offline OSV vulnerability DB into the shared
`VulnFinding` model, so the existing correlate / report / remediation pipeline works
on Python packages unchanged.

Like the npm feeder it needs no build: a lockfile already pins the full transitive
tree to exact versions, so the matcher is the only tier. It reads `uv.lock`,
`poetry.lock`, or `Pipfile.lock` (in that detection order) and compares versions
against OSV `ECOSYSTEM` ranges, running no Python tool and no package build, so it is
**safe by construction**: no untrusted-build consent and no sandbox.

Two things are Python-specific. Versions are [PEP 440] (epochs, `.post`/`.dev`,
`a1`/`rc1`, local segments), not SemVer, so matching uses the `pep440_rs` crate via
the shared `fleetreach_core::osv` skeleton; the stored finding keeps a SemVer
rendering (a best-effort coercion) for the shared model. Names are matched after
[PEP 503] normalization so `Flask`/`flask` and `ruamel.yaml`/`ruamel-yaml` resolve to
the same advisory.

Consistent with the feeder contract, every finding is package-level `Unknown`
reachability (engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is
carried where the record has it — the GHSA band, or a band + base score derived from a
CVSS_V3 vector — and otherwise left `Unknown` for `--enrich` to backfill via CVE
aliases.

```rust
use fleetreach_pypi::{pypi_db_path, PyPiDb, scan_offline};
use fleetreach_core::RepoId;
use std::path::Path;

// Load the OSV mirror once (the osv.dev `PyPI/all.zip` directly, or an unzipped
// directory), then scan each repo against it.
let root = pypi_db_path("file:///opt/pypi/all.zip").expect("a file:// mirror");
let db = PyPiDb::load(&root)?;
let findings = scan_offline(Path::new("/srv/app"), &db, &RepoId("app".into()))?;
```

[PEP 440]: https://peps.python.org/pep-0440/
[PEP 503]: https://peps.python.org/pep-0503/#normalized-names

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
