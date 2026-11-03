# fleetreach-os

[![crates.io](https://img.shields.io/crates/v/fleetreach-os.svg)](https://crates.io/crates/fleetreach-os)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-os)](https://docs.rs/fleetreach-os)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/fleetreach-os.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

Container image and OS package feeder for fleetreach: reads an image (a `docker save`
archive, an OCI image layout, or a root filesystem directory), finds its distribution
and installed packages, and matches them against the osv.dev distro exports into the
shared `VulnFinding` model, so image findings rank, dedupe and gate with the rest of the
fleet.

Like the language feeders it is **toolchain-free and safe by construction**: nothing in
the image is run, nothing is written to disk, and every layer named by digest is checked
against it. The pieces:

- [`image`](https://docs.rs/fleetreach-os/latest/fleetreach_os/image/): layer merge with OCI whiteouts (`.wh.<name>`, `.wh..wh..opq`), symlinks
  followed inside the image, only wanted files kept in memory;
- [`distro`](https://docs.rs/fleetreach-os/latest/fleetreach_os/distro/): `/etc/os-release` to the osv.dev ecosystem (`Debian:12`, `Ubuntu:24.04:LTS`,
  `Alpine:v3.20`, `Wolfi`, `Chainguard`, `MinimOS`, `Alpaquita:stream`, `Echo`,
  `CleanStart`), plus the Ubuntu Pro and Root overlays; an unknown distribution or release
  is a coverage gap, never clean;
- [`packages`](https://docs.rs/fleetreach-os/latest/fleetreach_os/packages/): dpkg `status` and distroless `status.d`, apk `installed`, each binary
  package mapped to the source package advisories name, and the files each package owns;
- [`DebVersion`](https://docs.rs/fleetreach-os/latest/fleetreach_os/dpkgver/struct.DebVersion.html) and [`ApkVersion`](https://docs.rs/fleetreach-os/latest/fleetreach_os/apkver/struct.ApkVersion.html): dpkg's and apk-tools' orderings, validated against
  `dpkg --compare-versions` and `apk version -t` (see `tests/comparator_golden.rs`);
- [`db`](https://docs.rs/fleetreach-os/latest/fleetreach_os/db/) and [`scan`](https://docs.rs/fleetreach-os/latest/fleetreach_os/scan/): the per-distro advisory index and the matcher. Unfixed Debian and
  Ubuntu records are findings with no patched version and their urgency;
- [`lang`](https://docs.rs/fleetreach-os/latest/fleetreach_os/lang/): the language lockfiles and installed package metadata in the image, for the
  existing language feeders, skipping files an OS package owns.

Every finding is package-level `Unknown` reachability (engine `fleetreach-tier-c`), never
`NotReachable`. Package names are `<distro>/<source package>` (`debian/openssl`), the
package-URL namespace and name.

```rust
use fleetreach_os::{open_image, inspect, db, scan, ScanOptions};
use fleetreach_core::RepoId;
use std::path::Path;

let fs = open_image(Path::new("app.tar"), &|_| false, None)?;
let found = inspect(&fs, None);
let distro = found.distro.clone()?;
let mut wanted = db::Wanted::default();
for eco in distro.ecosystems() {
    wanted.ecosystems.insert(eco, distro.family);
}
let advisories = db::load(&["/osv/Debian:12/all.zip".into()], &wanted)?;
let result = scan::scan(&distro, &found.inventory.packages, &advisories, &RepoId("app".into()), ScanOptions::default());
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
