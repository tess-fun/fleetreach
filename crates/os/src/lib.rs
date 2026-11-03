//! Container image and OS package feeder for fleetreach: reads an image (a `docker save`
//! archive, an OCI image layout, or a root filesystem directory), finds its distribution
//! and installed packages, and matches them against the osv.dev distro exports into the
//! shared `VulnFinding` model, so image findings rank, dedupe and gate with the rest of the
//! fleet.
//!
//! Like the language feeders it is **toolchain-free and safe by construction**: nothing in
//! the image is run, nothing is written to disk, and every layer named by digest is checked
//! against it. The pieces:
//!
//! - [`image`]: layer merge with OCI whiteouts (`.wh.<name>`, `.wh..wh..opq`), symlinks
//!   followed inside the image, only wanted files kept in memory;
//! - [`distro`]: `/etc/os-release` to the osv.dev ecosystem (`Debian:12`, `Ubuntu:24.04:LTS`,
//!   `Alpine:v3.20`, `Wolfi`, `Chainguard`, `MinimOS`, `Alpaquita:stream`, `Echo`,
//!   `CleanStart`, `Red Hat:enterprise_linux:9::baseos`, `AlmaLinux:9`, `Rocky Linux:9`,
//!   `openSUSE:Leap 15.6`, `SUSE:...`, `Azure Linux:3`, `Mageia:9`, `openEuler:...`, and the
//!   vendor-feed ecosystems `Amazon Linux:2023`, `Oracle Linux:9`, `Photon OS:5.0`), plus the
//!   Ubuntu Pro and Root overlays; an unknown distribution or release, or one with no
//!   advisories to match (CentOS, Fedora), is a coverage gap, never clean;
//! - [`feeds`]: Amazon Linux `updateinfo.xml`, Oracle OVAL and Photon CVE metadata converted
//!   into OSV records, for the distributions osv.dev does not carry;
//! - [`packages`]: dpkg `status` and distroless `status.d`, apk `installed`, and the rpm
//!   database ([`rpmdb`]: SQLite, Berkeley DB and NDB, read in pure Rust), each binary package
//!   mapped to the source package advisories name, and the files each package owns;
//! - [`DebVersion`], [`ApkVersion`] and [`RpmVersion`]: dpkg's, apk-tools' and rpm's
//!   orderings, validated against `dpkg --compare-versions`, `apk version -t` and
//!   `rpm.vercmp` (see `tests/comparator_golden.rs`);
//! - [`db`] and [`scan`]: the per-distro advisory index and the matcher. Unfixed Debian and
//!   Ubuntu records are findings with no patched version and their urgency. Red Hat and
//!   AlmaLinux advisories name binary packages, so there each binary is matched on its own;
//! - [`eol`]: the release's end of life, from a bundled endoflife.date snapshot, reported as
//!   a warning once standard support has ended;
//! - [`lang`]: the language lockfiles and installed package metadata in the image, for the
//!   existing language feeders, skipping files an OS package owns.
//!
//! Every finding is package-level `Unknown` reachability (engine `fleetreach-tier-c`), never
//! `NotReachable`. Package names are `<distro>/<source package>` (`debian/openssl`), the
//! package-URL namespace and name.
//!
//! ```no_run
//! use fleetreach_os::{open_image, inspect, db, scan, ScanOptions};
//! use fleetreach_core::RepoId;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let fs = open_image(Path::new("app.tar"), &|_| false, None)?;
//! let found = inspect(&fs, None);
//! let distro = found.distro.clone()?;
//! let mut wanted = db::Wanted::default();
//! for eco in distro.ecosystems() {
//!     wanted.ecosystems.insert(eco, distro.family);
//! }
//! let advisories = db::load(&["/osv/Debian:12/all.zip".into()], &wanted)?;
//! let result = scan::scan(&distro, &found.inventory.packages, &advisories, &RepoId("app".into()), ScanOptions::default());
//! # let _ = result;
//! # Ok(())
//! # }
//! ```
//!
//! # Minimum supported Rust version
//!
//! 1.89. An MSRV increase is treated as a minor-version bump.

mod apkver;
mod centos;
pub mod db;
pub mod distro;
mod dpkgver;
pub mod eol;
mod error;
pub mod feeds;
pub mod image;
pub mod lang;
pub mod packages;
pub mod rpmdb;
mod rpmver;
pub mod scan;
mod tar;

use std::path::Path;

pub use apkver::ApkVersion;
pub use distro::{Distro, Family, OsRelease};
pub use dpkgver::DebVersion;
pub use error::{DbError, OsError};
pub use image::ImageFs;
pub use packages::{Inventory, OsPackage};
pub use rpmver::RpmVersion;
pub use scan::ScanOptions;

/// Open an image keeping the OS package databases, os-release, and whatever `extra`
/// selects (pass [`lang::wanted`] to keep the language files too).
///
/// # Errors
///
/// As [`image::open`].
pub fn open_image(
    path: &Path,
    extra: &dyn Fn(&str) -> bool,
    platform: Option<&str>,
) -> Result<ImageFs, OsError> {
    image::open(path, &|p| packages::wanted(p) || extra(p), platform)
}

/// What an image is: its distribution (or why it cannot be matched) and its packages.
#[derive(Debug, Clone)]
pub struct Inspection {
    pub os_release: Option<OsRelease>,
    /// The distribution to match against, or the coverage-gap reason. `Ok(None)`-like
    /// images (no os-release and no package database, a `scratch` image) have
    /// [`Inspection::no_os`] set instead.
    pub distro: Result<Distro, String>,
    pub inventory: Inventory,
    /// True when the image has neither an os-release nor a package database: there are
    /// no OS packages to match, and that is not a gap.
    pub no_os: bool,
}

/// Detect the distribution and read the packages. `explicit` is an ecosystem named in
/// `fleet.toml` (`Debian:12`), used instead of os-release.
pub fn inspect(fs: &ImageFs, explicit: Option<&str>) -> Inspection {
    let inventory = packages::inventory(fs);
    let text = |p: &str| fs.read(p).map(|b| String::from_utf8_lossy(b).into_owned());
    let os_release = text("etc/os-release")
        .or_else(|| text("usr/lib/os-release"))
        .map(|t| distro::parse_os_release(&t));
    let no_os = os_release.is_none() && inventory.family.is_none();
    let hints = distro::Hints::from_versions(inventory.packages.iter().map(|p| p.version.as_str()));
    let detected = match (explicit, &os_release) {
        (Some(eco), _) => match distro::family_of(eco) {
            Some(f) => Ok(distro::explicit(eco, f)),
            None => Err(format!(
                "distro {eco} is not a distro ecosystem fleetreach matches"
            )),
        },
        (None, Some(os)) => distro::detect(os, text("etc/debian_version").as_deref(), hints),
        (None, None) => Err("no /etc/os-release, so the distribution is unknown".to_string()),
    };
    let distro = detected.and_then(|d| match inventory.family {
        Some(f) if f == d.family => Ok(Distro {
            modules: inventory.modules.clone(),
            ..d
        }),
        Some(f) => Err(format!(
            "{} uses {} packages but the image has a {} database",
            d.name,
            d.family.purl_type(),
            f.purl_type()
        )),
        None => Err(format!(
            "{}: no dpkg, apk or rpm package database found",
            d.name
        )),
    });
    Inspection {
        os_release,
        distro,
        inventory,
        no_os,
    }
}
