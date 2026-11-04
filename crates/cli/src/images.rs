//! Container images as a scan input (`[[image]]`, `scan --image`): each image is opened once,
//! its distribution and OS packages read by `fleetreach-os`, and the language lockfiles it
//! carries written to a private temporary directory (mode 0700, removed when the scan ends)
//! so the language feeders read them exactly as they read a repository. Files an OS package
//! owns are left out, so a Debian `python3-requests` is matched once, as the Debian package.
//!
//! Nothing in the image is run. An image that cannot be opened is an errored target; an
//! unknown distribution or release, an unreadable package database, and language artifacts
//! no feeder reads are coverage gaps, so an image is never reported clean on partial data.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fleetreach_core::{Ecosystem, RepoId};
use fleetreach_os::jar::Found;
use fleetreach_os::lang::Installed;
use fleetreach_os::Inspection;
use rayon::prelude::*;

use crate::config::{Image, Repo};

/// How deep the language lockfile search reaches inside an image (`/usr/src/app/...`).
const LANG_DEPTH: usize = 32;

/// One image, opened (or why it could not be).
pub(crate) struct Prepared {
    pub(crate) id: RepoId,
    /// The image path or reference as given, for messages.
    pub(crate) source: String,
    /// The manifest digest of an image pulled from a registry.
    pub(crate) digest: Option<String>,
    /// The VEX attached to it, with `--vex-oci`.
    pub(crate) attested: Option<crate::oci_vex::Attested>,
    /// Why attachments could not be read.
    pub(crate) vex_problem: Option<String>,
    pub(crate) opened: Result<Opened, String>,
}

/// What an opened image holds.
pub(crate) struct Opened {
    pub(crate) inspection: Inspection,
    /// Installed PyPI and npm packages with no lockfile beside them.
    pub(crate) pypi: Vec<Installed>,
    pub(crate) npm: Vec<Installed>,
    /// Installed Composer packages.
    pub(crate) composer: Vec<Installed>,
    /// The NuGet packages of built .NET applications.
    pub(crate) nuget: Vec<Installed>,
    /// Installed gems.
    pub(crate) gems: Vec<Installed>,
    /// What the image's Java archives hold.
    pub(crate) java: Vec<fleetreach_os::jar::Found>,
    /// What the Java archives an OS package owns hold.
    pub(crate) packaged_java: Vec<Packaged<fleetreach_os::jar::Found>>,
    /// The image's Go binaries no OS package owns, by path.
    pub(crate) go: Vec<(String, fleetreach_os::gobin::GoBuild)>,
    /// Those an OS package owns.
    pub(crate) packaged_go: Vec<Packaged<(String, fleetreach_os::gobin::GoBuild)>>,
    /// The image's Rust binaries with a crate list no OS package owns, by path.
    pub(crate) rust: Vec<(String, fleetreach_os::rustbin::RustBuild)>,
    pub(crate) packaged_rust: Vec<Packaged<(String, fleetreach_os::rustbin::RustBuild)>>,
    /// Installed language packages OS packages own, by ecosystem.
    pub(crate) packaged_pypi: Vec<Packaged<Installed>>,
    pub(crate) packaged_npm: Vec<Packaged<Installed>>,
    pub(crate) packaged_composer: Vec<Packaged<Installed>>,
    pub(crate) packaged_nuget: Vec<Packaged<Installed>>,
    pub(crate) packaged_gems: Vec<Packaged<Installed>>,
    /// Language artifacts present but read by nothing, with a count.
    pub(crate) unread: BTreeMap<&'static str, usize>,
    /// Wanted files the image reader could not keep (too large, unreadable).
    pub(crate) skipped: Vec<String>,
    /// Where each package came from.
    pub(crate) layers: Layers,
    /// The image's lockfiles, written out for the language feeders; `lang_repo` points here.
    pub(crate) _files: tempfile::TempDir,
    pub(crate) lang_repo: Repo,
}

/// Something an OS package owns, with the names advisories could know the package by. One from
/// a package the distribution's advisories never name is a vendor's, which they do not cover,
/// so it is scanned like any other.
pub(crate) struct Packaged<T> {
    pub(crate) names: [String; 2],
    pub(crate) item: T,
}

/// Tag `item` with the package that owns `path`, if there is one.
fn packaged<T>(inventory: &fleetreach_os::Inventory, path: &str, item: T) -> Option<Packaged<T>> {
    let owner = inventory.owners.get(path)?;
    let package = inventory.packages.iter().find(|p| p.name == *owner)?;
    Some(Packaged {
        names: [owner.clone(), package.source.clone()],
        item,
    })
}

/// The file in the image a Java archive entry came from.
fn archive_of(found: &Found) -> Option<&str> {
    match found {
        Found::Coordinates { path, .. }
        | Found::FileName { path, .. }
        | Found::Bundle { path, .. } => path.split('!').next(),
        Found::Unknown { .. } | Found::Unreadable { .. } => None,
    }
}

/// Which layer of an image each thing a finding can name came from. A package installed at
/// several versions, or a source package's binaries, take the highest layer: replacing the
/// layers below it would leave that one.
#[derive(Default)]
pub(crate) struct Layers {
    build: fleetreach_os::image::Build,
    /// By OS binary package name.
    packages: BTreeMap<String, Option<usize>>,
    /// By image path, for lockfiles, metadata and archives.
    files: BTreeMap<String, usize>,
}

impl Layers {
    fn new(fs: &fleetreach_os::image::ImageFs, inspection: &Inspection, paths: Vec<&str>) -> Self {
        let mut out = Layers {
            build: fs.build().clone(),
            ..Layers::default()
        };
        if out.build.layers.is_empty() {
            return out;
        }
        for p in &inspection.inventory.packages {
            let layer = fs.introduced(&p.name, &p.version);
            let at = out.packages.entry(p.name.clone()).or_insert(layer);
            *at = (*at).zip(layer).map(|(a, b)| a.max(b));
        }
        for path in paths {
            if let Some(layer) = fs.file_layer(path) {
                out.files.insert(path.to_string(), layer);
            }
        }
        out
    }

    /// The layer the OS binaries `names` came from: all of them must be known.
    pub(crate) fn of_packages<'a>(
        &self,
        mut names: impl Iterator<Item = &'a str>,
    ) -> Option<usize> {
        names.try_fold(0, |top, name| Some(top.max((*self.packages.get(name)?)?)))
    }

    /// The layer that wrote the file at `path`.
    pub(crate) fn of_file(&self, path: &str) -> Option<usize> {
        self.files.get(path).copied()
    }

    /// The layer that wrote the lockfiles directly in `dir`.
    pub(crate) fn of_dir(&self, dir: &str) -> Option<usize> {
        self.files
            .iter()
            .filter(|(p, _)| p.rsplit_once('/').map_or("", |(d, _)| d) == dir)
            .map(|(_, l)| *l)
            .max()
    }

    /// The image's base, when its history shows one and its config gives the layers' digests.
    pub(crate) fn base(
        &self,
        repo: &RepoId,
        inspection: &Inspection,
    ) -> Option<fleetreach_core::ImageBase> {
        let layers = self.build.base_layers?;
        Some(fleetreach_core::ImageBase {
            repo: repo.clone(),
            fingerprint: self.build.base_fingerprint()?,
            name: self.build.base_name.clone(),
            os: inspection.distro.as_ref().ok().map(|d| d.name.clone()),
            layers,
        })
    }

    /// Layer `index` as reports show it.
    pub(crate) fn describe(&self, index: usize) -> Option<fleetreach_core::ImageLayer> {
        let layer = self.build.layers.get(index)?;
        Some(fleetreach_core::ImageLayer {
            index,
            digest: layer.digest.clone(),
            created_by: layer.created_by.clone(),
            base: self.build.base_layers.is_some_and(|n| index < n),
        })
    }
}

impl Prepared {
    /// The attached documents as a report records them.
    pub(crate) fn vex_attestations(&self) -> Vec<fleetreach_core::ImageAttestation> {
        let documents = self.attested.iter().flat_map(|a| &a.documents);
        documents
            .map(|d| fleetreach_core::ImageAttestation {
                digest: d.digest.clone(),
                signed_by: d.signed_by.clone(),
                refused: d.refused.clone(),
                statements: d.statements,
                set_aside: 0,
            })
            .collect()
    }

    /// The distro ecosystems to load advisories for (the base plus its overlays).
    pub(crate) fn distro_ecosystems(&self) -> Vec<String> {
        match &self.opened {
            Ok(o) => o
                .inspection
                .distro
                .as_ref()
                .map(fleetreach_os::Distro::ecosystems)
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }
}

/// Open every image, in parallel, in config order.
pub(crate) fn prepare_all(
    images: &[Image],
    offline: bool,
    vex: Option<&crate::oci_vex::Policy>,
) -> Vec<Prepared> {
    images
        .par_iter()
        .map(|i| prepare(i, offline, vex))
        .collect()
}

/// What is attached to a pulled image. A failure only leaves its findings standing.
fn attached(
    image: &Image,
    reference: &str,
    pulled: &crate::registry::Pulled,
    offline: bool,
    policy: &crate::oci_vex::Policy,
) -> Result<crate::oci_vex::Attested, String> {
    let attachments = crate::registry::attachments(reference, pulled, offline)?;
    Ok(crate::oci_vex::read(
        &image.id,
        reference,
        &pulled.subjects(),
        &attachments,
        policy,
    ))
}

fn prepare(image: &Image, offline: bool, vex: Option<&crate::oci_vex::Policy>) -> Prepared {
    let (source, pulled) = match &image.reference {
        Some(reference) => (
            reference.clone(),
            crate::registry::pull(reference, image.platform.as_deref(), offline).map(Some),
        ),
        None => (image.path.display().to_string(), Ok(None)),
    };
    let digest = pulled
        .as_ref()
        .ok()
        .and_then(|p| p.as_ref())
        .map(|p| p.digest.clone());
    let (attested, vex_problem) = match (vex, pulled.as_ref().ok().and_then(|p| p.as_ref())) {
        (None, _) => (None, None),
        (Some(_), None) => (
            None,
            pulled
                .is_ok()
                .then(|| "it did not come from a registry".to_string()),
        ),
        (Some(policy), Some(p)) => match attached(image, &source, p, offline, policy) {
            Ok(attested) => (Some(attested), None),
            Err(why) => (None, Some(why)),
        },
    };
    Prepared {
        id: image.id.clone(),
        source,
        digest,
        attested,
        vex_problem,
        opened: pulled.and_then(|p| open(image, p.as_ref())),
    }
}

fn open(image: &Image, pulled: Option<&crate::registry::Pulled>) -> Result<Opened, String> {
    // A pull already chose the platform: its layout holds the one image.
    let (path, platform) = match pulled {
        Some(p) => (p.layout.as_path(), None),
        None => (image.path.as_path(), image.platform.as_deref()),
    };
    let fs = fleetreach_os::open_image(path, &fleetreach_os::lang::wanted, platform)
        .map_err(|e| e.to_string())?;
    let inspection = fleetreach_os::inspect(&fs, image.distro.as_deref());
    let lang = fleetreach_os::lang::collect(&fs, &inspection.inventory.owned);
    let inventory = &inspection.inventory;
    let packaged_go: Vec<_> = fs
        .go_binaries()
        .filter_map(|(path, build)| packaged(inventory, path, (path.to_string(), build.clone())))
        .collect();
    let packaged_rust: Vec<_> = fs
        .rust_binaries()
        .filter(|(_, build)| build.audited)
        .filter_map(|(path, build)| packaged(inventory, path, (path.to_string(), build.clone())))
        .collect();
    let packaged_java: Vec<_> = lang
        .owned
        .java
        .iter()
        .filter_map(|found| packaged(inventory, archive_of(found)?, found.clone()))
        .collect();
    let owned_by = |installed: &[Installed]| -> Vec<Packaged<Installed>> {
        installed
            .iter()
            .filter_map(|i| packaged(inventory, &i.path, i.clone()))
            .collect()
    };
    let packaged_pypi = owned_by(&lang.owned.pypi);
    let packaged_npm = owned_by(&lang.owned.npm);
    let packaged_composer = owned_by(&lang.owned.composer);
    let packaged_nuget = owned_by(&lang.owned.nuget);
    let packaged_gems = owned_by(&lang.owned.gems);
    let files = tempfile::Builder::new()
        .prefix("fleetreach-image-")
        .tempdir()
        .map_err(|e| format!("creating a temporary directory: {e}"))?;
    for (path, data) in &lang.files {
        write_file(files.path(), path, data)?;
    }
    let installed = lang
        .pypi
        .iter()
        .chain(&lang.npm)
        .chain(&lang.composer)
        .chain(&lang.nuget)
        .chain(&lang.gems)
        .chain(
            [
                &packaged_pypi,
                &packaged_npm,
                &packaged_composer,
                &packaged_nuget,
                &packaged_gems,
            ]
            .into_iter()
            .flatten()
            .map(|p| &p.item),
        );
    let archives = lang
        .java
        .iter()
        .chain(packaged_java.iter().map(|p| &p.item))
        .filter_map(archive_of);
    let paths = lang
        .files
        .keys()
        .map(String::as_str)
        .chain(installed.map(|i| i.path.as_str()))
        .chain(archives)
        .chain(lang.go.iter().map(|(path, _)| path.as_str()))
        .chain(packaged_go.iter().map(|go| go.item.0.as_str()))
        .chain(lang.rust.iter().map(|(path, _)| path.as_str()))
        .chain(packaged_rust.iter().map(|rust| rust.item.0.as_str()))
        .collect();
    let layers = Layers::new(&fs, &inspection, paths);
    let lang_repo = Repo {
        id: image.id.clone(),
        path: files.path().to_path_buf(),
        glob: true,
        glob_max_depth: LANG_DEPTH,
        vex_product_id: None,
        ecosystem: None,
    };
    Ok(Opened {
        inspection,
        pypi: lang.pypi,
        npm: lang.npm,
        composer: lang.composer,
        nuget: lang.nuget,
        gems: lang.gems,
        java: lang.java,
        packaged_java,
        go: lang.go,
        packaged_go,
        rust: lang.rust,
        packaged_rust,
        packaged_pypi,
        packaged_npm,
        packaged_composer,
        packaged_nuget,
        packaged_gems,
        unread: lang.unread,
        skipped: fs.skipped().to_vec(),
        layers,
        _files: files,
        lang_repo,
    })
}

/// Write one image file under `root`. Image paths are already normalized (no `..`, no
/// leading `/`), so the join stays inside `root`.
fn write_file(root: &Path, rel: &str, data: &[u8]) -> Result<(), String> {
    let path: PathBuf = rel.split('/').fold(root.to_path_buf(), |p, c| p.join(c));
    if !path.starts_with(root) {
        return Err(format!("refusing image path {rel}"));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("writing {rel}: {e}"))?;
    }
    std::fs::write(&path, data).map_err(|e| format!("writing {rel}: {e}"))
}

/// The language ecosystems the images need OSV data for: what their lockfiles hold, plus
/// the ecosystems of installed packages read from metadata and archives.
pub(crate) fn language_ecosystems(images: &[Prepared]) -> BTreeSet<Ecosystem> {
    let mut out = BTreeSet::new();
    for image in images {
        let Ok(o) = &image.opened else { continue };
        for unit in crate::orchestrate::image_lang_units(&o.lang_repo) {
            out.insert(unit.ecosystem);
        }
        if !o.pypi.is_empty() || !o.packaged_pypi.is_empty() {
            out.insert(Ecosystem::Pypi);
        }
        if !o.npm.is_empty() || !o.packaged_npm.is_empty() {
            out.insert(Ecosystem::Npm);
        }
        if !o.gems.is_empty() || !o.packaged_gems.is_empty() {
            out.insert(Ecosystem::RubyGems);
        }
        if !o.composer.is_empty() || !o.packaged_composer.is_empty() {
            out.insert(Ecosystem::Packagist);
        }
        if !o.nuget.is_empty() || !o.packaged_nuget.is_empty() {
            out.insert(Ecosystem::NuGet);
        }
        if !o.java.is_empty() || !o.packaged_java.is_empty() {
            out.insert(Ecosystem::Maven);
        }
        if !o.go.is_empty() || !o.packaged_go.is_empty() {
            out.insert(Ecosystem::Go);
        }
        if !o.rust.is_empty() || !o.packaged_rust.is_empty() {
            out.insert(Ecosystem::Cargo);
        }
    }
    out
}

/// The distro ecosystems every image needs, sorted and deduplicated.
pub(crate) fn distro_ecosystems(images: &[Prepared]) -> Vec<String> {
    images
        .iter()
        .flat_map(Prepared::distro_ecosystems)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// An image named on the command line (`scan --image app.tar`): its id is the file name
/// without its archive extensions.
pub(crate) fn from_arg(path: &Path) -> Image {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let mut id = name.as_str();
    for ext in [".gz", ".zst", ".tgz", ".tar"] {
        id = id.strip_suffix(ext).unwrap_or(id);
    }
    let id = if id.is_empty() { name.as_str() } else { id };
    Image {
        id: RepoId(id.to_string()),
        path: path.to_path_buf(),
        reference: None,
        platform: None,
        distro: None,
    }
}

/// The `[[image]]` of `--image docker://<reference>`; its id is the reference as written.
pub(crate) fn from_reference(reference: &str) -> Result<Image, String> {
    crate::registry::Reference::parse(reference)?;
    Ok(Image {
        id: RepoId(reference.to_string()),
        path: PathBuf::new(),
        reference: Some(reference.to_string()),
        platform: None,
        distro: None,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn command_line_ids() {
        assert_eq!(from_arg(Path::new("out/app.tar")).id.0, "app");
        assert_eq!(from_arg(Path::new("app.tar.gz")).id.0, "app");
        assert_eq!(from_arg(Path::new("rootfs")).id.0, "rootfs");
        assert_eq!(from_arg(Path::new(".tar")).id.0, ".tar");
    }
}
