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
    pub(crate) opened: Result<Opened, String>,
}

/// What an opened image holds.
pub(crate) struct Opened {
    pub(crate) inspection: Inspection,
    /// Installed PyPI and npm packages with no lockfile beside them.
    pub(crate) pypi: Vec<Installed>,
    pub(crate) npm: Vec<Installed>,
    /// Installed gems.
    pub(crate) gems: Vec<Installed>,
    /// What the image's Java archives hold.
    pub(crate) java: Vec<fleetreach_os::jar::Found>,
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
pub(crate) fn prepare_all(images: &[Image], offline: bool) -> Vec<Prepared> {
    images.par_iter().map(|i| prepare(i, offline)).collect()
}

fn prepare(image: &Image, offline: bool) -> Prepared {
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
    Prepared {
        id: image.id.clone(),
        source,
        digest,
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
    let files = tempfile::Builder::new()
        .prefix("fleetreach-image-")
        .tempdir()
        .map_err(|e| format!("creating a temporary directory: {e}"))?;
    for (path, data) in &lang.files {
        write_file(files.path(), path, data)?;
    }
    let installed = lang.pypi.iter().chain(&lang.npm).chain(&lang.gems);
    let archives = lang.java.iter().filter_map(|f| match f {
        Found::Coordinates { path, .. }
        | Found::FileName { path, .. }
        | Found::Bundle { path, .. } => path.split('!').next(),
        Found::Unknown { .. } | Found::Unreadable { .. } => None,
    });
    let paths = lang
        .files
        .keys()
        .map(String::as_str)
        .chain(installed.map(|i| i.path.as_str()))
        .chain(archives)
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
        gems: lang.gems,
        java: lang.java,
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
        if !o.pypi.is_empty() {
            out.insert(Ecosystem::Pypi);
        }
        if !o.npm.is_empty() {
            out.insert(Ecosystem::Npm);
        }
        if !o.gems.is_empty() {
            out.insert(Ecosystem::RubyGems);
        }
        if !o.java.is_empty() {
            out.insert(Ecosystem::Maven);
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
