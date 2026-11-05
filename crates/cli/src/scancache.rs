//! Reusing a repo's results between runs (`scan --incremental`, spec 16 row 1).
//!
//! A repo's merged findings are reused when nothing they came from has changed: the same
//! binary (which covers every parser), the same advisory data for its ecosystems, and the same
//! files. Whatever follows matching (enrichment, reachability, suppression, ranking) runs
//! as usual on the reused findings. With every repo of an ecosystem reused, its advisory
//! database is not even loaded.
//!
//! A repo's files count by their bytes, and only those a feeder can read ([`is_input`]): a
//! source edit or a fresh clone keeps the entry, and stating every file would cost what the
//! scan saves. Repos whose findings depend on more than that are never reused: Maven (POMs in
//! `~/.m2` or the network), SBOM inputs, govulncheck, the host's build resolution, a link loop,
//! and a pip file including something [`is_input`] does not cover. An errored repo is not
//! stored either, so it is tried again.

use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind::NotFound;
use std::path::{Path, PathBuf};

use fleetreach_core::Ecosystem;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::config::Repo;
use crate::orchestrate::SKIPPED_DIRS;

/// One entry per repo, so a changed repo overwrites its entry and the cache cannot grow past
/// the fleet.
#[derive(Serialize, Deserialize)]
struct Entry<T> {
    key: String,
    result: T,
}

/// Where entries live.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self, repo: &Repo) -> PathBuf {
        let name = hex(Sha256::digest(format!(
            "{}\0{}",
            repo.id,
            repo.path.display()
        )));
        self.dir.join(name.get(..2).unwrap_or("00")).join(name)
    }

    /// The entry stored for `repo` under exactly `key`. A damaged entry is a miss.
    pub(crate) fn get<T: DeserializeOwned>(&self, repo: &Repo, key: &str) -> Option<T> {
        let bytes = fleetreach_core::repofile::read(self.path(repo)).ok()?;
        let entry: Entry<T> = serde_json::from_slice(&bytes).ok()?;
        (entry.key == key).then_some(entry.result)
    }

    /// Best-effort: an entry that cannot be written is a miss next time.
    pub(crate) fn put<T: Serialize>(&self, repo: &Repo, key: &str, result: T) {
        let path = self.path(repo);
        let Some(parent) = path.parent() else { return };
        if crate::osvdb::create_private_dir(parent).is_err() {
            return;
        }
        let entry = Entry {
            key: key.to_string(),
            result,
        };
        let Ok(json) = serde_json::to_vec(&entry) else {
            return;
        };
        let tmp = path.with_extension(format!("{}.partial", std::process::id()));
        if std::fs::write(&tmp, json).is_ok() && std::fs::rename(&tmp, &path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// A file or tree of advisory data, by content. `None` when it cannot be read. A synced export
/// has its hash on record, which saves reading it on every run.
fn data_identity(path: &Path) -> Option<String> {
    if path.is_file() {
        let size = std::fs::metadata(path).ok()?.len();
        return match crate::osvdb::read_meta(path).filter(|meta| meta.size == size) {
            Some(meta) if !meta.sha256.is_empty() => Some(meta.sha256),
            _ => crate::curated::sha256_file(path).ok().map(|(sha, _)| sha),
        };
    }
    let mut hasher = Sha256::new();
    for entry in WalkDir::new(path).sort_by_file_name() {
        let entry = entry.ok()?;
        if entry.file_type().is_file() {
            let (sha, _) = crate::curated::sha256_file(entry.path()).ok()?;
            hasher.update(
                entry
                    .path()
                    .strip_prefix(path)
                    .ok()?
                    .to_string_lossy()
                    .as_bytes(),
            );
            hasher.update(sha);
        }
    }
    Some(hex(hasher.finalize()))
}

/// A mirror's identity: `Some("none")` with no mirror, `None` when it cannot be pinned down,
/// as a mirror on the network cannot.
#[must_use]
pub(crate) fn mirror_identity(url: Option<&str>) -> Option<String> {
    let Some(url) = url else {
        return Some("none".to_string());
    };
    data_identity(Path::new(url.strip_prefix("file://")?))
}

/// What every entry of this run is keyed on besides a repo's own files.
pub(crate) struct Session<'a> {
    pub(crate) store: &'a Store,
    /// The binary and the overlay.
    common: String,
    advisories: BTreeMap<Ecosystem, Option<String>>,
}

impl<'a> Session<'a> {
    /// `None` when the binary or the overlay cannot be read, so nothing can be vouched for.
    pub(crate) fn open(
        store: &'a Store,
        overlay: Option<&Path>,
        advisories: BTreeMap<Ecosystem, Option<String>>,
    ) -> Option<Self> {
        let binary = data_identity(&std::env::current_exe().ok()?)?;
        let overlay = match overlay {
            Some(dir) => data_identity(dir)?,
            None => String::new(),
        };
        Some(Self {
            store,
            common: format!("{binary}\0{overlay}"),
            advisories,
        })
    }

    /// The key of a repo planned as `units`, reading `inputs`, or `None` when it must be
    /// scanned.
    pub(crate) fn key(
        &self,
        repo: &Repo,
        units: &[(Ecosystem, String, bool)],
        inputs: &Inputs,
    ) -> Option<String> {
        let mut hasher = Sha256::new();
        hasher.update(&self.common);
        hasher.update(format!("\0{repo:?}\0{units:?}\0"));
        let ecosystems: BTreeSet<Ecosystem> = units.iter().map(|u| u.0).collect();
        for eco in &ecosystems {
            hasher.update(self.advisories.get(eco)?.as_deref()?);
        }
        for file in &inputs.files {
            hash_file(&repo.path, file, &mut hasher)?;
        }
        for tree in &inputs.trees {
            hash_tree(&repo.path, tree, &mut hasher)?;
        }
        if ecosystems.contains(&Ecosystem::NuGet) {
            hash_ancestor_props(&repo.path, &mut hasher)?;
        }
        Some(hex(hasher.finalize()))
    }
}

/// Where a repo's scan reads from. Walking a whole tree costs what a scan does, so an ecosystem
/// known to read exact files lists them.
#[derive(Default)]
pub(crate) struct Inputs {
    /// Read whole, or noted as absent.
    pub(crate) files: BTreeSet<PathBuf>,
    /// Every [`is_input`] file below these counts.
    pub(crate) trees: BTreeSet<PathBuf>,
}

/// A file a feeder can read. `docs/differential/scan_inputs.py` checks this against what a scan
/// really opens, under strace, across every ecosystem.
fn is_input(name: &str) -> bool {
    let extension = name.rsplit_once('.').map_or("", |(_, extension)| extension);
    matches!(
        extension,
        "lock"
            | "lockb"
            | "lockfile"
            | "toml"
            | "yml"
            | "yaml"
            | "txt"
            | "in"
            | "cfg"
            | "mod"
            | "go"
            | "sum"
            | "work"
            | "resolved"
            | "swift"
            | "exs"
            | "gemspec"
            | "csproj"
            | "fsproj"
            | "vbproj"
            | "props"
            | "targets"
            | "sln"
            | "slnx"
            | "config"
    ) || name.ends_with("-lock.json")
        || name.ends_with(".lock.json")
        || matches!(
            name,
            "package.json"
                | "composer.json"
                | "Gemfile"
                | "Pipfile"
                | "setup.py"
                | "project.assets.json"
                | "npm-shrinkwrap.json"
        )
}

/// What a pip file pulls in by name: it may be named anything, so one that [`is_input`] does
/// not cover makes the repo one this cache cannot vouch for.
fn names_other_files(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();
        ["-r", "-c", "--requirement", "--constraint"]
            .iter()
            .filter_map(|flag| line.strip_prefix(flag))
            .filter(|rest| rest.starts_with([' ', '\t', '=']))
            .any(|rest| {
                let target = rest.trim_start_matches([' ', '\t', '=']);
                let target = target.split_whitespace().next().unwrap_or_default();
                let name = Path::new(target).file_name().unwrap_or_default();
                !is_input(&name.to_string_lossy())
            })
    })
}

/// Add a file's name and bytes. `None` only when it exists and cannot be read.
fn hash_file(root: &Path, path: &Path, hasher: &mut Sha256) -> Option<()> {
    hasher.update(
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .as_bytes(),
    );
    hasher.update(b"\0");
    match fleetreach_core::repofile::read(path) {
        Ok(bytes) => {
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            let pip = name.ends_with(".txt") || name.ends_with(".in");
            if pip && names_other_files(&String::from_utf8_lossy(&bytes)) {
                return None;
            }
        }
        // Absent, or a dangling link: nothing to read.
        Err(e) if e.kind() == NotFound => {}
        Err(_) => return None,
    }
    Some(())
}

fn hash_tree(root: &Path, tree: &Path, hasher: &mut Sha256) -> Option<()> {
    // Following links, so what a linked directory holds counts as a feeder would see it.
    let walk = WalkDir::new(tree)
        .follow_links(true)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| {
            !(e.file_type().is_dir() && SKIPPED_DIRS.iter().any(|d| e.file_name() == *d))
        });
    for entry in walk {
        let entry = match entry {
            Ok(entry) => entry,
            // A dangling link, or a `.github` with nothing in it, holds nothing to read.
            Err(e) if e.io_error().is_some_and(|e| e.kind() == NotFound) => continue,
            Err(_) => return None,
        };
        if entry.file_type().is_file() && is_input(&entry.file_name().to_string_lossy()) {
            hash_file(root, entry.path(), hasher)?;
        }
    }
    Some(())
}

/// NuGet reads `Directory.*.props` from the directories above a project, up to the repository
/// root, which may be above a fleet entry.
fn hash_ancestor_props(root: &Path, hasher: &mut Sha256) -> Option<()> {
    for dir in root.ancestors().skip(1) {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("Directory."))
            .collect();
        names.sort();
        for name in names {
            hasher.update(name.as_bytes());
            hasher.update(fleetreach_core::repofile::read(dir.join(name)).ok()?);
        }
    }
    Some(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fleetreach_core::RepoId;

    fn repo(path: &Path) -> Repo {
        Repo {
            id: RepoId("r".to_string()),
            path: path.to_path_buf(),
            glob: true,
            glob_max_depth: 4,
            vex_product_id: None,
            ecosystem: None,
        }
    }

    fn session(store: &Store, npm: Option<&str>) -> Session<'static> {
        let store: &'static Store = Box::leak(Box::new(store.clone()));
        let advisories = BTreeMap::from([(Ecosystem::Npm, npm.map(str::to_string))]);
        Session::open(store, None, advisories).unwrap()
    }

    const NPM: &[(Ecosystem, String, bool)] = &[(Ecosystem::Npm, String::new(), false)];

    fn whole(root: &Path) -> Inputs {
        Inputs {
            files: BTreeSet::new(),
            trees: BTreeSet::from([root.to_path_buf()]),
        }
    }

    #[test]
    fn a_key_follows_every_input() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir_all(root.join("node_modules")).unwrap();
        std::fs::write(root.join("package-lock.json"), "{1}").unwrap();
        let store = Store::new(dir.path().join("cache"));
        let s = session(&store, Some("db1"));
        let (r, all) = (repo(&root), whole(&root));
        let first = s.key(&r, NPM, &all).unwrap();
        assert_eq!(s.key(&r, NPM, &all).unwrap(), first);

        // Ignored: what no feeder reads.
        std::fs::write(root.join("node_modules/x"), "y").unwrap();
        assert_eq!(s.key(&r, NPM, &all).unwrap(), first);

        // Same size, new bytes.
        std::fs::write(root.join("package-lock.json"), "{2}").unwrap();
        let second = s.key(&r, NPM, &all).unwrap();
        assert_ne!(second, first);

        // A source file is no input.
        std::fs::write(root.join("main.js"), "x").unwrap();
        assert_eq!(s.key(&r, NPM, &all).unwrap(), second);

        // A new file is, when it could be read.
        std::fs::write(root.join("pnpm-workspace.yaml"), "x").unwrap();
        let third = s.key(&r, NPM, &all).unwrap();
        assert_ne!(third, second);

        assert_ne!(
            session(&store, Some("db2")).key(&r, NPM, &all).unwrap(),
            third
        );
        assert!(session(&store, None).key(&r, NPM, &all).is_none());
        let units = [(Ecosystem::Hex, String::new(), false)];
        assert!(
            s.key(&r, &units, &all).is_none(),
            "an ecosystem with no identity"
        );
    }

    #[test]
    fn a_pip_include_of_an_unlisted_name_cannot_be_vouched_for() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let store = Store::new(dir.path().join("cache"));
        let s = session(&store, Some("db"));
        std::fs::write(
            root.join("requirements.txt"),
            "-r base.txt\n-c=pins.txt\nflask\n",
        )
        .unwrap();
        assert!(s.key(&repo(&root), NPM, &whole(&root)).is_some());
        for line in ["-r base.reqs", "--requirement=x/base.pip", "-c\tpins"] {
            std::fs::write(root.join("requirements.txt"), line).unwrap();
            assert!(s.key(&repo(&root), NPM, &whole(&root)).is_none(), "{line}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_directory_counts_and_a_loop_cannot_be_vouched_for() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        let shared = dir.path().join("shared");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&shared).unwrap();
        std::os::unix::fs::symlink(&shared, root.join("shared")).unwrap();
        std::os::unix::fs::symlink("/does/not/exist", root.join("dangling")).unwrap();
        let store = Store::new(dir.path().join("cache"));
        let s = session(&store, Some("db"));
        let (r, all) = (repo(&root), whole(&root));
        let before = s.key(&r, NPM, &all).unwrap();
        std::fs::write(shared.join("yarn.lock"), "x").unwrap();
        assert_ne!(s.key(&r, NPM, &all).unwrap(), before);
        std::os::unix::fs::symlink(dir.path(), root.join("up")).unwrap();
        assert!(s.key(&r, NPM, &all).is_none());
    }

    #[test]
    fn listed_files_count_even_when_they_appear() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let store = Store::new(dir.path().join("cache"));
        let s = session(&store, Some("db"));
        let inputs = Inputs {
            files: BTreeSet::from([root.join("Cargo.lock")]),
            trees: BTreeSet::from([root.join(".github")]),
        };
        let r = repo(&root);
        let absent = s.key(&r, NPM, &inputs).unwrap();
        std::fs::write(root.join("Cargo.lock"), "a").unwrap();
        let present = s.key(&r, NPM, &inputs).unwrap();
        assert_ne!(absent, present);
        std::fs::write(root.join("main.rs"), "a").unwrap();
        assert_eq!(s.key(&r, NPM, &inputs).unwrap(), present);
        std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
        std::fs::write(root.join(".github/workflows/ci.yml"), "a").unwrap();
        assert_ne!(s.key(&r, NPM, &inputs).unwrap(), present);
    }

    #[test]
    fn nuget_counts_props_above_the_repo() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let units = [(Ecosystem::NuGet, String::new(), false)];
        let store = Store::new(dir.path().join("cache"));
        let advisories = BTreeMap::from([(Ecosystem::NuGet, Some("db".to_string()))]);
        let s = Session::open(&store, None, advisories).unwrap();
        let before = s.key(&repo(&root), &units, &whole(&root)).unwrap();
        std::fs::write(dir.path().join("Directory.Packages.props"), "<x/>").unwrap();
        assert_ne!(s.key(&repo(&root), &units, &whole(&root)).unwrap(), before);
    }

    #[test]
    fn an_entry_answers_only_its_own_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("cache"));
        let r = repo(dir.path());
        assert_eq!(store.get::<u32>(&r, "k"), None);
        store.put(&r, "k", 7u32);
        assert_eq!(store.get::<u32>(&r, "k"), Some(7));
        assert_eq!(store.get::<u32>(&r, "other"), None);
        std::fs::write(store.path(&r), "not json").unwrap();
        assert_eq!(store.get::<u32>(&r, "k"), None);
    }

    #[test]
    fn a_mirror_is_known_by_its_content() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("all.zip");
        std::fs::write(&file, "a").unwrap();
        let url = format!("file://{}", file.display());
        let first = mirror_identity(Some(&url)).unwrap();
        std::fs::write(&file, "b").unwrap();
        assert_ne!(mirror_identity(Some(&url)).unwrap(), first);
        assert_eq!(mirror_identity(None).unwrap(), "none");
        assert!(mirror_identity(Some("https://example.com/db")).is_none());
        assert!(mirror_identity(Some("file:///does/not/exist")).is_none());
    }
}
