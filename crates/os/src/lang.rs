//! Language packages inside an image, for the existing language feeders.
//!
//! Two kinds of evidence are collected. **Lockfiles and manifests** (`package-lock.json`,
//! `Gemfile.lock`, `poetry.lock`, ...) are handed over as files, so each feeder reads them
//! exactly as it reads a repository. **Installed package metadata** that has no lockfile is
//! read here: Python `*.dist-info/METADATA` (and `*.egg-info/PKG-INFO`) and npm
//! `node_modules/<name>/package.json`. Anything owned by an OS package is skipped, because
//! the OS matcher already covers it (Trivy's rule): Debian's `python3-requests` is matched
//! as the Debian package, not again as the PyPI one.
//!
//! What is present but read by nothing here (Java archives, Go binaries, gems' `.gemspec`
//! files) is returned as a list, so the caller can report a coverage gap instead of a
//! silently partial scan.

use std::collections::{BTreeMap, BTreeSet};

use crate::image::ImageFs;

/// File names the language feeders read, kept when an image is opened.
pub const LOCKFILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "package.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "go.mod",
    "go.sum",
    "Gemfile.lock",
    "composer.lock",
    "composer.json",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "Pipfile",
    "pyproject.toml",
    "packages.lock.json",
    "packages.config",
    "Directory.Packages.props",
    "Directory.Build.props",
    "Manifest.toml",
    "Project.toml",
    "Package.resolved",
    "mix.lock",
    "gradle.lockfile",
    "pom.xml",
];

/// Directories never read for language files: VCS metadata and package caches.
const SKIP_PARTS: &[&str] = &[".git", ".cache", ".npm"];

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Whether `path` is a node_modules package manifest (`.../node_modules/x/package.json`,
/// `.../node_modules/@s/x/package.json`).
fn node_module_manifest(path: &str) -> bool {
    let Some(rest) = path
        .rsplit_once("node_modules/")
        .map(|(_, r)| r)
        .and_then(|r| r.strip_suffix("/package.json"))
    else {
        return false;
    };
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        [name] => !name.starts_with('.') && !name.starts_with('@'),
        [scope, _] => scope.starts_with('@'),
        _ => false,
    }
}

fn python_metadata(path: &str) -> bool {
    path.ends_with(".dist-info/METADATA") || path.ends_with(".egg-info/PKG-INFO")
}

/// The language files to keep when opening an image.
pub fn wanted(path: &str) -> bool {
    if path.split('/').any(|p| SKIP_PARTS.contains(&p)) {
        return false;
    }
    let name = basename(path);
    if path.contains("node_modules/") {
        return node_module_manifest(path);
    }
    python_metadata(path)
        || LOCKFILES.contains(&name)
        || (name.starts_with("requirements") && name.ends_with(".txt"))
        || (name.starts_with("pylock") && name.ends_with(".toml"))
        || [".csproj", ".fsproj", ".vbproj"]
            .iter()
            .any(|e| name.ends_with(e))
}

/// An installed language package read from its metadata.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Installed {
    pub name: String,
    pub version: String,
    /// Where it was found, relative to `/`.
    pub path: String,
}

/// The language evidence in an image.
#[derive(Debug, Clone, Default)]
pub struct LangFiles {
    /// Lockfiles and manifests not owned by an OS package, `path -> content`.
    pub files: BTreeMap<String, Vec<u8>>,
    /// Installed PyPI distributions (dist-info / egg-info).
    pub pypi: Vec<Installed>,
    /// Installed npm packages (node_modules).
    pub npm: Vec<Installed>,
    /// Kinds of language artifact present but not read, with a count (`"*.jar": 12`).
    pub unread: BTreeMap<&'static str, usize>,
    /// How many candidates were skipped because an OS package owns them.
    pub os_owned: usize,
}

fn email_header(text: &str, key: &str) -> Option<String> {
    text.lines()
        .take_while(|l| !l.is_empty())
        .find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix(':')))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Collect the language evidence of `fs`, skipping paths in `owned`.
pub fn collect(fs: &ImageFs, owned: &BTreeSet<String>) -> LangFiles {
    let mut out = LangFiles::default();
    for (path, data) in fs.files() {
        let name = basename(path);
        let unread = if name.ends_with(".jar") || name.ends_with(".war") || name.ends_with(".ear") {
            Some("Java archives (*.jar, *.war, *.ear)")
        } else if path.contains("/specifications/") && name.ends_with(".gemspec") {
            Some("installed gems (specifications/*.gemspec)")
        } else {
            None
        };
        if let Some(kind) = unread {
            if !owned.contains(path) {
                *out.unread.entry(kind).or_default() += 1;
            } else {
                out.os_owned += 1;
            }
            continue;
        }
        let Some(data) = data else { continue };
        if !wanted(path) {
            continue;
        }
        if owned.contains(path) {
            out.os_owned += 1;
            continue;
        }
        if python_metadata(path) {
            let text = String::from_utf8_lossy(data);
            if let (Some(n), Some(v)) =
                (email_header(&text, "Name"), email_header(&text, "Version"))
            {
                out.pypi.push(Installed {
                    name: n,
                    version: v,
                    path: path.to_string(),
                });
            }
            continue;
        }
        if node_module_manifest(path) {
            #[derive(serde::Deserialize)]
            struct Manifest {
                name: Option<String>,
                version: Option<String>,
            }
            if let Ok(Manifest {
                name: Some(n),
                version: Some(v),
            }) = serde_json::from_slice::<Manifest>(data)
            {
                out.npm.push(Installed {
                    name: n,
                    version: v,
                    path: path.to_string(),
                });
            }
            continue;
        }
        out.files.insert(path.to_string(), data.to_vec());
    }
    // Packages under a project whose lockfile was kept are scanned from that lockfile.
    let locked: Vec<String> = out
        .files
        .keys()
        .filter(|p| {
            matches!(
                basename(p),
                "package-lock.json"
                    | "npm-shrinkwrap.json"
                    | "yarn.lock"
                    | "pnpm-lock.yaml"
                    | "bun.lock"
            )
        })
        .map(|p| match p.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/node_modules/"),
            None => "node_modules/".to_string(),
        })
        .collect();
    out.npm
        .retain(|i| !locked.iter().any(|l| i.path.starts_with(l.as_str())));
    out.pypi.sort();
    out.npm.sort();
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn selects_lockfiles_and_installed_metadata() {
        assert!(wanted("app/package-lock.json"));
        assert!(wanted(
            "usr/local/lib/python3.12/site-packages/pip-24.0.dist-info/METADATA"
        ));
        assert!(wanted("usr/local/lib/node_modules/npm/package.json"));
        assert!(wanted("app/node_modules/@scope/x/package.json"));
        assert!(!wanted("app/node_modules/x/lib/package.json"));
        assert!(!wanted("app/node_modules/x/package-lock.json"));
        assert!(!wanted("root/.cache/pip/x/requirements.txt"));
        assert!(wanted("srv/requirements-prod.txt"));
    }

    #[test]
    fn os_owned_files_are_not_reported_twice() {
        let fs = ImageFs::from_files([
            (
                "usr/lib/python3/dist-packages/requests-2.28.1.dist-info/METADATA",
                &b"Metadata-Version: 2.1\nName: requests\nVersion: 2.28.1\n"[..],
            ),
            (
                "usr/local/lib/python3.12/site-packages/pip-24.0.dist-info/METADATA",
                &b"Name: pip\nVersion: 24.0\n\nName: not-a-header\n"[..],
            ),
            ("app/Gemfile.lock", &b"GEM\n"[..]),
            ("usr/share/java/x.jar", &b""[..]),
        ]);
        let owned: BTreeSet<String> =
            ["usr/lib/python3/dist-packages/requests-2.28.1.dist-info/METADATA".to_string()].into();
        let lang = collect(&fs, &owned);
        assert_eq!(lang.pypi.len(), 1);
        assert_eq!(
            (lang.pypi[0].name.as_str(), lang.pypi[0].version.as_str()),
            ("pip", "24.0")
        );
        assert_eq!(lang.os_owned, 1);
        assert!(lang.files.contains_key("app/Gemfile.lock"));
        assert_eq!(lang.unread.values().sum::<usize>(), 1);
    }
}
