//! Language packages inside an image, for the existing language feeders.
//!
//! Two kinds of evidence are collected. **Lockfiles and manifests** (`package-lock.json`,
//! `Gemfile.lock`, `poetry.lock`, ...) are handed over as files, so each feeder reads them
//! exactly as it reads a repository. **Installed package metadata** that has no lockfile is
//! read here: Python `*.dist-info/METADATA` (and `*.egg-info/PKG-INFO`), npm
//! `node_modules/<name>/package.json`, Ruby `specifications/*.gemspec` and Java archives
//! (see [`crate::jar`]). Anything owned by an OS package is skipped, because
//! the OS matcher already covers it (Trivy's rule): Debian's `python3-requests` is matched
//! as the Debian package, not again as the PyPI one.
//!
//! What is present but read by nothing here (a Java archive nothing identifies, one too large
//! or broken to read) is returned as a list, so the caller can report a coverage gap instead
//! of a silently partial scan.

use std::collections::{BTreeMap, BTreeSet};

use crate::image::ImageFs;
use crate::jar::{self, Found};

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

/// Whether `path` is an installed gem's specification (`.../specifications/rack-2.2.8.gemspec`,
/// or `.../specifications/default/` for those that ship with Ruby).
fn gemspec(path: &str) -> bool {
    path.ends_with(".gemspec")
        && (path.contains("/specifications/") || path.starts_with("specifications/"))
}

/// A gem's name and version from its specification (`s.name = "rack".freeze`), falling back on
/// its file name (`rack-2.2.8.gemspec`, `nokogiri-1.16.0-x86_64-linux.gemspec`).
fn gem_identity(path: &str, text: &str) -> Option<(String, String)> {
    let field = |key: &str| {
        text.lines().find_map(|l| {
            let (lhs, rhs) = l.split_once('=')?;
            let lhs = lhs.trim();
            if lhs.rsplit('.').next() != Some(key) || !lhs.contains('.') {
                return None;
            }
            let quote = rhs.find(['"', '\''])?;
            let rest = &rhs[quote + 1..];
            let end = rest.find(['"', '\''])?;
            Some(rest[..end].to_string()).filter(|v| !v.is_empty())
        })
    };
    if let (Some(name), Some(version)) = (field("name"), field("version")) {
        return Some((name, version));
    }
    let stem = basename(path).strip_suffix(".gemspec")?;
    let at = stem
        .char_indices()
        .find(|(i, c)| {
            *c == '-'
                && stem[i + 1..]
                    .chars()
                    .next()
                    .is_some_and(|d| d.is_ascii_digit())
        })?
        .0;
    let version = stem[at + 1..].split('-').next()?;
    Some((stem[..at].to_string(), version.to_string()))
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
    if jar::is_archive(path) {
        return true;
    }
    if path.contains("node_modules/") {
        return node_module_manifest(path);
    }
    python_metadata(path)
        || gemspec(path)
        || LOCKFILES.contains(&name)
        || (name.starts_with("requirements") && name.ends_with(".txt"))
        || (name.starts_with("pylock") && name.ends_with(".toml"))
        || [".csproj", ".fsproj", ".vbproj"]
            .iter()
            .any(|e| name.ends_with(e))
}

/// The coverage-gap kind for Java archives nothing identifies.
pub const JAVA_UNREAD: &str = "Java archives (*.jar, *.war, *.ear) with no coordinates";

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
    /// Installed gems (`specifications/*.gemspec`).
    pub gems: Vec<Installed>,
    /// What the image's Java archives hold, nested archives included.
    pub java: Vec<Found>,
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
        if jar::is_archive(name) {
            if owned.contains(path) {
                out.os_owned += 1;
            } else if let Some(digest) = data {
                out.java.extend(jar::parse_digest(digest));
            } else {
                // Under a package cache, or too large to read.
                *out.unread.entry(JAVA_UNREAD).or_default() += 1;
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
        if gemspec(path) {
            let text = String::from_utf8_lossy(data);
            match gem_identity(path, &text) {
                Some((name, version)) => out.gems.push(Installed {
                    name,
                    version,
                    path: path.to_string(),
                }),
                None => {
                    *out.unread
                        .entry("gem specifications that name no gem")
                        .or_default() += 1;
                }
            }
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
    out.gems.sort();
    out.gems
        .dedup_by(|a, b| a.name == b.name && a.version == b.version);
    for found in &out.java {
        if matches!(found, Found::Unknown { .. } | Found::Unreadable { .. }) {
            *out.unread.entry(JAVA_UNREAD).or_default() += 1;
        }
    }
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
        // An archive with nothing in it to identify it.
        assert_eq!(lang.unread.values().sum::<usize>(), 1);
    }

    #[test]
    fn gems_from_specifications() {
        let path = "usr/local/bundle/specifications/rack-2.2.8.gemspec";
        assert!(wanted(path));
        assert!(wanted(
            "usr/local/lib/ruby/gems/3.2.0/specifications/default/json-2.6.3.gemspec"
        ));
        assert!(!wanted("app/my.gemspec"));
        let text = "# stub: rack 2.2.8 ruby lib\nGem::Specification.new do |s|\n  \
                    s.name = \"rack\".freeze\n  s.version = \"2.2.8\"\n  \
                    s.required_rubygems_version = Gem::Requirement.new(\">= 0\".freeze)\n";
        assert_eq!(
            gem_identity(path, text),
            Some(("rack".to_string(), "2.2.8".to_string()))
        );
        // A spec the reader cannot follow: the file name.
        assert_eq!(
            gem_identity("x/specifications/nokogiri-1.16.0-x86_64-linux.gemspec", ""),
            Some(("nokogiri".to_string(), "1.16.0".to_string()))
        );
        let fs = ImageFs::from_files([(path, text.as_bytes())]);
        let lang = collect(&fs, &BTreeSet::new());
        assert_eq!(lang.gems[0].name, "rack");
    }
}
