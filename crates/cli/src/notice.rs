//! `licenses --notice <dir>` (spec 16, row 20): one attribution file per repo, from the license
//! and notice files its runtime packages ship.
//!
//! Packages are grouped by the exact text of their license files, so a hundred MIT crates with
//! the same text print it once, as `cargo about` does, while texts that differ (their copyright
//! lines) each print. `NOTICE` files, which Apache-2.0 section 4(d) asks to be passed on, are
//! reproduced per package, and so are the license files of code a package bundles in a
//! subdirectory (`third_party/fiat/LICENSE`), where it has them. A package whose own license
//! files are not on this machine is listed at the end, so the file never reads as complete when
//! it is not.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use fleetreach_core::Ecosystem;

use crate::licenses::{ecosystem_name, Decision};
use crate::licensetext::{read_license_files, read_nested_license_files, read_notice_files};

/// One package's attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub license: Option<String>,
}

impl Package {
    fn label(&self) -> String {
        format!("{} {} ({})", self.name, self.version, self.ecosystem)
    }
}

/// What one repo's attribution file holds.
#[derive(Debug, Default)]
pub struct Attribution {
    /// License texts, each with the packages that ship it word for word.
    pub texts: BTreeMap<String, Vec<Package>>,
    /// Notice files, per package: `(package, file name, text)`.
    pub notices: Vec<(Package, String, String)>,
    /// Packages whose files were not on this machine.
    pub missing: Vec<Package>,
    /// Packages whose files came from a cache entry written before notice files were kept.
    pub notices_unknown: Vec<Package>,
}

/// The attribution of one repo's runtime packages. `dirs` says where each package's files are,
/// by `(ecosystem, name, version)`.
pub fn attribution(
    repo: &str,
    decisions: &[Decision],
    dirs: &BTreeMap<(Ecosystem, String, String), PathBuf>,
) -> Attribution {
    let mut out = Attribution::default();
    let mut seen = std::collections::BTreeSet::new();
    let cache = crate::licensefetch::cache_root();
    let by_name: BTreeMap<(String, &str, &str), &PathBuf> = dirs
        .iter()
        .map(|((eco, name, version), dir)| {
            ((ecosystem_name(*eco), name.as_str(), version.as_str()), dir)
        })
        .collect();
    for d in decisions.iter().filter(|d| d.repo == repo && !d.dev) {
        if !seen.insert((d.ecosystem.clone(), d.package.clone(), d.version.clone())) {
            continue;
        }
        let package = Package {
            ecosystem: d.ecosystem.clone(),
            name: d.package.clone(),
            version: d.version.clone(),
            license: d.license.clone(),
        };
        let dir = by_name
            .get(&(d.ecosystem.clone(), d.package.as_str(), d.version.as_str()))
            .copied();
        let Some(dir) = dir else {
            out.missing.push(package);
            continue;
        };
        let files = read_license_files(dir);
        if files.is_empty() {
            out.missing.push(package.clone());
        }
        let files: Vec<_> = files
            .into_iter()
            .chain(read_nested_license_files(dir))
            .collect();
        let text: String = files
            .iter()
            .map(|(name, bytes)| format!("{name}:\n\n{}", text_of(bytes)))
            .collect::<Vec<_>>()
            .join("\n\n");
        if !text.is_empty() {
            out.texts.entry(text).or_default().push(package.clone());
        }
        let cached = cache.as_deref().is_some_and(|root| dir.starts_with(root));
        if cached && !crate::licensefetch::notices_kept(dir) {
            out.notices_unknown.push(package.clone());
        }
        for (name, bytes) in read_notice_files(dir) {
            out.notices.push((package.clone(), name, text_of(&bytes)));
        }
    }
    out
}

fn text_of(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes).replace("\r\n", "\n");
    let text: String = text
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect();
    text.trim_end().to_string()
}

/// The attribution file's text.
pub fn render(repo: &str, a: &Attribution) -> String {
    let rule = "=".repeat(78);
    let mut out = String::new();
    let packages: usize = a.texts.values().map(Vec::len).sum::<usize>() + a.missing.len();
    let _ = writeln!(out, "Third-party software in {repo}");
    let _ = writeln!(
        out,
        "\nThis file lists the licenses and notices of the {packages} runtime package(s) the \
         repo's lockfiles name, from the license files they ship. Written by fleetreach."
    );
    let mut groups: Vec<(&String, &Vec<Package>)> = a.texts.iter().collect();
    // Most-used text first, then by first package, so the order holds from run to run.
    groups.sort_by(|x, y| {
        y.1.len()
            .cmp(&x.1.len())
            .then_with(|| x.1[0].label().cmp(&y.1[0].label()))
    });
    for (text, users) in groups {
        let mut licenses: Vec<&str> = users.iter().filter_map(|p| p.license.as_deref()).collect();
        licenses.sort_unstable();
        licenses.dedup();
        let _ = writeln!(out, "\n{rule}");
        let _ = writeln!(
            out,
            "{}",
            if licenses.is_empty() {
                "License not declared".to_string()
            } else {
                licenses.join("; ")
            }
        );
        let _ = writeln!(out, "Used by:");
        let mut labels: Vec<String> = users.iter().map(Package::label).collect();
        labels.sort();
        for label in labels {
            let _ = writeln!(out, "  - {label}");
        }
        let _ = writeln!(out, "{rule}\n\n{text}");
    }
    if !a.notices.is_empty() {
        let _ = writeln!(out, "\n{rule}\nNotices\n{rule}");
        for (package, name, text) in &a.notices {
            let _ = writeln!(out, "\n--- {} {name}\n\n{text}", package.label());
        }
    }
    if !a.missing.is_empty() {
        let _ = writeln!(
            out,
            "\n{rule}\nNo license file found on this machine\n{rule}\n"
        );
        let mut labels: Vec<String> = a
            .missing
            .iter()
            .map(|p| match &p.license {
                Some(l) => format!("  - {}: declares {l}", p.label()),
                None => format!("  - {}: no license declared", p.label()),
            })
            .collect();
        labels.sort();
        for label in labels {
            let _ = writeln!(out, "{label}");
        }
    }
    out
}

/// The file name of a repo's attribution file: its id with anything but letters, digits, `-`,
/// `_` and `.` made `_`.
pub fn file_name(repo: &str) -> String {
    let safe: String = repo
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let safe = safe.trim_start_matches('.');
    format!("{}.NOTICE.txt", if safe.is_empty() { "repo" } else { safe })
}

/// Write every repo's attribution file into `dir`. Returns how many packages, over all repos,
/// have no license file here and how many have notices not checked.
pub fn write_all(
    dir: &Path,
    repos: &[String],
    decisions: &[Decision],
    dirs: &BTreeMap<(String, Ecosystem, String, String), PathBuf>,
) -> Result<(usize, usize), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (mut missing, mut unknown) = (0, 0);
    for repo in repos {
        let mine: BTreeMap<(Ecosystem, String, String), PathBuf> = dirs
            .iter()
            .filter(|((r, ..), _)| r == repo)
            .map(|((_, eco, name, version), path)| {
                ((*eco, name.clone(), version.clone()), path.clone())
            })
            .collect();
        let a = attribution(repo, decisions, &mine);
        missing += a.missing.len();
        unknown += a.notices_unknown.len();
        let path = dir.join(file_name(repo));
        std::fs::write(&path, render(repo, &a)).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok((missing, unknown))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::licenses::{Category, Verdict};

    fn decision(repo: &str, name: &str, license: &str, dev: bool) -> Decision {
        Decision {
            repo: repo.into(),
            ecosystem: ecosystem_name(Ecosystem::Cargo),
            package: name.into(),
            version: "1.0.0".into(),
            license: Some(license.into()),
            source: None,
            category: Category::Notice,
            verdict: Verdict::Allow,
            reason: String::new(),
            dev,
            detected: None,
            undeclared: vec![],
        }
    }

    #[test]
    fn same_texts_print_once_notices_print_per_package_and_missing_files_are_listed() {
        let root = tempfile::tempdir().unwrap();
        let mut dirs = BTreeMap::new();
        for (name, license, notice) in [
            ("a", "MIT text", None),
            ("b", "MIT text", None),
            ("c", "Apache text", Some("c includes d")),
        ] {
            let dir = root.path().join(name);
            std::fs::create_dir_all(dir.join("node_modules/x")).unwrap();
            std::fs::write(dir.join("node_modules/x/LICENSE"), "another package").unwrap();
            if name == "c" {
                std::fs::create_dir_all(dir.join("third_party/fiat")).unwrap();
                std::fs::write(dir.join("third_party/fiat/LICENSE"), "fiat text").unwrap();
            }
            std::fs::write(dir.join("LICENSE"), license).unwrap();
            if let Some(n) = notice {
                std::fs::write(dir.join("NOTICE"), n).unwrap();
            }
            dirs.insert(
                (Ecosystem::Cargo, name.to_string(), "1.0.0".to_string()),
                dir,
            );
        }
        let decisions = [
            decision("r", "a", "MIT", false),
            decision("r", "b", "MIT", false),
            decision("r", "c", "Apache-2.0", false),
            decision("r", "gone", "BSD-3-Clause", false),
            decision("r", "test-only", "MIT", true),
            decision("other", "a", "MIT", false),
        ];
        let a = attribution("r", &decisions, &dirs);
        assert_eq!(a.texts.len(), 2);
        assert_eq!(a.texts["LICENSE:\n\nMIT text"].len(), 2);
        assert!(a
            .texts
            .contains_key("LICENSE:\n\nApache text\n\nthird_party/fiat/LICENSE:\n\nfiat text"));
        assert_eq!(a.notices.len(), 1);
        assert_eq!(a.missing.len(), 1);
        let text = render("r", &a);
        assert!(text.contains("4 runtime package(s)"), "{text}");
        assert!(
            text.contains("  - a 1.0.0 (cargo)\n  - b 1.0.0 (cargo)"),
            "{text}"
        );
        assert!(
            text.contains("--- c 1.0.0 (cargo) NOTICE\n\nc includes d"),
            "{text}"
        );
        assert!(
            text.contains("gone 1.0.0 (cargo): declares BSD-3-Clause"),
            "{text}"
        );
        assert!(!text.contains("test-only"), "{text}");
    }

    #[test]
    fn file_names_are_safe() {
        assert_eq!(file_name("org/app"), "org_app.NOTICE.txt");
        assert_eq!(file_name("../x"), "_x.NOTICE.txt");
        assert_eq!(file_name(""), "repo.NOTICE.txt");
    }
}
