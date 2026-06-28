//! Parse a `composer.lock` into a flat, deduplicated set of installed Composer packages —
//! the input the OSV matcher scans. Read straight from the lockfile, so it needs **no PHP
//! toolchain and no network**: Composer already pins every package to one exact version
//! across the full transitive tree.
//!
//! Unlike `Gemfile.lock`, `composer.lock` is JSON, so this uses serde. Its shape (only the
//! fields the matcher reads):
//!
//! ```json
//! {
//!   "packages":     [ { "name": "monolog/monolog", "version": "2.1.0" } ],
//!   "packages-dev": [ { "name": "phpunit/phpunit", "version": "9.5.0" } ]
//! }
//! ```
//!
//! `composer.lock` does not record which packages are **direct** dependencies, so the
//! direct set is read from the sibling `composer.json`'s `require` / `require-dev` keys
//! (when present). Package names are Composer's canonical lowercase `vendor/name`; platform
//! requirements (`php`, `ext-*`, `lib-*`, `composer-*`) have no `/` and are not real
//! packages, so they are filtered. Names are matched **case-insensitively** (Composer treats
//! package names case-insensitively); everything is lowercased here and in the DB index.

use std::collections::{BTreeMap, BTreeSet};

use fleetreach_core::DepGraph;
use serde::Deserialize;

/// One resolved package from `composer.lock`: its canonical lowercase name, exact installed
/// version, and whether the project depends on it **directly** (it appears in
/// `composer.json`'s `require`/`require-dev`) rather than only transitively.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub direct: bool,
}

#[derive(Deserialize)]
struct ComposerLock {
    #[serde(default)]
    packages: Vec<LockPackage>,
    #[serde(default, rename = "packages-dev")]
    packages_dev: Vec<LockPackage>,
}

#[derive(Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    /// This package's own runtime requirements (`require` in composer.lock): name →
    /// constraint. Only the real-package keys (those containing `/`) are read, for the
    /// `dependency_path` graph; platform requirements (`php`, `ext-*`) are skipped.
    #[serde(default)]
    require: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct ComposerJson {
    /// The project's own `vendor/name` (the root of every chain), when present.
    name: Option<String>,
    #[serde(default)]
    require: BTreeMap<String, serde_json::Value>,
    #[serde(default, rename = "require-dev")]
    require_dev: BTreeMap<String, serde_json::Value>,
}

/// Parse `composer.lock` JSON into a deduplicated, sorted set of installed packages. The
/// optional `composer_json` text marks the `direct` flag; without it every package is
/// reported transitive (a conservative under-claim that never hides a finding). Both the
/// production (`packages`) and dev (`packages-dev`) sets are included — a dev dependency can
/// still ship a vulnerable version into CI or tooling.
///
/// # Errors
///
/// Returns the underlying [`serde_json::Error`] if `composer.lock` is not valid JSON. A
/// malformed `composer.json` is tolerated (the direct set is then empty) — it is only
/// metadata for the `direct` flag, never a reason to fail the scan.
pub fn installed_packages(
    lock_text: &str,
    composer_json: Option<&str>,
) -> Result<(Vec<InstalledPackage>, DepGraph), serde_json::Error> {
    let lock: ComposerLock = serde_json::from_str(lock_text)?;
    let (root, direct) =
        composer_json.map_or_else(|| ("(root)".to_string(), BTreeSet::new()), manifest_info);

    let packages = lock
        .packages
        .iter()
        .chain(&lock.packages_dev)
        .map(|p| {
            let name = p.name.to_ascii_lowercase();
            InstalledPackage {
                direct: direct.contains(&name),
                name,
                version: p.version.clone(),
            }
        })
        .collect();
    let graph = composer_graph(&lock, &direct, &root);
    Ok((dedupe(packages), graph))
}

/// Build the `dependency_path` graph from `composer.lock` + the project's direct set. The
/// root's edges are the direct deps; each package's `require` (real-package keys) are its
/// edges. Names are Composer's canonical lowercase `vendor/name`, matching the occurrence
/// package field, so the chain connects cleanly.
fn composer_graph(lock: &ComposerLock, direct: &BTreeSet<String>, root: &str) -> DepGraph {
    let mut graph = DepGraph::new(root);
    graph.add_edges(root, direct.iter().cloned());
    for p in lock.packages.iter().chain(&lock.packages_dev) {
        let name = p.name.to_ascii_lowercase();
        graph.add_edges(
            &name,
            p.require
                .keys()
                .filter(|k| k.contains('/'))
                .map(|k| k.to_ascii_lowercase()),
        );
    }
    graph
}

/// The project root name + direct-dependency names from a `composer.json`: the root is its
/// `name` (`vendor/app`, lowercased) or `(root)`; the direct set is the lowercased keys of
/// `require`/`require-dev` that name a real package (contain a `/`), so platform requirements
/// (`php`, `ext-mbstring`, `composer-runtime-api`, ...) are excluded. A malformed
/// `composer.json` yields `(root)` + an empty set rather than an error.
fn manifest_info(composer_json: &str) -> (String, BTreeSet<String>) {
    let Ok(cj) = serde_json::from_str::<ComposerJson>(composer_json) else {
        return ("(root)".to_string(), BTreeSet::new());
    };
    let root = cj
        .name
        .map_or_else(|| "(root)".to_string(), |n| n.to_ascii_lowercase());
    let direct = cj
        .require
        .into_keys()
        .chain(cj.require_dev.into_keys())
        .filter(|k| k.contains('/'))
        .map(|k| k.to_ascii_lowercase())
        .collect();
    (root, direct)
}

/// Collapse duplicate `(name, version)` rows into one, with `direct` winning if any
/// occurrence was direct, and sort for deterministic output.
fn dedupe(packages: Vec<InstalledPackage>) -> Vec<InstalledPackage> {
    let mut by_key: BTreeMap<(String, String), bool> = BTreeMap::new();
    for p in packages {
        let e = by_key.entry((p.name, p.version)).or_insert(false);
        *e = *e || p.direct;
    }
    by_key
        .into_iter()
        .map(|((name, version), direct)| InstalledPackage {
            name,
            version,
            direct,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn rows(pkgs: &[InstalledPackage]) -> Vec<(&str, &str, bool)> {
        pkgs.iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.direct))
            .collect()
    }

    const LOCK: &str = r#"{
      "packages": [
        { "name": "monolog/monolog", "version": "2.1.0" },
        { "name": "psr/log", "version": "1.1.3" }
      ],
      "packages-dev": [
        { "name": "phpunit/phpunit", "version": "9.5.0" }
      ]
    }"#;

    const COMPOSER_JSON: &str = r#"{
      "require": { "php": ">=7.4", "ext-json": "*", "monolog/monolog": "^2.0" },
      "require-dev": { "phpunit/phpunit": "^9.5" }
    }"#;

    #[test]
    fn dependency_path_chains_via_require() {
        // app -> monolog/monolog -> psr/log (transitive); app -> monolog/monolog (direct).
        let lock = r#"{
          "packages": [
            { "name": "monolog/monolog", "version": "2.1.0", "require": { "php": ">=7.4", "psr/log": "^1.1" } },
            { "name": "psr/log", "version": "1.1.3" }
          ]
        }"#;
        let cj = r#"{ "name": "acme/app", "require": { "monolog/monolog": "^2.0" } }"#;
        let (_pkgs, graph) = installed_packages(lock, Some(cj)).unwrap();
        assert_eq!(
            graph.chain_to("psr/log"),
            vec!["acme/app", "monolog/monolog", "psr/log"]
        );
        assert_eq!(
            graph.chain_to("monolog/monolog"),
            vec!["acme/app", "monolog/monolog"]
        );
    }

    #[test]
    fn parses_lock_with_direct_set() {
        let (pkgs, _) = installed_packages(LOCK, Some(COMPOSER_JSON)).unwrap();
        assert_eq!(
            rows(&pkgs),
            vec![
                ("monolog/monolog", "2.1.0", true), // direct (require)
                ("phpunit/phpunit", "9.5.0", true), // direct (require-dev)
                ("psr/log", "1.1.3", false),        // transitive
            ]
        );
    }

    #[test]
    fn without_composer_json_all_transitive() {
        let (pkgs, _) = installed_packages(LOCK, None).unwrap();
        assert!(pkgs.iter().all(|p| !p.direct));
        assert_eq!(pkgs.len(), 3);
    }

    #[test]
    fn names_are_lowercased() {
        let lock = r#"{ "packages": [ { "name": "Monolog/Monolog", "version": "2.1.0" } ] }"#;
        let cj = r#"{ "require": { "MONOLOG/monolog": "^2.0" } }"#;
        let (pkgs, _) = installed_packages(lock, Some(cj)).unwrap();
        assert_eq!(rows(&pkgs), vec![("monolog/monolog", "2.1.0", true)]);
    }

    #[test]
    fn platform_requirements_are_not_direct_packages() {
        let (_root, set) =
            manifest_info(r#"{ "require": { "php": ">=8", "ext-gd": "*", "a/b": "^1" } }"#);
        assert_eq!(set.into_iter().collect::<Vec<_>>(), vec!["a/b".to_string()]);
    }

    #[test]
    fn empty_and_malformed_inputs() {
        assert!(installed_packages(r#"{}"#, None).unwrap().0.is_empty());
        // A malformed composer.json is tolerated (empty direct set), not an error.
        assert!(manifest_info("not json").1.is_empty());
        // A malformed composer.lock IS an error (fail closed).
        assert!(installed_packages("not json", None).is_err());
    }

    #[test]
    fn dedupes_same_name_version_direct_wins() {
        let pkgs = dedupe(vec![
            InstalledPackage {
                name: "a/b".into(),
                version: "1.0".into(),
                direct: false,
            },
            InstalledPackage {
                name: "a/b".into(),
                version: "1.0".into(),
                direct: true,
            },
        ]);
        assert_eq!(rows(&pkgs), vec![("a/b", "1.0", true)]);
    }
}
