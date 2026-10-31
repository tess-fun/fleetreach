//! Supply-chain signals beyond known advisories (spec 10, phase 1): lockfile hygiene read
//! from files fleetreach already parses, with no package download and no network.
//!
//! | Signal id | Meaning | Read from |
//! |-----------|---------|-----------|
//! | `fleetreach:install-script` | the package runs a script when installed | `package-lock.json` `hasInstallScript` |
//! | `fleetreach:non-registry-source` | fetched from git, a URL or a path, not a registry | `package-lock.json` `resolved`, `Cargo.lock` `source`, `uv.lock` `source` |
//! | `fleetreach:unexpected-registry` | fetched from a registry that is not the public one or an allowed one (dependency confusion, lockfile injection) | the same fields |
//! | `fleetreach:missing-integrity` | a registry package with no checksum to verify the download | `package-lock.json` `integrity`, `Cargo.lock` `checksum` |
//! | `fleetreach:mutable-action-ref` | a third-party GitHub Action pinned to a tag or branch, which its owner can move (the tj-actions/changed-files attack), instead of a commit SHA | `.github/workflows/*.yml` |
//!
//! Signals are warnings of kind `notice` with these ids, one finding per signal with an
//! occurrence per package, so they gate with `--fail-on-warnings` and never inflate the
//! vulnerability count. They are additive: no signal never means safe.
//! `[settings.signals] registries` adds hosts to the allowed set.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fleetreach_core::semver::Version;
use fleetreach_core::{DependencyKind, Ecosystem, Occurrence, RepoId, WarnFinding, WarnKind};

use crate::config::Repo;
use crate::orchestrate::plan_repo;

/// Registry hosts allowed without configuration.
const PUBLIC_REGISTRIES: &[&str] = &[
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "github.com/rust-lang/crates.io-index",
    "index.crates.io",
    "pypi.org",
    "files.pythonhosted.org",
];

/// GitHub Action owners whose tags are maintained by GitHub itself.
const FIRST_PARTY_ACTION_OWNERS: &[&str] = &["actions", "github"];

/// Signal id and one-line title.
const SIGNALS: &[(&str, &str)] = &[
    (
        "fleetreach:install-script",
        "Runs an install script (code that executes when the package is installed)",
    ),
    (
        "fleetreach:non-registry-source",
        "Fetched from git, a URL or a path instead of a registry",
    ),
    (
        "fleetreach:unexpected-registry",
        "Fetched from a registry outside the allowed set (possible dependency confusion)",
    ),
    (
        "fleetreach:missing-integrity",
        "Registry package with no checksum in the lockfile",
    ),
    (
        "fleetreach:mutable-action-ref",
        "Third-party GitHub Action pinned to a movable tag or branch instead of a commit SHA",
    ),
];

/// One package that tripped one signal.
struct Hit {
    signal: &'static str,
    package: String,
    version: String,
    direct: bool,
}

/// The signal findings for every repo, one finding per signal id.
pub fn fleet_signals(repos: &[Repo], extra_registries: &[String]) -> Vec<WarnFinding> {
    let allowed: Vec<String> = PUBLIC_REGISTRIES
        .iter()
        .map(|s| (*s).to_string())
        .chain(extra_registries.iter().cloned())
        .collect();
    let mut by_signal: BTreeMap<&'static str, Vec<Occurrence>> = BTreeMap::new();
    for repo in repos {
        let mut hits = Vec::new();
        let mut seen_dirs = BTreeSet::new();
        for unit in plan_repo(repo).units {
            let dir = unit.repo.path.clone();
            if !seen_dirs.insert((dir.clone(), unit.ecosystem)) {
                continue;
            }
            match unit.ecosystem {
                Ecosystem::Npm => npm(&dir, &allowed, &mut hits),
                Ecosystem::Cargo => {
                    for lock in crate::orchestrate::discover_lockfiles(&unit.repo).0 {
                        cargo(&lock, &allowed, &mut hits);
                    }
                }
                Ecosystem::Pypi => uv(&dir, &allowed, &mut hits),
                Ecosystem::GitHubActions => actions(&dir, &mut hits),
                _ => {}
            }
            // Workflows sit at the repo root, which is not always its own unit.
        }
        if repo.path.join(".github").join("workflows").is_dir()
            && !seen_dirs
                .iter()
                .any(|(_, e)| *e == Ecosystem::GitHubActions)
        {
            actions(&repo.path, &mut hits);
        }
        for hit in hits {
            by_signal
                .entry(hit.signal)
                .or_default()
                .push(Occurrence::InRepo {
                    repo: RepoId(repo.id.0.clone()),
                    package: hit.package,
                    installed: lenient_version(&hit.version),
                    patched: Vec::new(),
                    dependency_kind: if hit.direct {
                        DependencyKind::Direct
                    } else {
                        DependencyKind::Transitive
                    },
                    dependency_path: Vec::new(),
                    active: None,
                    source: Default::default(),
                    scope: Default::default(),
                });
        }
    }
    SIGNALS
        .iter()
        .filter_map(|(id, title)| {
            let mut occurrences = by_signal.remove(id)?;
            occurrences.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
            occurrences.dedup();
            Some(WarnFinding {
                kind: WarnKind::Notice,
                advisory_id: Some((*id).to_string()),
                title: (*title).to_string(),
                occurrences,
            })
        })
        .collect()
}

/// A version for the shared model; tags like `v4` or refs like `main` become `0.0.0`.
fn lenient_version(raw: &str) -> Version {
    let trimmed = raw.trim_start_matches('v');
    Version::parse(trimmed)
        .or_else(|_| Version::parse(&format!("{trimmed}.0")))
        .or_else(|_| Version::parse(&format!("{trimmed}.0.0")))
        .unwrap_or_else(|_| Version::new(0, 0, 0))
}

/// Whether `url` points at an allowed registry.
fn allowed_registry(url: &str, allowed: &[String]) -> bool {
    let rest = url
        .split_once("://")
        .map_or(url, |(_, r)| r)
        .trim_start_matches("git+");
    // The whole host (and path prefix) must match: `registry.npmjs.org.evil.example` is
    // exactly the lookalike this signal exists to catch.
    allowed.iter().any(|a| {
        rest.strip_prefix(a.as_str())
            .is_some_and(|after| after.is_empty() || after.starts_with('/'))
    })
}

fn npm(dir: &Path, allowed: &[String], hits: &mut Vec<Hit>) {
    let Ok(text) = std::fs::read_to_string(dir.join("package-lock.json")) else {
        return;
    };
    let Ok(lock) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    let direct: BTreeSet<String> = ["dependencies", "devDependencies", "optionalDependencies"]
        .iter()
        .filter_map(|k| {
            lock.pointer(&format!("/packages//{k}"))
                .and_then(|v| v.as_object())
        })
        .flat_map(|m| m.keys().cloned())
        .collect();
    for (key, entry) in lock
        .get("packages")
        .and_then(|p| p.as_object())
        .into_iter()
        .flatten()
    {
        if key.is_empty() || entry.get("link").and_then(|l| l.as_bool()) == Some(true) {
            continue; // the root project, or a workspace link
        }
        let name = key
            .rsplit("node_modules/")
            .next()
            .unwrap_or(key)
            .to_string();
        let version = entry
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let top = key.matches("node_modules/").count() == 1;
        let hit = |signal| Hit {
            signal,
            package: name.clone(),
            version: version.clone(),
            direct: top && direct.contains(&name),
        };
        if entry.get("hasInstallScript").and_then(|v| v.as_bool()) == Some(true) {
            hits.push(hit("fleetreach:install-script"));
        }
        match entry.get("resolved").and_then(|v| v.as_str()) {
            Some(r)
                if r.starts_with("git")
                    || r.starts_with("file:")
                    || r.contains("github.com/") && !r.contains("registry") =>
            {
                hits.push(hit("fleetreach:non-registry-source"));
            }
            Some(r) if r.starts_with("http") => {
                if !allowed_registry(r, allowed) {
                    hits.push(hit("fleetreach:unexpected-registry"));
                }
                if entry.get("integrity").is_none() {
                    hits.push(hit("fleetreach:missing-integrity"));
                }
            }
            _ => {}
        }
    }
}

fn cargo(lock_path: &Path, allowed: &[String], hits: &mut Vec<Hit>) {
    let Ok(text) = std::fs::read_to_string(lock_path) else {
        return;
    };
    let Ok(lock) = toml::from_str::<toml::Value>(&text) else {
        return;
    };
    for p in lock
        .get("package")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let (Some(name), Some(version)) = (
            p.get("name").and_then(|v| v.as_str()),
            p.get("version").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let Some(source) = p.get("source").and_then(|v| v.as_str()) else {
            continue; // a path or workspace crate: the project itself
        };
        let hit = |signal| Hit {
            signal,
            package: name.to_string(),
            version: version.to_string(),
            direct: false,
        };
        if source.starts_with("git+") {
            hits.push(hit("fleetreach:non-registry-source"));
            continue;
        }
        let registry = source.split_once('+').map_or(source, |(_, url)| url);
        if !allowed_registry(registry, allowed) {
            hits.push(hit("fleetreach:unexpected-registry"));
        }
        if p.get("checksum").is_none() {
            hits.push(hit("fleetreach:missing-integrity"));
        }
    }
}

fn uv(dir: &Path, allowed: &[String], hits: &mut Vec<Hit>) {
    let Ok(text) = std::fs::read_to_string(dir.join("uv.lock")) else {
        return;
    };
    let Ok(lock) = toml::from_str::<toml::Value>(&text) else {
        return;
    };
    for p in lock
        .get("package")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let (Some(name), Some(source)) = (
            p.get("name").and_then(|v| v.as_str()),
            p.get("source").and_then(|v| v.as_table()),
        ) else {
            continue;
        };
        let version = p
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let hit = |signal| Hit {
            signal,
            package: name.to_string(),
            version: version.clone(),
            direct: false,
        };
        if source.contains_key("git") || source.contains_key("url") {
            hits.push(hit("fleetreach:non-registry-source"));
        } else if let Some(registry) = source.get("registry").and_then(|v| v.as_str()) {
            if !allowed_registry(registry, allowed) {
                hits.push(hit("fleetreach:unexpected-registry"));
            }
        }
    }
}

fn actions(repo_root: &Path, hits: &mut Vec<Hit>) {
    let dir = repo_root.join(".github").join("workflows");
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if !path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e, "yml" | "yaml"))
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for used in fleetreach_ghactions::used_actions(&text) {
            let owner = used.name.split('/').next().unwrap_or_default();
            let pinned = used.version_ref.len() == 40
                && used.version_ref.bytes().all(|b| b.is_ascii_hexdigit());
            if !pinned && !FIRST_PARTY_ACTION_OWNERS.contains(&owner) {
                hits.push(Hit {
                    signal: "fleetreach:mutable-action-ref",
                    package: used.name,
                    version: used.version_ref,
                    direct: true,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn registry_hosts_are_matched_by_prefix() {
        let allowed: Vec<String> = PUBLIC_REGISTRIES.iter().map(|s| (*s).to_string()).collect();
        assert!(allowed_registry(
            "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
            &allowed
        ));
        assert!(allowed_registry(
            "https://github.com/rust-lang/crates.io-index",
            &allowed
        ));
        assert!(allowed_registry("https://pypi.org/simple", &allowed));
        assert!(!allowed_registry(
            "https://npm.evil.example/a/-/a-1.0.0.tgz",
            &allowed
        ));
        assert!(!allowed_registry(
            "https://registry.npmjs.org.evil.example/a",
            &allowed
        ));
        assert!(!allowed_registry(
            "https://pypi.org.attacker.io/simple",
            &allowed
        ));
    }

    #[test]
    fn versions_degrade_to_zero_for_refs() {
        assert_eq!(lenient_version("v4").to_string(), "4.0.0");
        assert_eq!(lenient_version("1.2").to_string(), "1.2.0");
        assert_eq!(lenient_version("main").to_string(), "0.0.0");
    }
}
