//! The package inventory of each repo, for `fleetreach sbom`: every package each dependency
//! source declares, read with the same repo planning and the same feeder readers as `scan`
//! (so an SBOM and a scan always see the same sources), but kept whole instead of filtered to
//! vulnerable packages. Reads lockfiles and manifests only; needs no advisory DB, no
//! toolchain and no network.

use std::path::Path;

use fleetreach_core::inventory::{Package, RepoInventory, SourceInventory};
use fleetreach_core::{Coverage, Ecosystem};

use crate::config::Repo;
use crate::orchestrate::{discover_lockfiles, plan_repo, ScanUnit};

/// Read every source in `repo`. A source that exists but cannot be read is recorded in
/// `errors`, never dropped: the caller treats the inventory as incomplete.
pub fn repo_inventory(repo: &Repo) -> RepoInventory {
    let plan = plan_repo(repo);
    let mut inv = RepoInventory::new(repo.id.clone());
    inv.errors.extend(
        plan.walk_errors
            .iter()
            .map(|e| format!("could not fully walk the repo: {e}")),
    );
    // A lockfile format no feeder reads is a coverage gap, as in `scan`: listed as a source
    // with no packages, so the BOM marks itself incomplete.
    for gap in &plan.unsupported {
        inv.sources.push(
            SourceInventory::new(gap.ecosystem, gap.source.clone(), Vec::new())
                .with_gap(gap.level, format!("{}: {}", gap.source, gap.reason)),
        );
    }
    for unit in &plan.units {
        match unit_inventory(unit) {
            Ok(sources) => {
                for mut source in sources {
                    if !unit.rel_dir.is_empty() {
                        source.source = format!("{}/{}", unit.rel_dir, source.source);
                    }
                    inv.sources.push(source);
                }
            }
            Err(reason) if unit.rel_dir.is_empty() => inv.errors.push(reason),
            Err(reason) => inv.errors.push(format!("{}: {reason}", unit.rel_dir)),
        }
    }
    inv
}

fn unit_inventory(unit: &ScanUnit) -> Result<Vec<SourceInventory>, String> {
    let dir = unit.repo.path.as_path();
    let one = |source: SourceInventory| Ok(vec![source]);
    match unit.ecosystem {
        Ecosystem::Cargo => {
            let (lockfiles, errors) = discover_lockfiles(&unit.repo);
            if let Some(error) = errors.first() {
                return Err(error.clone());
            }
            if lockfiles.is_empty() {
                return Err("no Cargo.lock found".to_string());
            }
            lockfiles
                .iter()
                .map(|path| {
                    let mut source =
                        fleetreach_scan::lockfile_inventory(path).map_err(|e| e.to_string())?;
                    source.source = path.strip_prefix(dir).unwrap_or(path).display().to_string();
                    Ok(source)
                })
                .collect()
        }
        Ecosystem::Go => one(go(dir)?),
        Ecosystem::Npm => {
            let (installed, graph) =
                fleetreach_npm::read_lockfile(dir).map_err(|e| e.to_string())?;
            let name = fleetreach_npm::LOCKFILES
                .iter()
                .filter(|f| dir.join(f).is_file())
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            let packages = installed
                .into_iter()
                .map(|p| Package::new(p.name, p.version, p.direct, p.dev))
                .collect();
            one(SourceInventory::new(Ecosystem::Npm, name, packages).with_graph(&graph))
        }
        Ecosystem::Pypi => one(fleetreach_pypi::inventory(dir).map_err(|e| e.to_string())?),
        Ecosystem::NuGet => one(fleetreach_nuget::inventory(dir).map_err(|e| e.to_string())?),
        Ecosystem::RubyGems => {
            let body = read(dir, "Gemfile.lock")?;
            let mut packages: Vec<Package> = fleetreach_rubygems::installed_gems(&body)
                .into_iter()
                .map(|g| Package::new(g.name, g.version, g.direct, false))
                .collect();
            packages.extend(git_gems(&body));
            let graph = fleetreach_rubygems::dependency_graph(&body);
            one(
                SourceInventory::new(Ecosystem::RubyGems, "Gemfile.lock", packages)
                    .with_graph(&graph),
            )
        }
        Ecosystem::Packagist => {
            let lock = read(dir, "composer.lock")?;
            let manifest = std::fs::read_to_string(dir.join("composer.json")).ok();
            let (installed, graph) =
                fleetreach_packagist::installed_packages(&lock, manifest.as_deref())
                    .map_err(|e| format!("composer.lock: {e}"))?;
            let packages = installed
                .into_iter()
                .map(|p| Package::new(p.name, p.version, p.direct, p.dev))
                .collect();
            one(
                SourceInventory::new(Ecosystem::Packagist, "composer.lock", packages)
                    .with_graph(&graph),
            )
        }
        Ecosystem::Julia => {
            let manifest = read(dir, "Manifest.toml")?;
            let project = std::fs::read_to_string(dir.join("Project.toml")).ok();
            let (installed, graph) =
                fleetreach_julia::installed_packages(&manifest, project.as_deref())
                    .map_err(|e| format!("Manifest.toml: {e}"))?;
            let packages = installed
                .into_iter()
                .map(|p| Package::new(p.name, p.version, p.direct, false))
                .collect();
            one(
                SourceInventory::new(Ecosystem::Julia, "Manifest.toml", packages)
                    .with_graph(&graph),
            )
        }
        Ecosystem::Swift => {
            let resolved = read(dir, "Package.resolved")?;
            let manifest = std::fs::read_to_string(dir.join("Package.swift")).ok();
            let packages = fleetreach_swift::installed_packages(&resolved, manifest.as_deref())
                .map_err(|e| format!("Package.resolved: {e}"))?
                .into_iter()
                .map(|p| Package::new(p.name, p.version, p.direct, false))
                .collect();
            one(SourceInventory::new(
                Ecosystem::Swift,
                "Package.resolved",
                packages,
            ))
        }
        Ecosystem::Hex => {
            let lock = read(dir, "mix.lock")?;
            let (installed, graph) = fleetreach_hex::installed_packages(&lock);
            let packages = installed
                .into_iter()
                .map(|p| Package::new(p.name, p.version, p.direct, false))
                .collect();
            one(SourceInventory::new(Ecosystem::Hex, "mix.lock", packages).with_graph(&graph))
        }
        Ecosystem::Maven => {
            if dir.join("gradle.lockfile").is_file() {
                let text = read(dir, "gradle.lockfile")?;
                let packages = maven_packages(fleetreach_maven::parse_gradle_lockfile(&text));
                one(SourceInventory::new(
                    Ecosystem::Maven,
                    "gradle.lockfile",
                    packages,
                ))
            } else {
                let text = read(dir, "pom.xml")?;
                let packages = maven_packages(fleetreach_maven::parse_pom_xml(&text));
                one(SourceInventory::new(Ecosystem::Maven, "pom.xml", packages).with_gap(
                    Coverage::DirectOnly,
                    "pom.xml: declares direct dependencies only; transitive dependencies were not \
                     resolved",
                ))
            }
        }
        Ecosystem::GitHubActions => one(github_actions(dir)?),
    }
}

/// Gems from `GIT` sections of a `Gemfile.lock`. The matcher skips them (no registry
/// advisory applies to a git checkout), but they are dependencies all the same, so the SBOM
/// lists them with their remote and revision. `PATH` gems are the project's own code.
fn git_gems(lock: &str) -> Vec<Package> {
    let declared: std::collections::BTreeSet<&str> = lock
        .split("\nDEPENDENCIES\n")
        .nth(1)
        .map(|deps| {
            deps.lines()
                .take_while(|l| l.starts_with("  "))
                .filter_map(|l| l.split_whitespace().next())
                .map(|n| n.trim_end_matches('!'))
                .collect()
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    for block in lock.split("\n\n") {
        let mut lines = block.lines();
        if lines.next().map(str::trim) != Some("GIT") {
            continue;
        }
        let (mut remote, mut revision) = (None, None);
        for line in block.lines() {
            let line_trim = line.trim();
            if let Some(v) = line_trim.strip_prefix("remote:") {
                remote = Some(v.trim().to_string());
            } else if let Some(v) = line_trim.strip_prefix("revision:") {
                revision = Some(v.trim().to_string());
            } else if line.starts_with("    ") && !line.starts_with("      ") {
                // `    name (version)` under `specs:`; deeper lines are its requirements.
                if let Some((name, rest)) = line_trim.split_once(' ') {
                    let version = rest.trim_matches(|c| c == '(' || c == ')');
                    if let Some(url) = &remote {
                        out.push(
                            Package::new(name, version, declared.contains(name), false)
                                .with_source(fleetreach_core::DepSource::Git {
                                    url: url.clone(),
                                    rev: revision.clone(),
                                }),
                        );
                    }
                }
            }
        }
    }
    out
}

fn read(dir: &Path, file: &str) -> Result<String, String> {
    std::fs::read_to_string(dir.join(file)).map_err(|e| format!("{file}: {e}"))
}

fn maven_packages(installed: Vec<fleetreach_maven::InstalledPackage>) -> Vec<Package> {
    installed
        .into_iter()
        .map(|p| Package::new(p.name, p.version, p.direct, false))
        .collect()
}

/// `go.mod` requirements, with `replace` directives applied. Since Go 1.17 the file lists
/// every module the build needs; before that only direct ones, so older files are partial.
fn go(dir: &Path) -> Result<SourceInventory, String> {
    let text = read(dir, "go.mod")?;
    let direct = fleetreach_go::direct_modules(&text);
    let replaces = fleetreach_go::replace_directives(&text);
    let mut packages = Vec::new();
    for module in fleetreach_go::required_modules(&text) {
        let replaced = replaces.iter().find(|r| {
            r.from_path == module.path
                && r.from_version
                    .as_deref()
                    .is_none_or(|v| v == module.version)
        });
        let (path, version) = match replaced {
            // A local-path replacement is first-party code, not a published module.
            Some(r) if r.to_version.is_none() => continue,
            Some(r) => (r.to_path.clone(), r.to_version.clone().unwrap_or_default()),
            None => (module.path.clone(), module.version.clone()),
        };
        packages.push(Package::new(
            path,
            version,
            direct.contains(&module.path),
            false,
        ));
    }
    let mut inv = SourceInventory::new(Ecosystem::Go, "go.mod", packages);
    if go_version_before_1_17(&text) {
        inv = inv.with_gap(
            Coverage::Partial,
            "go.mod: written for Go before 1.17, which lists direct requirements only",
        );
    }
    Ok(inv)
}

/// Whether the `go` directive names a version before 1.17 (no directive counts as old).
fn go_version_before_1_17(go_mod: &str) -> bool {
    let Some(version) = go_mod
        .lines()
        .find_map(|l| l.trim().strip_prefix("go ").map(str::trim))
    else {
        return true;
    };
    let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let (major, minor) = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    (major, minor) < (1, 17)
}

/// Version-pinned `uses:` references across `.github/workflows/*.yml`.
fn github_actions(dir: &Path) -> Result<SourceInventory, String> {
    let workflows = dir.join(".github").join("workflows");
    let mut files: Vec<_> = std::fs::read_dir(&workflows)
        .map_err(|e| format!(".github/workflows: {e}"))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| matches!(e, "yml" | "yaml"))
        })
        .collect();
    files.sort();
    let mut packages = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
        packages.extend(
            fleetreach_ghactions::used_actions(&text)
                .into_iter()
                .map(|a| Package::new(a.name, a.version_ref, true, false)),
        );
    }
    Ok(SourceInventory::new(
        Ecosystem::GitHubActions,
        ".github/workflows",
        packages,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_gems_carry_their_remote() {
        let lock = "GIT\n  remote: https://github.com/mastodon/webpush.git\n  revision: 9631ac6\n  \
                    specs:\n    webpush (1.1.0)\n      hkdf (~> 0.2)\n\nPATH\n  remote: .\n  specs:\n    \
                    mine (0.1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    hkdf (0.3.0)\n\n\
                    DEPENDENCIES\n  webpush!\n";
        let gems = git_gems(lock);
        assert_eq!(gems.len(), 1);
        assert_eq!(
            (gems[0].name.as_str(), gems[0].version.as_str()),
            ("webpush", "1.1.0")
        );
        assert!(gems[0].direct);
        assert_eq!(
            gems[0].source,
            fleetreach_core::DepSource::Git {
                url: "https://github.com/mastodon/webpush.git".into(),
                rev: Some("9631ac6".into())
            }
        );
    }

    #[test]
    fn go_directive_age() {
        assert!(go_version_before_1_17("module x\n\ngo 1.16\n"));
        assert!(!go_version_before_1_17("module x\n\ngo 1.17\n"));
        assert!(!go_version_before_1_17("module x\ngo 1.22.3\n"));
        assert!(go_version_before_1_17("module x\n"));
    }
}
