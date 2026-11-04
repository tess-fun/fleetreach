//! `scan --why` and `scan --versions`: how a package enters the fleet, and at which versions.
//! Both read lockfiles only: no advisory data, no network. The graphs outside Cargo are by
//! package name, so two versions of one package share a node there.

use std::collections::{BTreeMap, BTreeSet};

use fleetreach_core::depgraph::{all_paths, DepGraph};
use fleetreach_core::inventory::ROOT;
use fleetreach_core::Ecosystem;
use fleetreach_report::sanitize_cell;
use fleetreach_scan::{all_routes_to, routes_to};
use serde_json::json;

use crate::config::{Config, Repo};
use crate::evidence::coerce;
use crate::orchestrate::discover_lockfiles;

/// One package at one version in one repo, and the paths into it.
struct Route {
    repo: String,
    ecosystem: String,
    name: String,
    version: String,
    direct: bool,
    paths: Vec<Vec<String>>,
    /// The list stopped at the cap.
    short: bool,
}

fn ecosystem_name(ecosystem: Ecosystem) -> String {
    format!("{ecosystem:?}").to_lowercase()
}

/// `package` by its full name or its last segment (`log4j-core` for
/// `org.apache.logging.log4j:log4j-core`, `grpc` for `google.golang.org/grpc`),
/// case-insensitively.
fn wanted(name: &str, package: &str) -> bool {
    let last = name.rsplit([':', '/']).next().unwrap_or(name);
    name.eq_ignore_ascii_case(package) || last.eq_ignore_ascii_case(package)
}

/// `--why`: every route by which a package enters each repo's dependency tree, in every
/// ecosystem: the shortest, or with `cap` every path up to it. Exits `0` if found anywhere,
/// `2` if it is in no tree.
pub(crate) fn run_why(config: &Config, package: &str, cap: Option<usize>, json_out: bool) -> u8 {
    let mut routes = Vec::new();
    for repo in &config.repos {
        routes.extend(other_routes(repo, package, cap));
        for lockfile in discover_lockfiles(repo).0 {
            match cargo_routes(repo, &lockfile, package, cap) {
                Ok(found) => routes.extend(found),
                Err(e) => eprintln!("warning: {}: {e}", repo.id),
            }
        }
    }
    if json_out {
        print_json(&json!({
            "schema": "fleetreach-why/1",
            "package": package,
            "routes": routes.iter().map(|r| json!({
                "repo": r.repo,
                "ecosystem": r.ecosystem,
                "name": r.name,
                "version": r.version,
                "direct": r.direct,
                "paths": r.paths,
                "truncated": r.short,
            })).collect::<Vec<_>>(),
        }));
    } else {
        routes.iter().for_each(print_route);
    }
    if routes.is_empty() {
        eprintln!("`{package}` is not in any repo's dependency tree");
        return 2;
    }
    0
}

fn print_json(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_default()
    );
}

fn print_route(route: &Route) {
    // Package, version and path segments come from untrusted lockfiles and are echoed to the
    // terminal; neutralize control sequences.
    let kind = if route.direct { "direct" } else { "transitive" };
    let head = format!(
        "{} — {} {}",
        sanitize_cell(&route.repo),
        sanitize_cell(&route.name),
        sanitize_cell(&route.version)
    );
    if route.ecosystem == "cargo" {
        println!("{head} ({kind}):");
    } else {
        println!("{head} ({}, {kind}):", route.ecosystem);
    }
    for path in &route.paths {
        let path: Vec<String> = path.iter().map(|s| sanitize_cell(s)).collect();
        println!("  {}", path.join(" → "));
    }
    if route.short {
        println!("  (more paths; raise --max-paths to see them)");
    }
}

fn cargo_routes(
    repo: &Repo,
    lockfile: &std::path::Path,
    package: &str,
    cap: Option<usize>,
) -> Result<Vec<Route>, String> {
    let route = |version: String, direct, paths, short| Route {
        repo: repo.id.0.clone(),
        ecosystem: "cargo".to_string(),
        name: package.to_string(),
        version,
        direct,
        paths,
        short,
    };
    match cap {
        None => Ok(routes_to(lockfile, package)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|r| route(r.version, r.direct, vec![r.path], false))
            .collect()),
        Some(cap) => Ok(all_routes_to(lockfile, package, cap)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|r| {
                let direct = r.paths.iter().any(|p| p.len() <= 2);
                route(r.version, direct, r.paths, r.short)
            })
            .collect()),
    }
}

/// `--why` outside Cargo: the package in every other source the repo declares. A source
/// without a graph shows the repo and the package alone.
fn other_routes(repo: &Repo, package: &str, cap: Option<usize>) -> Vec<Route> {
    let inventory = crate::inventory::repo_inventory(repo);
    for error in &inventory.errors {
        eprintln!("warning: {}: {error}", repo.id);
    }
    let mut routes = Vec::new();
    for source in &inventory.sources {
        if source.ecosystem == Ecosystem::Cargo {
            continue;
        }
        let mut graph = DepGraph::new(ROOT);
        let mut edges: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for (from, to) in &source.edges {
            graph.add_edges(from, [to.as_str()]);
            edges.entry(from).or_default().insert(to);
        }
        let next = |node: &&str| -> Vec<&str> {
            edges
                .get(node)
                .map_or_else(Vec::new, |tos| tos.iter().copied().collect())
        };
        for pkg in source.packages.iter().filter(|p| wanted(&p.name, package)) {
            let (mut paths, short) = match cap {
                None => (vec![graph.chain_to(&pkg.name)], false),
                Some(cap) => {
                    let (found, short) = all_paths(&[ROOT], next, &pkg.name.as_str(), cap);
                    let owned = found
                        .iter()
                        .map(|p| p.iter().map(ToString::to_string).collect())
                        .collect();
                    (owned, short)
                }
            };
            paths.retain(|p: &Vec<String>| !p.is_empty());
            if paths.is_empty() {
                paths = vec![vec![ROOT.to_string(), pkg.name.clone()]];
            }
            for path in &mut paths {
                path[0] = repo.id.0.clone();
            }
            routes.push(Route {
                repo: repo.id.0.clone(),
                ecosystem: ecosystem_name(source.ecosystem),
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                direct: pkg.direct,
                paths,
                short,
            });
        }
    }
    routes
}

/// `--versions`: each version of a package across the fleet and the repos on it. Exits `0` if
/// found anywhere, `2` if no repo has it.
pub(crate) fn run_versions(config: &Config, package: &str, json_out: bool) -> u8 {
    // ecosystem, name -> version -> repos
    type Fleet = BTreeMap<(String, String), BTreeMap<String, BTreeSet<String>>>;
    let mut fleet = Fleet::new();
    for repo in &config.repos {
        let inventory = crate::inventory::repo_inventory(repo);
        for error in &inventory.errors {
            eprintln!("warning: {}: {error}", repo.id);
        }
        for source in &inventory.sources {
            for pkg in source.packages.iter().filter(|p| wanted(&p.name, package)) {
                let key = (ecosystem_name(source.ecosystem), pkg.name.clone());
                let versions = fleet.entry(key).or_default();
                let repos = versions.entry(pkg.version.clone()).or_default();
                repos.insert(repo.id.0.clone());
            }
        }
    }
    let sorted = |versions: &BTreeMap<String, BTreeSet<String>>| {
        let mut list: Vec<(String, Vec<String>)> = versions
            .iter()
            .map(|(v, repos)| (v.clone(), repos.iter().cloned().collect()))
            .collect();
        list.sort_by_cached_key(|(v, _)| (coerce(v), v.clone()));
        list
    };
    if json_out {
        print_json(&json!({
            "schema": "fleetreach-versions/1",
            "package": package,
            "packages": fleet.iter().map(|((ecosystem, name), versions)| json!({
                "ecosystem": ecosystem,
                "name": name,
                "versions": sorted(versions).iter().map(|(version, repos)| json!({
                    "version": version,
                    "repos": repos,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }));
    } else {
        for ((ecosystem, name), versions) in &fleet {
            println!("{} ({ecosystem}):", sanitize_cell(name));
            for (version, repos) in sorted(versions) {
                let repos: Vec<String> = repos.iter().map(|r| sanitize_cell(r)).collect();
                println!(
                    "  {}  {} repo(s): {}",
                    sanitize_cell(&version),
                    repos.len(),
                    repos.join(", ")
                );
            }
        }
    }
    if fleet.is_empty() {
        eprintln!("`{package}` is in no repo");
        return 2;
    }
    0
}
