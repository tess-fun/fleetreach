//! `--reachability=static`: the sound call-graph engine (NOT the grep heuristic
//! in [`crate::reach`]).
//!
//! For each repo that has findings naming specific functions, this builds the
//! repo once under the reach-driver and resolves every such finding's affected
//! functions against the whole-closure call graph. A finding is annotated with a
//! [`Reachability`] verdict (and the legacy `reachable` bool, so `--reachable-
//! only` drops a sound `NotReachable`).
//!
//! Soundness discipline (spec §1): only a definite, uncontested `NotReachable`
//! across *all* of a finding's occurrences yields `NotReachable`. A build
//! failure, an unresolved sink, an opaque boundary, or a function we cannot
//! attribute to a verdict all resolve to `Unknown` — never `NotReachable`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fleetreach_core::{FleetReport, Occurrence, ReachVerdict, Reachability, VulnFinding};
use fleetreach_reach::{
    analyze_project_cached, BuildConfig, FeatureSelection, SandboxPolicy, Verdict,
};
use sha2::{Digest, Sha256};

use crate::config::Config;

/// The pinned nightly the reach-driver was built against. The verdict is scoped
/// to it (recorded in `Reachability::config`).
pub const TOOLCHAIN: &str = "nightly-2026-06-27";

/// Inputs for the static engine.
pub struct Options<'a> {
    /// Path to the built `fleetreach-reach-driver` binary.
    pub driver: &'a Path,
    /// Which cargo features to build each repo with (part of the cache key).
    pub features: FeatureSelection,
    /// How to confine the untrusted build (defense-in-depth).
    pub sandbox: SandboxPolicy,
    /// Per-repo progress to stderr.
    pub verbose: bool,
}

/// A successful per-repo analysis: verdicts plus the cache key of the analyzed
/// closure (the witness anchor, §9.2).
struct RepoData {
    verdicts: BTreeMap<String, Verdict>,
    cache_key: Option<String>,
}

/// Per-repo analysis outcome: the analysis, or a build/setup failure.
type RepoOutcome = Result<RepoData, String>;

/// Annotate findings with static reachability. One cargo build per affected repo.
pub fn assess(report: &mut FleetReport, config: &Config, opts: &Options) {
    let engine = format!("static-mir-rta@{}", env!("CARGO_PKG_VERSION"));

    // Sinks per repo: the union of affected functions of findings occurring there.
    let mut sinks_by_repo: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for v in &report.vulnerabilities {
        if v.affected_functions.is_empty() {
            continue; // whole-crate advisory: no function-level sink to resolve
        }
        for repo in repos_of(v) {
            sinks_by_repo
                .entry(repo)
                .or_default()
                .extend(v.affected_functions.iter().cloned());
        }
    }
    if sinks_by_repo.is_empty() {
        return;
    }

    // Build + analyze each repo once.
    let mut by_repo: BTreeMap<String, RepoOutcome> = BTreeMap::new();
    for (repo_id, sinks) in &sinks_by_repo {
        let outcome = match config.repos.iter().find(|r| r.id.0 == **repo_id) {
            None => Err("repo is not in the fleet config".to_string()),
            Some(repo) => {
                if opts.verbose {
                    eprintln!("reachability(static): analyzing {repo_id} …");
                }
                let sink_vec: Vec<String> = sinks.iter().cloned().collect();
                let build = BuildConfig {
                    toolchain: TOOLCHAIN,
                    features: opts.features.clone(),
                    sandbox: opts.sandbox,
                };
                analyze_project_cached(&repo.path, opts.driver, &build, &sink_vec)
                    .map(|c| {
                        if opts.verbose {
                            eprintln!(
                                "reachability(static): {repo_id} graph {}",
                                if c.from_cache {
                                    "(cache hit)"
                                } else {
                                    "(rebuilt)"
                                }
                            );
                        }
                        RepoData {
                            verdicts: c.verdicts,
                            cache_key: c.cache_key,
                        }
                    })
                    .map_err(|e| e.to_string())
            }
        };
        if opts.verbose {
            if let Err(e) = &outcome {
                eprintln!("reachability(static): {repo_id} could not be analyzed: {e}");
            }
        }
        by_repo.insert((*repo_id).to_string(), outcome);
    }

    // The target the closure was built for — the host default (no `--target`).
    let host = host_triple();

    // Annotate each finding from the verdicts of the repos it occurs in.
    for v in &mut report.vulnerabilities {
        if v.affected_functions.is_empty() {
            continue;
        }
        let verdict = combine(v, &by_repo);
        // A `NotReachable` carries a witness binding it to its inputs (§9.2) and
        // names the analyzed target (§7 edge 3); other verdicts carry neither.
        let (targets, witness) = match &verdict {
            ReachVerdict::NotReachable => {
                let cache_keys: BTreeSet<String> = repos_of(v)
                    .filter_map(|repo| by_repo.get(repo))
                    .filter_map(|outcome| outcome.as_ref().ok())
                    .filter_map(|data| data.cache_key.clone())
                    .collect();
                (
                    vec![host.clone()],
                    Some(witness_hash(&engine, &v.affected_functions, &cache_keys)),
                )
            }
            _ => (Vec::new(), None),
        };
        let reachability = Reachability {
            verdict,
            config: TOOLCHAIN.to_string(),
            engine: engine.clone(),
            targets,
            witness,
        };
        v.reachable = reachability.as_legacy_bool();
        v.reachability = Some(reachability);
    }
}

/// The host target triple the closure was built for, from `rustc -vV`; falls back
/// to the architecture name when `rustc` cannot be queried.
fn host_triple() -> String {
    std::process::Command::new("rustc")
        .arg("-vV")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("host: ").map(str::to_string))
        })
        .unwrap_or_else(|| std::env::consts::ARCH.to_string())
}

/// A content-addressed witness for a `NotReachable` verdict (§9.2): SHA-256 over
/// the toolchain, engine, sinks, and the repos' cache keys (which bind lockfile,
/// features, and source). Any input change moves the hash, so `vex verify` re-derives.
fn witness_hash(engine: &str, sinks: &[String], cache_keys: &BTreeSet<String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(TOOLCHAIN.as_bytes());
    hasher.update([0]);
    hasher.update(engine.as_bytes());
    let mut sorted: Vec<&str> = sinks.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.dedup();
    for sink in sorted {
        hasher.update([0]);
        hasher.update(sink.as_bytes());
    }
    // `cache_keys` is a BTreeSet, so iteration is already sorted + deduped.
    for key in cache_keys {
        hasher.update([0]);
        hasher.update(key.as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The repo ids a finding occurs in.
fn repos_of(v: &VulnFinding) -> impl Iterator<Item = &str> {
    v.occurrences.iter().filter_map(|o| match o {
        Occurrence::InRepo { repo, .. } => Some(repo.0.as_str()),
        Occurrence::Toolchain { .. } => None,
    })
}

/// Combine the per-(repo, function, monomorphization) verdicts for one finding.
/// `Reachable` wins (with the first witness); `NotReachable` only if every
/// occurrence is a definite, uncontested `NotReachable`; otherwise `Unknown`.
fn combine(v: &VulnFinding, by_repo: &BTreeMap<String, RepoOutcome>) -> ReachVerdict {
    let mut witness: Option<Vec<String>> = None;
    let mut saw_unknown = false;
    let mut saw_not_reachable = false;

    for repo in repos_of(v) {
        match by_repo.get(repo) {
            // Repo not analyzed, or its build failed → cannot rule anything out.
            None | Some(Err(_)) => saw_unknown = true,
            Some(Ok(data)) => {
                for func in &v.affected_functions {
                    // Verdicts are keyed by the exact requested path.
                    match data.verdicts.get(func) {
                        Some(Verdict::Reachable { witness: w }) => {
                            witness.get_or_insert_with(|| w.clone());
                        }
                        Some(Verdict::NotReachable) => saw_not_reachable = true,
                        Some(Verdict::Unknown { .. }) => saw_unknown = true,
                        // The function did not resolve to a node in this build
                        // (e.g. a version where it does not exist) → fail closed.
                        None => saw_unknown = true,
                    }
                }
            }
        }
    }

    if let Some(w) = witness {
        ReachVerdict::Reachable { witness: w }
    } else if saw_unknown {
        ReachVerdict::Unknown {
            reason: "could not prove unreachable for every occurrence (build failure, \
                     opaque boundary, or unresolved sink)"
                .to_string(),
        }
    } else if saw_not_reachable {
        ReachVerdict::NotReachable
    } else {
        ReachVerdict::Unknown {
            reason: "no affected function resolved to a call-graph node".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleetreach_core::{Exploitability, RepoId, Severity};

    fn finding(funcs: &[&str], repos: &[&str]) -> VulnFinding {
        VulnFinding {
            advisory_id: "RUSTSEC-2099-0001".into(),
            aliases: vec![],
            ecosystem: Default::default(),
            title: "t".into(),
            severity: Severity::High,
            cvss_score: None,
            url: None,
            occurrences: repos
                .iter()
                .map(|r| Occurrence::InRepo {
                    repo: RepoId((*r).into()),
                    package: "p".into(),
                    installed: fleetreach_core::semver::Version::new(1, 0, 0),
                    patched: vec![],
                    dependency_kind: fleetreach_core::DependencyKind::Direct,
                    dependency_path: vec![],
                    active: None,
                    source: Default::default(),
                })
                .collect(),
            affected_functions: funcs.iter().map(|s| (*s).into()).collect(),
            reachable: None,
            reachability: None,
            exploit: Exploitability::default(),
        }
    }

    /// A successful repo outcome: a verdict per sink path.
    fn ok(pairs: Vec<(&str, Verdict)>) -> RepoOutcome {
        Ok(RepoData {
            verdicts: pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            cache_key: Some("reach-test".to_string()),
        })
    }

    fn repos(pairs: Vec<(&str, RepoOutcome)>) -> BTreeMap<String, RepoOutcome> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn reachable_wins_with_witness() {
        let f = finding(&["k::v"], &["a"]);
        let by_repo = repos(vec![(
            "a",
            ok(vec![(
                "k::v",
                Verdict::Reachable {
                    witness: vec!["main".into(), "k::v".into()],
                },
            )]),
        )]);
        assert_eq!(
            combine(&f, &by_repo),
            ReachVerdict::Reachable {
                witness: vec!["main".into(), "k::v".into()]
            }
        );
    }

    #[test]
    fn all_definite_not_reachable_is_not_reachable() {
        let f = finding(&["k::v"], &["a", "b"]);
        let by_repo = repos(vec![
            ("a", ok(vec![("k::v", Verdict::NotReachable)])),
            ("b", ok(vec![("k::v", Verdict::NotReachable)])),
        ]);
        assert_eq!(combine(&f, &by_repo), ReachVerdict::NotReachable);
    }

    #[test]
    fn one_unknown_repo_makes_it_unknown_not_notreachable() {
        // NotReachable in one repo, but the other's build failed → Unknown.
        let f = finding(&["k::v"], &["a", "b"]);
        let by_repo = repos(vec![
            ("a", ok(vec![("k::v", Verdict::NotReachable)])),
            ("b", Err("build failed".into())),
        ]);
        assert!(matches!(
            combine(&f, &by_repo),
            ReachVerdict::Unknown { .. }
        ));
    }

    #[test]
    fn reachable_in_any_repo_beats_notreachable_elsewhere() {
        let f = finding(&["k::v"], &["a", "b"]);
        let by_repo = repos(vec![
            ("a", ok(vec![("k::v", Verdict::NotReachable)])),
            (
                "b",
                ok(vec![(
                    "k::v",
                    Verdict::Reachable {
                        witness: vec!["x".into()],
                    },
                )]),
            ),
        ]);
        assert!(matches!(
            combine(&f, &by_repo),
            ReachVerdict::Reachable { .. }
        ));
    }

    #[test]
    fn witness_hash_is_deterministic_and_order_independent() {
        let keys: BTreeSet<String> = ["reach-a", "reach-b"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = witness_hash("eng", &["a::x".into(), "b::y".into()], &keys);
        let b = witness_hash("eng", &["b::y".into(), "a::x".into()], &keys);
        assert_eq!(a, b, "sink order must not change the witness");
        assert!(a.starts_with("sha256:"));
        assert_eq!(a.len(), "sha256:".len() + 64);
        // A different input yields a different witness.
        assert_ne!(a, witness_hash("eng2", &["a::x".into()], &keys));
    }

    #[test]
    fn unresolved_function_fails_closed_to_unknown() {
        // The repo analyzed fine but produced no verdict for the function.
        let f = finding(&["k::v"], &["a"]);
        let by_repo = repos(vec![("a", ok(vec![("other::fn", Verdict::NotReachable)]))]);
        assert!(matches!(
            combine(&f, &by_repo),
            ReachVerdict::Unknown { .. }
        ));
    }
}
