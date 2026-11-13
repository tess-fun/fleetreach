//! Function-level witnesses for npm and PyPI findings (spec 16, row 13): a call graph over
//! the repo's own JavaScript/TypeScript or Python source, and over installed dependency source
//! when `node_modules` or a virtualenv is present, judged against the bundled sink records.
//!
//! Positive-only, like the import graphs it refines. A finding whose record's sink is reached
//! by a chain of resolved calls becomes `Reachable` with that chain; anything else keeps the
//! verdict the import graph gave it. Proposed (unreviewed) records give witnesses too, since a
//! witness never sets a finding aside; one with many sinks is skipped as too broad (see
//! `fleetreach_sinks::calls`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fleetreach_core::{
    Ecosystem, FleetReport, ImportSite, Occurrence, ReachVerdict, Reachability, RepoId, VulnFinding,
};
use fleetreach_sinks::calls::{witnesses, Lang, Outcome, Project, Step};
use fleetreach_sinks::record::{SinkRecord, SinkSet};
use rayon::prelude::*;
use walkdir::WalkDir;

use crate::config::Config;

/// Annotate npm and PyPI findings in `report` that have a sink record with a call chain, when
/// the repo's code reaches a sink.
pub fn assess(report: &mut FleetReport, config: &Config, set: &SinkSet, verbose: bool) {
    // (repo, language) -> the records its findings need.
    let mut wanted: BTreeMap<(String, Lang), BTreeSet<String>> = BTreeMap::new();
    for v in &report.vulnerabilities {
        let Some(lang) = lang_of(v.ecosystem) else {
            continue;
        };
        let Some(record) = record_of(v, set) else {
            continue;
        };
        for occ in &v.occurrences {
            if let Occurrence::InRepo { repo, .. } = occ {
                wanted
                    .entry((repo.0.clone(), lang))
                    .or_default()
                    .insert(record.id.clone());
            }
        }
    }
    if wanted.is_empty() {
        return;
    }
    let outcomes: BTreeMap<(String, Lang), Outcome> = wanted
        .into_par_iter()
        .filter_map(|((repo, lang), ids)| {
            let dir = config.repos.iter().find(|r| r.id.0 == repo)?.path.clone();
            let records: Vec<&SinkRecord> = ids.iter().filter_map(|id| set.get(id)).collect();
            let outcome = analyze(&dir, lang, &records);
            if verbose {
                eprintln!(
                    "reachability(calls): {repo} {}: {} modules, {} functions, {} of {} records reached{}",
                    lang_name(lang),
                    outcome.modules,
                    outcome.functions,
                    outcome.reached.len(),
                    records.len(),
                    if outcome.truncated { " (graph size limit hit)" } else { "" },
                );
            }
            Some(((repo, lang), outcome))
        })
        .collect();

    for v in &mut report.vulnerabilities {
        let Some(lang) = lang_of(v.ecosystem) else {
            continue;
        };
        let Some(id) = record_of(v, set).map(|r| r.id.clone()) else {
            continue;
        };
        let found = v.occurrences.iter().find_map(|occ| {
            let Occurrence::InRepo { repo, .. } = occ else {
                return None;
            };
            let chain = outcomes.get(&(repo.0.clone(), lang))?.reached.get(&id)?;
            Some((repo.clone(), chain.clone()))
        });
        if let Some((repo, chain)) = found {
            v.reachable = Some(true);
            v.reachability = Some(reachability(lang, &repo, &chain));
        }
    }
}

fn reachability(lang: Lang, repo: &RepoId, chain: &[Step]) -> Reachability {
    let import_site = chain.first().and_then(|s| {
        Some(ImportSite {
            repo: repo.clone(),
            file: s.file.clone(),
            line: s.line?,
        })
    });
    Reachability {
        verdict: ReachVerdict::Reachable {
            witness: chain.iter().map(ToString::to_string).collect(),
        },
        config: "call-graph".to_string(),
        engine: match lang {
            Lang::Js => "fleetreach-js-calls",
            Lang::Python => "fleetreach-py-calls",
        }
        .to_string(),
        targets: Vec::new(),
        witness: None,
        import_site,
    }
}

fn lang_name(lang: Lang) -> &'static str {
    match lang {
        Lang::Js => "js",
        Lang::Python => "python",
    }
}

fn lang_of(e: Ecosystem) -> Option<Lang> {
    match e {
        Ecosystem::Npm => Some(Lang::Js),
        Ecosystem::Pypi => Some(Lang::Python),
        _ => None,
    }
}

/// The record for a finding's advisory id or an alias, in the finding's own ecosystem.
fn record_of<'a>(v: &VulnFinding, set: &'a SinkSet) -> Option<&'a SinkRecord> {
    let eco = match v.ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "PyPI",
        _ => return None,
    };
    std::iter::once(&v.advisory_id)
        .chain(&v.aliases)
        .filter_map(|id| set.get(id))
        .find(|r| r.ecosystem == eco)
}

fn analyze(dir: &Path, lang: Lang, records: &[&SinkRecord]) -> Outcome {
    let read = |p: &Path| fleetreach_core::repofile::read_to_string(p).ok();
    let (first_party, site_dirs) = match lang {
        Lang::Js => (js_sources(dir), Vec::new()),
        Lang::Python => {
            let layout = crate::py_reach::Layout::discover(dir);
            (layout.source_files, layout.site_dirs)
        }
    };
    let project = Project {
        lang,
        root: dir.to_path_buf(),
        first_party,
        site_dirs,
        read: &read,
    };
    witnesses(&project, records)
}

/// The repo's own JavaScript and TypeScript files (dependencies and declaration files left
/// out).
fn js_sources(dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| e.file_name() != "node_modules" && e.file_name() != ".git")
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| fleetreach_sinks::js::is_source(&e.path().to_string_lossy()))
        .map(|e| e.into_path())
        .collect()
}
