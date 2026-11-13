//! What the image call graphs (`--reachability=jvm`, `--reachability=dotnet`) share: one
//! graph per image judged against every bundled sink record, and a finding's verdict over all
//! its occurrences.
//!
//! Soundness discipline, as for the Rust engine: a finding is `NotReachable` only when every
//! occurrence is in an analyzed image whose graph holds a definite "not reached" for a
//! reviewed record that covers the occurrence's package. A sink reached anywhere gives
//! `Reachable` with its chain. Anything else (no record, a record reached by name or not yet
//! reviewed, a sink absent from the installed code, a file that could not be read, no entry
//! points, an occurrence outside an analyzed image) is `Unknown` with the reason.

use crate::hexenc::ToHex;
use std::collections::BTreeMap;
use std::path::PathBuf;

use fleetreach_core::{
    Ecosystem, FleetReport, Occurrence, ReachVerdict, Reachability, RepoId, VulnFinding,
};
use fleetreach_sinks::record::{SinkRecord, SinkSet};
use sha2::{Digest, Sha256};

/// What one image's graph says about one record, in report terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Judged {
    /// Why the first step is an entry point, then each step as `Type.method`.
    Reached {
        root: String,
        steps: Vec<String>,
    },
    NotReached,
    /// Why the graph cannot say.
    Unknown(&'static str),
}

/// What one image's graph says about every record.
pub(crate) struct ImageGraph {
    /// By record id.
    pub(crate) verdicts: BTreeMap<String, Judged>,
    /// SHA-256 over the inputs and the entry-point rule, the anchor of a `NotReachable`.
    pub(crate) inputs: String,
    /// The graph's size, for `--verbose`.
    pub(crate) summary: String,
}

/// Why an image has no graph.
pub(crate) type GraphOutcome = Result<ImageGraph, String>;

/// One engine's terms: which findings it judges and how it names itself.
pub(crate) struct Engine<'a> {
    pub(crate) ecosystem: Ecosystem,
    /// `jvm-rta@1.7.0`.
    pub(crate) name: String,
    /// The verdict scope written on every verdict.
    pub(crate) config: &'a str,
    /// For an occurrence in a repo that is not an analyzed image: "JVM", ".NET".
    pub(crate) kind: &'a str,
}

/// SHA-256 over every input file's image path and content, and the entry-point rule.
pub(crate) fn inputs_hash(files: &[(String, PathBuf)], app: &[String]) -> Result<String, String> {
    let mut hasher = Sha256::new();
    for (path, file) in files {
        let data = std::fs::read(file).map_err(|e| format!("{path}: {e}"))?;
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(Sha256::digest(&data));
    }
    for package in app {
        hasher.update([1]);
        hasher.update(package.as_bytes());
    }
    Ok(hex(&hasher.finalize()))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    format!("sha256:{}", bytes.to_hex())
}

/// Annotate the engine's findings that have a sink record from the images' graphs.
pub(crate) fn assess(
    report: &mut FleetReport,
    set: &SinkSet,
    graphs: &BTreeMap<RepoId, GraphOutcome>,
    engine: &Engine<'_>,
) {
    for v in &mut report.vulnerabilities {
        annotate(v, set, graphs, engine);
    }
}

/// Set one finding's reachability, if it is the engine's ecosystem and has a record.
pub(crate) fn annotate(
    v: &mut VulnFinding,
    set: &SinkSet,
    graphs: &BTreeMap<RepoId, GraphOutcome>,
    engine: &Engine<'_>,
) {
    if v.ecosystem != engine.ecosystem {
        return;
    }
    let Some(record) = record_of(v, set) else {
        return;
    };
    let (verdict, witness) = combine(v, record, graphs, engine);
    let reachability = Reachability {
        verdict,
        config: engine.config.to_string(),
        engine: engine.name.clone(),
        targets: Vec::new(),
        witness,
        import_site: None,
    };
    v.reachable = reachability.as_legacy_bool();
    v.reachability = Some(reachability);
}

/// The record for a finding's advisory id or any of its aliases.
fn record_of<'a>(v: &VulnFinding, set: &'a SinkSet) -> Option<&'a SinkRecord> {
    std::iter::once(&v.advisory_id)
        .chain(&v.aliases)
        .find_map(|id| set.get(id))
}

/// One finding's verdict over all its occurrences: `Reachable` if any image reaches a sink,
/// `NotReachable` only if every one is a definite "not reached", else `Unknown` with the first
/// reason. Every occurrence counts, even one that looks fixed: skipping one wrongly could only
/// end in a wrong "not reached". A `NotReachable` carries a hash binding it to the record and
/// the inputs.
pub(crate) fn combine(
    v: &VulnFinding,
    record: &SinkRecord,
    graphs: &BTreeMap<RepoId, GraphOutcome>,
    engine: &Engine<'_>,
) -> (ReachVerdict, Option<String>) {
    let mut unknown: Option<String> = None;
    let mut anchors = Vec::new();
    for occ in &v.occurrences {
        let Occurrence::InRepo { repo, package, .. } = occ else {
            unknown.get_or_insert_with(|| "a toolchain occurrence has no class path".into());
            continue;
        };
        let graph = match graphs.get(repo) {
            None => {
                unknown.get_or_insert_with(|| {
                    format!(
                        "{} is not an image analyzed for {} reachability",
                        repo.0, engine.kind
                    )
                });
                continue;
            }
            Some(Err(why)) => {
                unknown.get_or_insert_with(|| format!("{}: {why}", repo.0));
                continue;
            }
            Some(Ok(graph)) => graph,
        };
        let covered = record.packages.iter().any(|p| p == package);
        match graph.verdicts.get(&record.id) {
            Some(Judged::Reached { root, steps }) => {
                let mut chain = vec![format!("{} ({root})", repo.0)];
                chain.extend(steps.iter().cloned());
                return (ReachVerdict::Reachable { witness: chain }, None);
            }
            Some(Judged::NotReached) if covered => anchors.push(graph.inputs.as_str()),
            Some(Judged::NotReached) => {
                unknown.get_or_insert_with(|| {
                    format!("record {} does not name the package {package}", record.id)
                });
            }
            Some(Judged::Unknown(why)) => {
                unknown.get_or_insert_with(|| format!("{}: {why}", repo.0));
            }
            None => {
                unknown.get_or_insert_with(|| format!("{}: record not judged", repo.0));
            }
        }
    }
    if let Some(reason) = unknown {
        return (ReachVerdict::Unknown { reason }, None);
    }
    if anchors.is_empty() {
        let reason = "no occurrence to judge".to_string();
        return (ReachVerdict::Unknown { reason }, None);
    }
    anchors.sort_unstable();
    anchors.dedup();
    let mut hasher = Sha256::new();
    hasher.update(engine.name.as_bytes());
    hasher.update([0]);
    hasher.update(record.id.as_bytes());
    for sink in &record.sinks {
        hasher.update([0]);
        hasher.update(sink.key().as_bytes());
    }
    for anchor in anchors {
        hasher.update([1]);
        hasher.update(anchor.as_bytes());
    }
    (ReachVerdict::NotReachable, Some(hex(&hasher.finalize())))
}
