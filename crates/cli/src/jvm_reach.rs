//! `--reachability=jvm`: a call graph over the Java archives of each image, judged against the
//! curated sink records (spec 16, row 13).
//!
//! The image's archives are written out while it is read, loaded as data by `fleetreach-jvm`
//! (never run), and walked once from the service's entry points: the classes `jvm_app` names,
//! or a fat jar's or war's own classes. Every bundled record is judged against that graph, and
//! a Maven finding takes the verdict of its advisory's record in each image it occurs in.
//!
//! Soundness discipline, as for the Rust engine: a finding is `NotReachable` only when every
//! occurrence is in an analyzed image whose graph holds a definite "not reached"
//! for a reviewed record that covers the occurrence's package. A sink reached anywhere gives
//! `Reachable` with its chain. Anything else (no record, a record reached by name or not yet
//! reviewed, a sink absent from the installed jars, an archive or class that could not be read,
//! no entry points, an occurrence outside an analyzed image) is `Unknown` with the reason.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use fleetreach_core::{
    Ecosystem, FleetReport, Occurrence, ReachVerdict, Reachability, RepoId, VulnFinding,
};
use fleetreach_jvm::classpath::{load, Input};
use fleetreach_jvm::graph::{analyze, Root};
use fleetreach_jvm::model::Role;
use fleetreach_jvm::verdict::{judge, Verdict, Why};
use fleetreach_os::image::JavaArchives;
use fleetreach_sinks::record::{SinkRecord, SinkSet};
use sha2::{Digest, Sha256};

/// The verdict scope written on every JVM verdict.
const CONFIG: &str = "image class path";

/// One graph at a time: a large image's graph holds millions of methods.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// What one image's graph says about every record.
pub(crate) struct ImageGraph {
    /// By record id.
    verdicts: BTreeMap<String, Verdict>,
    /// SHA-256 over the archives and the entry-point rule, the anchor of a `NotReachable`.
    inputs: String,
    /// `classes, entry points, methods reached`, for `--verbose`.
    pub(crate) summary: String,
}

/// Why an image has no graph.
pub(crate) type GraphOutcome = Result<ImageGraph, String>;

/// Build the graph over `archives` and judge every record in `set`. `app` holds the service's
/// own packages in slash form with a trailing slash; when empty, only a fat jar's or a war's
/// own classes are the service.
pub(crate) fn analyze_image(
    archives: &JavaArchives,
    app: &[String],
    set: &SinkSet,
) -> GraphOutcome {
    if archives.files.is_empty() {
        return Err("the image holds no Java archive".to_string());
    }
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let inputs: Vec<Input> = archives
        .files
        .iter()
        .map(|(_, file)| Input {
            path: file.clone(),
            role: Role::Dependency,
        })
        .collect();
    let mut cp = load(&inputs).map_err(|e| e.to_string())?;
    if !app.is_empty() {
        for class in &mut cp.classes {
            let name = cp.names.name(class.name);
            if app.iter().any(|p| name.starts_with(p.as_str())) {
                class.role = Role::App;
            }
        }
    }
    let analysis = analyze(&cp);
    let partial = !cp.unread.is_empty() || !archives.missing.is_empty();
    let verdicts = set
        .records
        .values()
        .map(|record| (record.id.clone(), judge(record, &analysis, partial)))
        .collect();
    let summary = format!(
        "{} classes, {} entry points, {} of {} methods reached{}",
        cp.classes.len(),
        analysis.roots,
        analysis.reached(),
        analysis.methods(),
        if partial {
            let first = cp.unread.first().or(archives.missing.first());
            format!(
                ", partial ({} unread, {} archives missing; first: {})",
                cp.unread.len(),
                archives.missing.len(),
                first.map_or("", String::as_str)
            )
        } else {
            String::new()
        }
    );
    Ok(ImageGraph {
        verdicts,
        inputs: inputs_hash(&archives.files, app)?,
        summary,
    })
}

/// SHA-256 over every archive's image path and content, and the entry-point rule.
fn inputs_hash(files: &[(String, PathBuf)], app: &[String]) -> Result<String, String> {
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

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(7 + bytes.len() * 2);
    out.push_str("sha256:");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Annotate the Maven findings that have a sink record from the images' graphs.
pub(crate) fn assess(
    report: &mut FleetReport,
    set: &SinkSet,
    graphs: &BTreeMap<RepoId, GraphOutcome>,
) {
    let engine = format!("jvm-rta@{}", env!("CARGO_PKG_VERSION"));
    for v in &mut report.vulnerabilities {
        annotate(v, set, graphs, &engine);
    }
}

/// Set one finding's reachability, if it is a Maven finding with a record.
fn annotate(
    v: &mut VulnFinding,
    set: &SinkSet,
    graphs: &BTreeMap<RepoId, GraphOutcome>,
    engine: &str,
) {
    if v.ecosystem != Ecosystem::Maven {
        return;
    }
    let Some(record) = record_of(v, set) else {
        return;
    };
    let (verdict, witness) = combine(v, record, graphs, engine);
    let reachability = Reachability {
        verdict,
        config: CONFIG.to_string(),
        engine: engine.to_string(),
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
/// reason. Every occurrence counts, even one that looks fixed: Maven versions are not semver,
/// and skipping one wrongly could only end in a wrong "not reached". A `NotReachable` carries a hash binding it to the record and the archives.
fn combine(
    v: &VulnFinding,
    record: &SinkRecord,
    graphs: &BTreeMap<RepoId, GraphOutcome>,
    engine: &str,
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
                    format!("{} is not an image analyzed for JVM reachability", repo.0)
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
            Some(Verdict::Reached(w)) => {
                let mut chain = vec![format!("{} ({})", repo.0, root_name(&w.root))];
                chain.extend(w.steps.iter().map(|s| format!("{}.{}", s.class, s.method)));
                return (ReachVerdict::Reachable { witness: chain }, None);
            }
            Some(Verdict::NotReached(_)) if covered => anchors.push(graph.inputs.as_str()),
            Some(Verdict::NotReached(_)) => {
                unknown.get_or_insert_with(|| {
                    format!("record {} does not name the package {package}", record.id)
                });
            }
            Some(Verdict::Unknown(why)) => {
                unknown.get_or_insert_with(|| format!("{}: {}", repo.0, why_text(*why)));
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
    hasher.update(engine.as_bytes());
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

fn root_name(root: &Root) -> String {
    match root {
        Root::AppCode => "service code".to_string(),
        Root::Manifest => "Main-Class".to_string(),
        Root::Nested => "nested in a made class".to_string(),
        Root::Generated => "generated or loaded by name".to_string(),
        Root::Annotation(a) => format!("@{}", a.replace('/', ".")),
        other => format!("{other:?}"),
    }
}

fn why_text(why: Why) -> &'static str {
    match why {
        Why::NoEntryPoints => {
            "no entry points: name the service's packages with `jvm_app` (or `--jvm-app`)"
        }
        Why::PartialRead => "some archives or classes could not be read",
        Why::NoSinks => "the record names no sink methods",
        Why::SinkAbsent => "no sink of the record is in the installed classes",
        Why::RecordCannotSay => "the record is not reviewed, or its sinks are reached by name",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use fleetreach_core::{DependencyKind, Exploitability, Severity};
    use fleetreach_jvm::graph::Step;
    use fleetreach_jvm::graph::Witness;
    use fleetreach_jvm::verdict::Limits;
    use fleetreach_sinks::record::{Evidence, Review, Sink, Status, Verdict as Kind, SCHEMA};

    use super::*;

    fn record() -> SinkRecord {
        SinkRecord {
            schema: SCHEMA.into(),
            id: "GHSA-aaaa-bbbb-cccc".into(),
            aliases: vec!["CVE-2099-1".into()],
            ecosystem: "Maven".into(),
            packages: vec!["g:a".into()],
            status: Status::Reviewed,
            verdict: Kind::Sinks,
            sinks: vec![Sink {
                class: "g.Flawed".into(),
                method: "sink".into(),
                descriptor: None,
            }],
            gadgets: vec![],
            reached_by_name: false,
            evidence: Evidence::default(),
            review: Some(Review {
                by: "ann".into(),
                date: "2026-11-12".into(),
                note: None,
            }),
            note: None,
        }
    }

    fn finding(repos: &[(&str, &str)]) -> VulnFinding {
        VulnFinding {
            advisory_id: "CVE-2099-1".into(),
            aliases: vec![],
            ecosystem: Ecosystem::Maven,
            title: "t".into(),
            severity: Severity::High,
            cvss_score: None,
            cvss_vector: None,
            url: None,
            occurrences: repos
                .iter()
                .map(|(repo, package)| Occurrence::InRepo {
                    repo: RepoId((*repo).into()),
                    package: (*package).into(),
                    installed: fleetreach_core::semver::Version::new(1, 0, 0),
                    patched: vec![],
                    dependency_kind: DependencyKind::Transitive,
                    dependency_path: vec![],
                    active: None,
                    source: Default::default(),
                    scope: Default::default(),
                    layer: None,
                })
                .collect(),
            affected_functions: vec![],
            reachable: None,
            reachability: None,
            exploit: Exploitability::default(),
        }
    }

    fn graph(verdict: Verdict) -> GraphOutcome {
        Ok(ImageGraph {
            verdicts: BTreeMap::from([("GHSA-aaaa-bbbb-cccc".to_string(), verdict)]),
            inputs: "sha256:00".into(),
            summary: String::new(),
        })
    }

    fn not_reached() -> Verdict {
        Verdict::NotReached(Limits {
            open_reflection: 0,
            open_dynamic: 0,
        })
    }

    fn verdict_of(v: &VulnFinding, graphs: &BTreeMap<RepoId, GraphOutcome>) -> ReachVerdict {
        combine(v, &record(), graphs, "jvm-rta@test").0
    }

    #[test]
    fn not_reached_in_every_image_is_not_reachable_with_a_witness() {
        let graphs = BTreeMap::from([
            (RepoId("one".into()), graph(not_reached())),
            (RepoId("two".into()), graph(not_reached())),
        ]);
        let v = finding(&[("one", "g:a"), ("two", "g:a")]);
        let (verdict, witness) = combine(&v, &record(), &graphs, "jvm-rta@test");
        assert_eq!(verdict, ReachVerdict::NotReachable);
        assert!(witness.unwrap().starts_with("sha256:"));
    }

    #[test]
    fn an_occurrence_outside_an_analyzed_image_is_unknown() {
        let graphs = BTreeMap::from([(RepoId("one".into()), graph(not_reached()))]);
        let v = finding(&[("one", "g:a"), ("repo", "g:a")]);
        assert!(matches!(
            verdict_of(&v, &graphs),
            ReachVerdict::Unknown { .. }
        ));
        let graphs = BTreeMap::from([(RepoId("one".into()), Err("no archives".to_string()))]);
        let v = finding(&[("one", "g:a")]);
        assert!(matches!(
            verdict_of(&v, &graphs),
            ReachVerdict::Unknown { .. }
        ));
    }

    #[test]
    fn a_package_the_record_does_not_name_is_unknown() {
        let graphs = BTreeMap::from([(RepoId("one".into()), graph(not_reached()))]);
        let v = finding(&[("one", "g:other")]);
        assert!(matches!(
            verdict_of(&v, &graphs),
            ReachVerdict::Unknown { .. }
        ));
    }

    #[test]
    fn a_reached_sink_anywhere_wins_with_its_chain() {
        let witness = Witness {
            root: Root::AppCode,
            steps: vec![Step {
                class: "g.Flawed".into(),
                method: "sink".into(),
                descriptor: "()V".into(),
            }],
        };
        let graphs = BTreeMap::from([
            (RepoId("one".into()), graph(not_reached())),
            (
                RepoId("two".into()),
                graph(Verdict::Reached(Box::new(witness))),
            ),
        ]);
        let v = finding(&[("one", "g:a"), ("two", "g:other")]);
        let ReachVerdict::Reachable { witness } = verdict_of(&v, &graphs) else {
            unreachable!()
        };
        assert_eq!(witness, ["two (service code)", "g.Flawed.sink"]);
    }

    #[test]
    fn a_record_that_cannot_say_stays_unknown() {
        let graphs = BTreeMap::from([(
            RepoId("one".into()),
            graph(Verdict::Unknown(Why::RecordCannotSay)),
        )]);
        let v = finding(&[("one", "g:a")]);
        assert!(matches!(
            verdict_of(&v, &graphs),
            ReachVerdict::Unknown { .. }
        ));
    }

    #[test]
    fn findings_with_no_record_are_left_alone() {
        let mut v = finding(&[("one", "g:a")]);
        v.advisory_id = "GHSA-none".into();
        let graphs = BTreeMap::from([(RepoId("one".into()), graph(not_reached()))]);
        let mut set = SinkSet::default();
        set.records.insert(record().id, record());
        set.aliases.insert("CVE-2099-1".into(), record().id);
        annotate(&mut v, &set, &graphs, "jvm-rta@test");
        assert!(v.reachability.is_none());
        v.advisory_id = "CVE-2099-1".into();
        annotate(&mut v, &set, &graphs, "jvm-rta@test");
        let r = v.reachability.as_ref().unwrap();
        assert_eq!(r.verdict, ReachVerdict::NotReachable);
        assert_eq!(v.reachable, Some(false));
    }
}
