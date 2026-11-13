//! `--reachability=jvm`: a call graph over the Java archives of each image, judged against the
//! curated sink records (spec 16, row 13).
//!
//! The image's archives are written out while it is read, loaded as data by `fleetreach-jvm`
//! (never run), and walked once from the service's entry points: the classes `jvm_app` names,
//! or a fat jar's or war's own classes. Every bundled record is judged against that graph, and
//! a Maven finding takes the verdict of its advisory's record in each image it occurs in.
//! How a finding's occurrences combine into one verdict is `graph_reach`'s, shared with
//! `--reachability=dotnet`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use fleetreach_core::{Ecosystem, FleetReport, RepoId};
use fleetreach_jvm::classpath::{load, Input};
use fleetreach_jvm::graph::{analyze, Root};
use fleetreach_jvm::model::Role;
use fleetreach_jvm::verdict::{judge, Verdict, Why};
use fleetreach_os::image::JavaArchives;
use fleetreach_sinks::record::SinkSet;

pub(crate) use crate::graph_reach::GraphOutcome;
use crate::graph_reach::{inputs_hash, Engine, ImageGraph, Judged};

/// The verdict scope written on every JVM verdict.
const CONFIG: &str = "image class path";

/// One graph at a time: a large image's graph holds millions of methods.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

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
        .map(|record| {
            let verdict = judge(record, &analysis, partial);
            (record.id.clone(), judged(verdict, &archives.files))
        })
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

/// The JVM verdict in report terms.
fn judged(verdict: Verdict, files: &[(String, std::path::PathBuf)]) -> Judged {
    match verdict {
        Verdict::Reached(w) => Judged::Reached {
            root: root_name(&in_image(&w.root, files)),
            steps: w
                .steps
                .iter()
                .map(|s| format!("{}.{}", s.class, s.method))
                .collect(),
        },
        Verdict::NotReached(_) => Judged::NotReached,
        Verdict::Unknown(why) => Judged::Unknown(why_text(why)),
    }
}

/// Annotate the Maven findings that have a sink record from the images' graphs.
pub(crate) fn assess(
    report: &mut FleetReport,
    set: &SinkSet,
    graphs: &BTreeMap<RepoId, GraphOutcome>,
) {
    crate::graph_reach::assess(report, set, graphs, &engine());
}

fn engine() -> Engine<'static> {
    Engine {
        ecosystem: Ecosystem::Maven,
        name: format!("jvm-rta@{}", env!("CARGO_PKG_VERSION")),
        config: CONFIG,
        kind: "JVM",
    }
}

/// A resource root names the written-out copy of its archive; name the archive by its path in
/// the image instead, which is stable and means something to the reader.
fn in_image(root: &Root, files: &[(String, std::path::PathBuf)]) -> Root {
    let Root::Resource(origin) = root else {
        return root.clone();
    };
    for (path, file) in files {
        if let Some(rest) = origin.strip_prefix(file.to_string_lossy().as_ref()) {
            return Root::Resource(format!("{path}{rest}"));
        }
    }
    root.clone()
}

fn root_name(root: &Root) -> String {
    match root {
        Root::AppCode => "service code".to_string(),
        Root::Manifest => "Main-Class".to_string(),
        Root::Nested => "nested in a made class".to_string(),
        Root::Generated => "generated or loaded by name".to_string(),
        Root::Annotation(a) => format!("@{}", a.replace('/', ".")),
        Root::Resource(origin) => format!("named in {origin}"),
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
    use crate::graph_reach::{annotate, combine};
    use fleetreach_core::{Occurrence, ReachVerdict, VulnFinding};
    use fleetreach_sinks::record::SinkRecord;

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
            verdicts: BTreeMap::from([("GHSA-aaaa-bbbb-cccc".to_string(), judged(verdict, &[]))]),
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

    fn test_engine() -> Engine<'static> {
        Engine {
            name: "jvm-rta@test".into(),
            ..engine()
        }
    }

    fn verdict_of(v: &VulnFinding, graphs: &BTreeMap<RepoId, GraphOutcome>) -> ReachVerdict {
        combine(v, &record(), graphs, &test_engine()).0
    }

    #[test]
    fn not_reached_in_every_image_is_not_reachable_with_a_witness() {
        let graphs = BTreeMap::from([
            (RepoId("one".into()), graph(not_reached())),
            (RepoId("two".into()), graph(not_reached())),
        ]);
        let v = finding(&[("one", "g:a"), ("two", "g:a")]);
        let (verdict, witness) = combine(&v, &record(), &graphs, &test_engine());
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
    fn a_resource_root_names_the_archive_in_the_image() {
        let files = [(
            "usr/local/tomcat/lib/jasper.jar".to_string(),
            std::path::PathBuf::from("/tmp/fleetreach-jars-x/000009.jar"),
        )];
        let root = Root::Resource("/tmp/fleetreach-jars-x/000009.jar!META-INF/x.xml".into());
        assert_eq!(
            root_name(&in_image(&root, &files)),
            "named in usr/local/tomcat/lib/jasper.jar!META-INF/x.xml"
        );
    }

    #[test]
    fn findings_with_no_record_are_left_alone() {
        let mut v = finding(&[("one", "g:a")]);
        v.advisory_id = "GHSA-none".into();
        let graphs = BTreeMap::from([(RepoId("one".into()), graph(not_reached()))]);
        let mut set = SinkSet::default();
        set.records.insert(record().id, record());
        set.aliases.insert("CVE-2099-1".into(), record().id);
        annotate(&mut v, &set, &graphs, &test_engine());
        assert!(v.reachability.is_none());
        v.advisory_id = "CVE-2099-1".into();
        annotate(&mut v, &set, &graphs, &test_engine());
        let r = v.reachability.as_ref().unwrap();
        assert_eq!(r.verdict, ReachVerdict::NotReachable);
        assert_eq!(v.reachable, Some(false));
    }
}
