//! `--reachability=dotnet`: a call graph over the .NET assemblies of each image, judged against
//! the curated NuGet sink records (spec 16, row 13).
//!
//! The image's assemblies (every `.dll` outside the runtime's own shared frameworks) are written
//! out while it is read, parsed as data by `fleetreach-clr` (never loaded or run), and walked
//! once from the services' entry points. A service is a folder holding a `*.deps.json`, as
//! `dotnet publish` writes it: its own assembly and the deps file's `project` libraries are the
//! service's code. Type names in its configuration files (`appsettings*.json`, `*.config`) are
//! made, since reflection loads them. The shared frameworks' assemblies are read for their
//! interfaces only: a method can be the runtime's way in only under a name an outside interface
//! declares. Every bundled NuGet record is judged against that graph,
//! and a NuGet finding takes the verdict of its advisory's record in each image it occurs in,
//! combined as for the JVM (`graph_reach`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use fleetreach_clr::graph::{analyze_outside, OutsideInterfaces, Role, Root};
use fleetreach_clr::verdict::{judge, Verdict, Why};
use fleetreach_core::{Ecosystem, FleetReport, RepoId};
use fleetreach_os::image::DotnetAssemblies;
use fleetreach_os::ImageFs;
use fleetreach_sinks::record::SinkSet;

pub(crate) use crate::graph_reach::GraphOutcome;
use crate::graph_reach::{inputs_hash, Engine, ImageGraph, Judged};

/// The verdict scope written on every .NET verdict.
const CONFIG: &str = "image assemblies";

/// One graph at a time, as for the JVM.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Whether the image reader should keep a file for this engine: assemblies and the shared
/// frameworks' (written out) and the configuration files whose type names reflection loads.
pub(crate) fn wanted(path: &str) -> bool {
    fleetreach_os::image::is_assembly(path)
        || fleetreach_os::image::is_framework_assembly(path)
        || is_config(path)
}

/// `appsettings.json`, `appsettings.Production.json`, `web.config`, `App.dll.config`,
/// `nlog.config`, `log4net.config`.
fn is_config(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    (name.starts_with("appsettings") && name.ends_with(".json")) || name.ends_with(".config")
}

/// The services in an image: each `*.deps.json` folder, with its own assembly names (lower
/// case) from the file name and the deps file's `project` libraries.
fn services(fs: &ImageFs) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (path, data) in fs.files() {
        let Some(stem) = path.strip_suffix(".deps.json") else {
            continue;
        };
        // The shared frameworks' own deps files describe the runtime, not a service.
        if !fleetreach_os::image::is_assembly(&format!("{stem}.dll")) {
            continue;
        }
        let (dir, name) = stem.rsplit_once('/').unwrap_or(("", stem));
        let own = out.entry(dir.to_string()).or_default();
        own.insert(name.to_ascii_lowercase());
        let Some(json) = data.and_then(|d| serde_json::from_slice::<serde_json::Value>(d).ok())
        else {
            continue;
        };
        if let Some(libraries) = json.get("libraries").and_then(|l| l.as_object()) {
            for (key, lib) in libraries {
                if lib.get("type").and_then(|t| t.as_str()) == Some("project") {
                    let id = key.split('/').next().unwrap_or(key);
                    own.insert(id.to_ascii_lowercase());
                }
            }
        }
    }
    out
}

/// The service a path belongs to: the deepest service folder holding it.
fn service_of<'a>(services: &'a BTreeMap<String, BTreeSet<String>>, path: &str) -> Option<&'a str> {
    services
        .keys()
        .filter(|dir| dir.is_empty() || path.starts_with(&format!("{dir}/")))
        .max_by_key(|dir| dir.len())
        .map(String::as_str)
}

/// Dotted words in a configuration file, which may name types.
fn config_names(fs: &ImageFs, services: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    let mut names = BTreeSet::new();
    for (path, data) in fs.files() {
        if !is_config(path) || service_of(services, path).is_none() {
            continue;
        }
        let Some(text) = data.and_then(|d| std::str::from_utf8(d).ok()) else {
            continue;
        };
        for word in
            text.split(|c: char| !(c.is_alphanumeric() || matches!(c, '.' | '+' | '`' | '_')))
        {
            if word.contains('.') && word.len() > 2 {
                names.insert(word.to_string());
            }
        }
    }
    names.into_iter().collect()
}

/// Build the graph over the image's assemblies and judge every NuGet record in `set`.
pub(crate) fn analyze_image(fs: &ImageFs, set: &SinkSet) -> GraphOutcome {
    let assemblies: DotnetAssemblies = fs.dotnet_assemblies();
    if assemblies.files.is_empty() {
        return Err("the image holds no .NET assembly".to_string());
    }
    let services = services(fs);
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut inputs = Vec::new();
    let mut unread = Vec::new();
    for (path, file) in &assemblies.files {
        let bytes = std::fs::read(file).map_err(|e| format!("{path}: {e}"))?;
        match fleetreach_clr::read(&bytes) {
            Ok(assembly) => {
                let name = path.rsplit('/').next().unwrap_or(path);
                let stem = name
                    .get(..name.len().saturating_sub(4))
                    .unwrap_or(name)
                    .to_ascii_lowercase();
                let own = service_of(&services, path)
                    .and_then(|dir| services.get(dir))
                    .is_some_and(|own| own.contains(&stem));
                let role = if own { Role::App } else { Role::Dependency };
                inputs.push((assembly, role));
            }
            // A native DLL beside the managed ones is not code the graph could miss.
            Err(fleetreach_clr::ClrError::NotDotNet) => {}
            Err(e) => unread.push(format!("{path}: {e}")),
        }
    }
    // The shared frameworks' interfaces, which say which methods the runtime may call.
    let mut outside = OutsideInterfaces::default();
    outside.add_files(assemblies.framework.iter().map(|(_, file)| file));
    let names = config_names(fs, &services);
    let analysis = analyze_outside(&inputs, &names, &outside);
    let partial = !unread.is_empty() || !assemblies.missing.is_empty();
    let verdicts = set
        .records
        .values()
        .filter(|r| r.ecosystem == "NuGet")
        .map(|record| (record.id.clone(), judged(judge(record, &analysis, partial))))
        .collect();
    let summary = format!(
        "{} assemblies in {} service(s), {} entry points, {} of {} methods reached{}",
        inputs.len(),
        services.len(),
        analysis.roots,
        analysis.reached(),
        analysis.methods(),
        if partial {
            let first = unread.first().or(assemblies.missing.first());
            format!(
                ", partial ({} unread, {} missing; first: {})",
                unread.len(),
                assemblies.missing.len(),
                first.map_or("", String::as_str)
            )
        } else {
            String::new()
        }
    );
    let mut rule: Vec<String> = services
        .iter()
        .flat_map(|(dir, own)| own.iter().map(move |n| format!("{dir}/{n}")))
        .collect();
    rule.extend(names);
    // A framework is named by its versioned folder, so its paths stand for its content.
    rule.extend(
        assemblies
            .framework
            .iter()
            .map(|(p, _)| format!("framework:{p}")),
    );
    Ok(ImageGraph {
        verdicts,
        inputs: inputs_hash(&assemblies.files, &rule)?,
        summary,
    })
}

/// The .NET verdict in report terms.
fn judged(verdict: Verdict) -> Judged {
    match verdict {
        Verdict::Reached(w) => Judged::Reached {
            root: root_name(&w.root).to_string(),
            steps: w
                .steps
                .iter()
                .map(|s| format!("{}.{}", s.type_name, s.method))
                .collect(),
        },
        Verdict::NotReached(_) => Judged::NotReached,
        Verdict::Unknown(why) => Judged::Unknown(why_text(why)),
    }
}

fn root_name(root: &Root) -> &'static str {
    match root {
        Root::AppCode => "service code",
        Root::Outside => "called by the runtime or by reflection",
        Root::AssemblyAttribute => "an assembly attribute",
        Root::Configuration => "named in configuration",
    }
}

fn why_text(why: Why) -> &'static str {
    match why {
        Why::NoEntryPoints => "no entry points: no folder holds a .deps.json naming the service",
        Why::PartialRead => "some assemblies could not be read",
        Why::NoSinks => "the record names no sink methods",
        Why::SinkAbsent => "no sink of the record is in the installed assemblies",
        Why::RecordCannotSay => "the record is not reviewed, or its sinks are reached by name",
    }
}

/// Annotate the NuGet findings that have a sink record from the images' graphs.
pub(crate) fn assess(
    report: &mut FleetReport,
    set: &SinkSet,
    graphs: &BTreeMap<RepoId, GraphOutcome>,
) {
    let engine = Engine {
        ecosystem: Ecosystem::NuGet,
        name: format!("clr-rta@{}", env!("CARGO_PKG_VERSION")),
        config: CONFIG,
        kind: ".NET",
    };
    crate::graph_reach::assess(report, set, graphs, &engine);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn record(id: &str, class: &str) -> fleetreach_sinks::record::SinkRecord {
        use fleetreach_sinks::record::{Evidence, Review, Sink, Status, Verdict as Kind, SCHEMA};
        fleetreach_sinks::record::SinkRecord {
            schema: SCHEMA.into(),
            id: id.into(),
            aliases: vec![],
            ecosystem: "NuGet".into(),
            packages: vec!["graphlib".into()],
            status: Status::Reviewed,
            verdict: Kind::Sinks,
            sinks: vec![Sink {
                class: class.into(),
                method: "Mark".into(),
                descriptor: None,
            }],
            gadgets: vec![],
            reached_by_name: false,
            evidence: Evidence::default(),
            review: Some(Review {
                by: "ann".into(),
                date: "2026-11-13".into(),
                note: None,
            }),
            note: None,
        }
    }

    /// A root filesystem with the crate's graph fixture published as a service.
    fn image(with_deps: bool) -> (tempfile::TempDir, tempfile::TempDir, ImageFs) {
        let root = tempfile::tempdir().unwrap();
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../clr/tests");
        std::fs::create_dir_all(root.path().join("app")).unwrap();
        for dll in ["graphapp.dll", "graphlib.dll"] {
            std::fs::copy(fixtures.join(dll), root.path().join("app").join(dll)).unwrap();
        }
        if with_deps {
            std::fs::write(
                root.path().join("app/graphapp.deps.json"),
                r#"{"libraries":{"graphapp/1.0.0":{"type":"project"},"graphlib/1.0.0":{"type":"package"}}}"#,
            )
            .unwrap();
        }
        let spill = tempfile::tempdir().unwrap();
        let fs = fleetreach_os::image::open_spilling_assemblies(
            root.path(),
            &|p| fleetreach_os::lang::wanted(p) || wanted(p),
            None,
            spill.path(),
        )
        .unwrap();
        (root, spill, fs)
    }

    #[test]
    fn an_image_service_is_judged_against_nuget_records() {
        let mut set = SinkSet::default();
        for r in [
            record("GHSA-aaaa-bbbb-cccc", "Lib.Unreached"),
            record("GHSA-aaaa-bbbb-dddd", "Lib.ViaString"),
        ] {
            set.records.insert(r.id.clone(), r);
        }
        let (_root, _spill, fs) = image(true);
        let graph = analyze_image(&fs, &set).unwrap();
        assert_eq!(graph.verdicts["GHSA-aaaa-bbbb-cccc"], Judged::NotReached);
        let Judged::Reached { root, steps } = &graph.verdicts["GHSA-aaaa-bbbb-dddd"] else {
            panic!("{:?}", graph.verdicts);
        };
        assert_eq!(root, "service code");
        assert_eq!(steps.last().unwrap(), "Lib.ViaString.Mark");
        assert!(
            graph.summary.starts_with("2 assemblies in 1 service(s)"),
            "{}",
            graph.summary
        );

        // Without a deps file nothing is the service's code: no entry points, no claim.
        let (_root, _spill, fs) = image(false);
        let graph = analyze_image(&fs, &set).unwrap();
        assert!(matches!(
            graph.verdicts["GHSA-aaaa-bbbb-cccc"],
            Judged::Unknown(_)
        ));
    }

    #[test]
    fn services_come_from_deps_files_outside_the_runtime() {
        let deps = br#"{"libraries":{"Api/1.0.0":{"type":"project"},"Shared/1.0.0":{"type":"project"},"Newtonsoft.Json/13.0.3":{"type":"package"}}}"#;
        let fs = ImageFs::from_files([
            ("app/Api.deps.json", &deps[..]),
            (
                "usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.1/Microsoft.NETCore.App.deps.json",
                b"{}",
            ),
            ("app/appsettings.json", br#"{"Serilog":{"Using":["Serilog.Sinks.File"]}}"#),
        ]);
        let s = services(&fs);
        assert_eq!(s.len(), 1);
        assert_eq!(
            s["app"].iter().cloned().collect::<Vec<_>>(),
            ["api", "shared"]
        );
        assert_eq!(
            service_of(&s, "app/runtimes/unix/lib/net8.0/x.dll"),
            Some("app")
        );
        assert_eq!(service_of(&s, "opt/other/x.dll"), None);
        assert_eq!(config_names(&fs, &s), ["Serilog.Sinks.File"]);
        assert!(wanted("app/web.config") && wanted("app/x.dll") && !wanted("app/x.pdb"));
    }
}
