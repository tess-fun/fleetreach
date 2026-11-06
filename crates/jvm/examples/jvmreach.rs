//! Run the call graph over a service and judge every sink record.
//!
//! `cargo run -p fleetreach-jvm --example jvmreach -- RECORDS APP.jar [DEP.jar ...]`
//!
//! The first jar is the service; a Spring Boot fat jar needs nothing else. With `JVMREACH_APP`
//! set to comma-separated class name prefixes, those classes are the service instead, for
//! services shipped as a directory of jars. `JVMREACH_E3=file` writes one line per record:
//! id, verdict, verdict if the record were not marked reached by name, entry root.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fleetreach_jvm::classpath::{load, Input};
use fleetreach_jvm::graph::analyze;
use fleetreach_jvm::model::Op;
use fleetreach_jvm::model::Role;
use fleetreach_jvm::verdict::{judge, Verdict};
use fleetreach_sinks::record::load_dir;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [records, app, deps @ ..] = args.as_slice() else {
        eprintln!("usage: jvmreach RECORDS APP.jar [DEP.jar ...]");
        std::process::exit(2);
    };
    let set = match load_dir(Path::new(records)) {
        Ok(set) => set,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    let mut inputs = vec![Input {
        path: PathBuf::from(app),
        role: Role::App,
    }];
    inputs.extend(deps.iter().map(|d| Input {
        path: PathBuf::from(d),
        role: Role::Dependency,
    }));
    let cp = match load(&inputs) {
        Ok(mut cp) => {
            if let Ok(prefixes) = std::env::var("JVMREACH_APP") {
                let prefixes: Vec<&str> = prefixes.split(',').collect();
                for i in 0..cp.classes.len() {
                    let name = cp.names.name(cp.classes[i].name);
                    let app = prefixes.iter().any(|p| name.starts_with(p));
                    cp.classes[i].role = if app { Role::App } else { Role::Dependency };
                }
            }
            cp
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    let analysis = analyze(&cp);
    println!(
        "{} classes, {} unread, {} named in resources, {} entry points, {} of {} methods reached",
        cp.classes.len(),
        cp.unread.len(),
        cp.named_in_resources.len(),
        analysis.roots,
        analysis.reached(),
        analysis.methods(),
    );
    println!(
        "open reflection in {} methods, {} open invokedynamic sites",
        analysis.open_reflection.len(),
        analysis.open_dynamic,
    );
    if let Ok(path) = std::env::var("JVMREACH_DUMP") {
        let mut lines: Vec<String> = analysis.reached_classes().into_iter().collect();
        for c in &cp.classes {
            let code = !c.is_interface && c.methods.iter().any(|m| !m.ops.is_empty());
            let tag = if code { '#' } else { '=' };
            lines.push(format!("{tag} {}", cp.names.name(c.name).replace('/', ".")));
        }
        if let Err(e) = std::fs::write(&path, lines.join("\n")) {
            eprintln!("error: {path}: {e}");
        }
        let mut methods: Vec<String> = analysis.reached_methods().into_iter().collect();
        for c in &cp.classes {
            for m in &c.methods {
                let names = &cp.names;
                let (class, name, desc) =
                    (names.name(c.name), names.name(m.name), names.name(m.desc));
                let tag = if m.is_abstract { '=' } else { '#' };
                methods.push(format!("{tag} {class}.{name}:{desc}"));
            }
        }
        if let Err(e) = std::fs::write(format!("{path}.methods"), methods.join("\n")) {
            eprintln!("error: {path}.methods: {e}");
        }
    }
    if let Ok(wanted) = std::env::var("JVMREACH_CALLERS") {
        let reached = analysis.reached_methods();
        for c in &cp.classes {
            for m in &c.methods {
                for op in &m.ops {
                    if let Op::Call { class, name, .. } = op {
                        if cp.names.name(*name) == wanted {
                            let caller = format!(
                                "{}.{}:{}",
                                cp.names.name(c.name),
                                cp.names.name(m.name),
                                cp.names.name(m.desc)
                            );
                            let state = if reached.contains(&caller) {
                                "reached"
                            } else {
                                "-"
                            };
                            println!("{state} {caller} calls {}", cp.names.name(*class));
                        }
                    }
                }
            }
        }
    }
    if let Ok(path) = std::env::var("JVMREACH_E3") {
        let partial = !cp.unread.is_empty();
        let word = |v: &Verdict| match v {
            Verdict::Reached(_) => "reached".to_string(),
            Verdict::NotReached(_) => "not-reached".to_string(),
            Verdict::Unknown(why) => format!("unknown-{why:?}"),
        };
        let mut lines = Vec::new();
        for record in set.records.values() {
            let verdict = judge(record, &analysis, partial);
            let mut unflagged = record.clone();
            unflagged.reached_by_name = false;
            let open = judge(&unflagged, &analysis, partial);
            let root = match &open {
                Verdict::Reached(w) => format!("{:?}", w.root),
                _ => String::new(),
            };
            lines.push(format!(
                "{}\t{}\t{}\t{root}",
                record.id,
                word(&verdict),
                word(&open)
            ));
        }
        if let Err(e) = std::fs::write(&path, lines.join("\n")) {
            eprintln!("error: {path}: {e}");
        }
    }
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for record in set.records.values() {
        let verdict = judge(record, &analysis, !cp.unread.is_empty());
        match &verdict {
            Verdict::Reached(w) => {
                *tally.entry("reached".into()).or_default() += 1;
                let path: Vec<String> = w
                    .steps
                    .iter()
                    .map(|s| format!("{}.{}", s.class, s.method))
                    .collect();
                println!(
                    "{} reached ({:?}): {}",
                    record.id,
                    w.root,
                    path.join(" -> ")
                );
            }
            Verdict::NotReached(l) => {
                *tally.entry("not reached".into()).or_default() += 1;
                println!("{} not reached ({l:?})", record.id);
            }
            Verdict::Unknown(why) => {
                *tally.entry(format!("unknown {why:?}")).or_default() += 1;
            }
        }
    }
    println!("{tally:?}");
}
