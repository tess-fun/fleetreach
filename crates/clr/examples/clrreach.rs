//! Build the call graph over a .NET app's output folder and compare it with the methods the
//! runtime ran (the JIT-event oracle, docs/differential/clr/jit): every method that ran in
//! one of the folder's assemblies should be in the graph.
//!
//! `clrreach [--framework DIR]... APP.dll DIR [RAN.txt]`: APP.dll is the service's own
//! assembly, every other `*.dll` in DIR a dependency. Each `--framework` folder (a shared
//! framework such as `shared/Microsoft.NETCore.App/10.0.9`) gives the interfaces the
//! runtime calls through. Without RAN.txt, prints the graph's size only.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

use fleetreach_clr::graph::{analyze_outside, OutsideInterfaces, Role};

fn main() {
    let mut args: Vec<String> = Vec::new();
    let mut frameworks: Vec<String> = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == "--framework" {
            frameworks.extend(it.next());
        } else {
            args.push(a);
        }
    }
    let [app, dir, rest @ ..] = args.as_slice() else {
        eprintln!("usage: clrreach [--framework DIR]... APP.dll DIR [RAN.txt]");
        std::process::exit(2);
    };
    let start = Instant::now();
    let mut outside = OutsideInterfaces::default();
    for fw in &frameworks {
        for e in std::fs::read_dir(fw).into_iter().flatten().flatten() {
            let p = e.path();
            if p.extension().and_then(|e| e.to_str()) != Some("dll") {
                continue;
            }
            if let Some(a) = std::fs::read(&p)
                .ok()
                .and_then(|b| fleetreach_clr::read(&b).ok())
            {
                outside.add(&a);
            }
        }
    }
    let mut inputs = Vec::new();
    // The whole tree: `runtimes/<rid>/lib/` holds platform builds that replace the top
    // level's.
    let mut entries = Vec::new();
    let mut dirs = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else {
                entries.push(p);
            }
        }
    }
    entries.sort();
    let app_path = Path::new(dir).join(app);
    for path in entries {
        if path.extension().and_then(|e| e.to_str()) != Some("dll") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        match fleetreach_clr::read(&bytes) {
            Ok(a) => {
                let role = if path == app_path {
                    Role::App
                } else {
                    Role::Dependency
                };
                inputs.push((a, role));
            }
            Err(e) => eprintln!("unread {}: {e}", path.display()),
        }
    }
    let read = start.elapsed();
    let analysis = analyze_outside(&inputs, &[], &outside);
    let walked = start.elapsed() - read;
    println!(
        "{} assemblies, {} methods, {} reached, {} roots, {} open reflection; read {:.0?}, graph {:.0?}",
        inputs.len(),
        analysis.methods(),
        analysis.reached(),
        analysis.roots,
        analysis.open_reflection.len(),
        read,
        walked
    );
    let Some(ran) = rest.first() else { return };
    let reached = analysis.reached_methods();
    // `Assembly\tType::Method`; `?` when the runtime loaded the module before the oracle
    // started listening.
    let defined: BTreeSet<(String, String)> = inputs
        .iter()
        .flat_map(|(a, _)| {
            a.types.iter().flat_map(move |t| {
                t.methods
                    .iter()
                    .map(move |m| (a.name.clone(), format!("{}::{}", t.full_name, m.name)))
            })
        })
        .collect();
    let by_name: BTreeSet<&str> = defined.iter().map(|(_, m)| m.as_str()).collect();
    let text = std::fs::read_to_string(ran).unwrap_or_default();
    let mut ran_in = 0;
    let mut missed = Vec::new();
    for line in text.lines() {
        let (assembly, method) = line.split_once('\t').unwrap_or(("?", line));
        let ours = if assembly == "?" {
            by_name.contains(method)
        } else {
            defined.contains(&(assembly.to_string(), method.to_string()))
        };
        if !ours {
            continue;
        }
        ran_in += 1;
        if !reached.contains(method) {
            missed.push(line);
        }
    }
    println!(
        "ran in these assemblies: {ran_in}, missed by the graph: {}",
        missed.len()
    );
    for m in missed {
        println!("MISS {m}");
    }
}
