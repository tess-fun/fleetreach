//! Run the source call graph over one project against every bundled record of an ecosystem,
//! printing each chain found (a measuring harness, not a scan).
//!
//! `cargo run -p fleetreach-sinks --example callwitness -- --lang js|python --root DIR [--records DIR]`
//!
//! First-party files are every source file under `DIR` outside `node_modules`, `.git` and
//! virtualenvs (a directory holding `pyvenv.cfg`, whose `site-packages` are read as installed
//! code). Output: one JSON line per record reached, then a summary line on stderr.

use std::path::{Path, PathBuf};

use fleetreach_sinks::calls::{witnesses, Lang, Project};
use fleetreach_sinks::record::bundled;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let (mut lang, mut root, mut records_dir) = (None, None, None);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--lang" => lang = Some(value),
            "--root" => root = Some(PathBuf::from(value)),
            "--records" => records_dir = Some(PathBuf::from(value)),
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let root = root.ok_or("--root is required")?;
    let (lang, eco) = match lang.as_deref() {
        Some("js") => (Lang::Js, "npm"),
        Some("python") => (Lang::Python, "PyPI"),
        _ => return Err("--lang js|python".into()),
    };
    let set = match records_dir {
        Some(dir) => fleetreach_sinks::record::load_dir(&dir).map_err(|e| e.to_string())?,
        None => bundled().map_err(|e| e.to_string())?,
    };
    let records: Vec<_> = set
        .records
        .values()
        .filter(|r| r.ecosystem == eco)
        .collect();
    let (mut first_party, mut site_dirs) = (Vec::new(), Vec::new());
    walk(&root, lang, &mut first_party, &mut site_dirs);
    first_party.sort();
    let read = |p: &Path| std::fs::read_to_string(p).ok();
    let project = Project {
        lang,
        root: root.clone(),
        first_party,
        site_dirs,
        read: &read,
    };
    let start = std::time::Instant::now();
    let out = witnesses(&project, &records);
    for (id, chain) in &out.reached {
        let steps: Vec<String> = chain.iter().map(ToString::to_string).collect();
        let packages = set.get(id).map(|r| r.packages.clone()).unwrap_or_default();
        println!(
            "{}",
            serde_json::json!({"id": id, "packages": packages, "chain": steps})
        );
    }
    eprintln!(
        "{}: {} first-party files, {} modules, {} functions, {} of {} records reached, {:.1}s{}",
        root.display(),
        project.first_party.len(),
        out.modules,
        out.functions,
        out.reached.len(),
        records.len(),
        start.elapsed().as_secs_f64(),
        if out.truncated { " (truncated)" } else { "" }
    );
    Ok(())
}

fn walk(dir: &Path, lang: Lang, files: &mut Vec<PathBuf>, sites: &mut Vec<PathBuf>) {
    if dir.join("pyvenv.cfg").is_file() {
        if let Ok(entries) = std::fs::read_dir(dir.join("lib")) {
            for e in entries.flatten() {
                let site = e.path().join("site-packages");
                if site.is_dir() {
                    sites.push(site);
                }
            }
        }
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        let name = e.file_name();
        let Ok(kind) = e.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if name != "node_modules" && name != ".git" && name != "__pycache__" {
                walk(&path, lang, files, sites);
            }
        } else if kind.is_file() {
            let p = path.to_string_lossy();
            let ok = match lang {
                Lang::Js => fleetreach_sinks::js::is_source(&p),
                Lang::Python => fleetreach_sinks::python::is_source(&p),
            };
            if ok {
                files.push(path);
            }
        }
    }
}
