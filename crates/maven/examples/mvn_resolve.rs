//! Print the resolved dependency set of a Maven project from the local repositories:
//! `cargo run -p fleetreach-maven --example mvn_resolve -- <project-dir> [<repo-root>...]`.
//! Used to compare with `mvn dependency:list`. With `MVN_RESOLVE_EACH=1`, each reactor module's
//! own set is printed under a `== group:artifact` line, to compare with Maven's per-module
//! `dependency:tree`.
fn main() {
    let mut args = std::env::args().skip(1);
    let Some(dir) = args.next() else {
        eprintln!("usage: mvn_resolve <project-dir> [<repo-root>...]");
        std::process::exit(2);
    };
    let roots: Vec<std::path::PathBuf> = args.map(Into::into).collect();
    let source = fleetreach_maven::LocalRepositories {
        roots,
        gradle_roots: Vec::new(),
    };
    let dir = std::path::Path::new(&dir);
    if std::env::var_os("MVN_RESOLVE_EACH").is_some() {
        match fleetreach_maven::resolve_each_module(dir, &source) {
            Ok(each) => {
                for (module, packages) in each {
                    println!("== {module}");
                    for p in packages {
                        println!("{}:{}:{}", p.name, p.version, p.scope);
                    }
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        }
        return;
    }
    match fleetreach_maven::resolve(dir, &source) {
        Ok(r) => {
            for p in &r.packages {
                println!("{}:{}:{}", p.name, p.version, p.scope);
            }
            for m in &r.missing {
                eprintln!("missing: {m}");
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}
