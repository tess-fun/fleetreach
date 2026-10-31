//! Print the resolved dependency set of a Maven project from the local repositories:
//! `cargo run -p fleetreach-maven --example mvn_resolve -- <project-dir> [<repo-root>...]`.
//! Used to compare with `mvn dependency:list`.
fn main() {
    let mut args = std::env::args().skip(1);
    let Some(dir) = args.next() else {
        eprintln!("usage: mvn_resolve <project-dir> [<repo-root>...]");
        std::process::exit(2);
    };
    let roots: Vec<std::path::PathBuf> = args.map(Into::into).collect();
    let source = fleetreach_maven::LocalRepositories { roots };
    match fleetreach_maven::resolve(std::path::Path::new(&dir), &source) {
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
