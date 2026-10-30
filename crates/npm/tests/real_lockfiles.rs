//! Robustness check over real lockfiles (spec 02): every listed lockfile must parse, and the
//! parsed `(name, version)` count is printed for comparison with an independent count. Point
//! `FR_JS_LOCKS` at a file listing lockfile paths, one per line.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[test]
#[ignore = "needs FR_JS_LOCKS pointing at real lockfiles"]
fn real_lockfiles_parse() {
    let list = std::env::var("FR_JS_LOCKS").expect("FR_JS_LOCKS");
    for line in std::fs::read_to_string(list).unwrap().lines() {
        let path = std::path::Path::new(line.trim());
        let dir = path.parent().unwrap();
        let (installed, _) = fleetreach_npm::read_lockfile(dir)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        println!("{}\t{}", installed.len(), path.display());
        if std::env::var_os("FR_JS_DUMP").is_some() {
            for p in &installed {
                println!("PKG\t{}\t{}@{}", path.display(), p.name, p.version);
            }
        }
    }
}
