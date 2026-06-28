//! Feature resolution: `cargo tree` distinguishes a built dependency from an
//! off-by-default optional one (the phantom Cargo.lock-only entry). Offline —
//! the fixture project uses only path dependencies.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use fleetreach_cli::resolve::{built_package_set, host_triple};

#[test]
fn built_set_excludes_off_by_default_optional_deps() {
    let host = host_triple().expect("host triple from rustc -vV");
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/resolve-project");

    let built = built_package_set(&project, &host).expect("cargo tree on fixture project");
    let names: BTreeSet<&str> = built.iter().map(|(n, _)| n.as_str()).collect();

    assert!(names.contains("resolve-app"), "the root crate: {names:?}");
    assert!(
        names.contains("realdep"),
        "a normal dep is built: {names:?}"
    );
    assert!(
        !names.contains("optdep"),
        "an off-by-default optional dep is a phantom, not built: {names:?}"
    );
}
