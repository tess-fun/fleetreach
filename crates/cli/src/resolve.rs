//! Feature-aware "is it actually built?" resolution via `cargo tree`.
//!
//! `Cargo.lock` records optional dependencies even when their feature is off, so
//! a lockfile-only scan can flag a package (e.g. `proc-macro-error2` via `jiff`'s
//! off-by-default `defmt` feature) that is never compiled. `cargo metadata`'s
//! resolve graph is the *maximal* graph and includes those phantoms — but
//! `cargo tree` **is** feature-aware, so we use it as the oracle for the host's
//! default build set.
//!
//! This is opt-in (`--resolve-features`): it shells out to `cargo` and needs the
//! repo's buildable source, so it is never the default. Best-effort — any
//! failure leaves findings unannotated rather than aborting the scan.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use fleetreach_core::semver::Version;

/// The host target triple (e.g. `x86_64-apple-darwin`), parsed from `rustc -vV`.
pub fn host_triple() -> Option<String> {
    let output = Command::new("rustc").arg("-vV").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(|triple| triple.trim().to_string())
}

/// The `(name, version)` set actually compiled for the host's default build of
/// the project at `project_dir`, per `cargo tree` (normal + build edges, default
/// features). `Err` (cargo missing, not a project, stale lock, …) tells the
/// caller to skip annotation rather than fail the scan.
pub fn built_package_set(
    project_dir: &Path,
    host_triple: &str,
) -> Result<BTreeSet<(String, Version)>, String> {
    // `cargo tree` runs cargo inside the (untrusted) scanned repo, where its
    // `.cargo/config.toml` is honored. `--offline` keeps it from reaching the
    // network or resolving git deps, and `CARGO_NET_GIT_FETCH_WITH_CLI=false`
    // stops a hostile config from spawning the operator's `git` (with its
    // credential helpers). The feature is best-effort, so an offline miss simply
    // leaves findings unannotated rather than reaching out.
    let output = Command::new("cargo")
        .current_dir(project_dir)
        .env("CARGO_NET_GIT_FETCH_WITH_CLI", "false")
        .args([
            "tree",
            // What a default `cargo build` compiles for this target; excludes dev.
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--target",
            host_triple,
            "--format",
            "{p}",
            "--locked",
            "--offline",
        ])
        .output()
        .map_err(|e| format!("running cargo tree: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo tree failed in {}: {}",
            project_dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_package_specs(&text))
}

/// Parse `cargo tree --format "{p}"` output: each line is `name vX.Y.Z[ (source)]`.
fn parse_package_specs(text: &str) -> BTreeSet<(String, Version)> {
    let mut set = BTreeSet::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        if let Ok(version) = Version::parse(version.trim_start_matches('v')) {
            set.insert((name.to_string(), version));
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cargo_tree_package_specs() {
        let text = "fleetreach-cli v0.1.0 (/path)\njiff v0.2.0\nnot a version line\n";
        let set = parse_package_specs(text);
        assert!(set.contains(&("jiff".to_string(), Version::new(0, 2, 0))));
        assert!(set.contains(&("fleetreach-cli".to_string(), Version::new(0, 1, 0))));
        assert_eq!(set.len(), 2);
    }
}
