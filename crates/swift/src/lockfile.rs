//! Parse a Swift `Package.resolved` into a flat, deduplicated set of installed packages —
//! the input the OSV matcher scans. Read straight from the lockfile, so it needs **no Swift
//! toolchain and no network**: `Package.resolved` already pins the full dependency graph to
//! exact versions.
//!
//! Swift packages are identified by their **source URL**, not a short name, and the OSV
//! `SwiftURL` ecosystem keys advisories on a normalized form (`github.com/apple/swift-nio`).
//! `Package.resolved` records the full clone URL (`https://github.com/apple/swift-nio.git`),
//! so both sides are run through [`normalize_package_url`] — strip the scheme and any
//! `git@`/`.git`/trailing slash, lowercase — before matching.
//!
//! Two lockfile formats exist: v1 nests pins under `object.pins` with a `repositoryURL`; v2/v3
//! list `pins` at the top level with a `location`. Both are handled. A pin resolved to a
//! branch or bare revision (no `state.version`) has no release to match and is skipped.
//! `Package.resolved` does not record which dependencies are direct, so the direct set is read
//! from the sibling `Package.swift`'s `.package(url:)` declarations when present.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

/// One resolved package from `Package.resolved`: its **normalized URL** identity, exact
/// installed version, and whether the project depends on it **directly** (it appears in
/// `Package.swift`) rather than only transitively.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub direct: bool,
}

#[derive(Deserialize)]
struct Resolved {
    /// v2/v3: pins at the top level.
    #[serde(default)]
    pins: Vec<Pin>,
    /// v1: pins nested under `object`.
    object: Option<ObjectV1>,
}

#[derive(Deserialize)]
struct ObjectV1 {
    #[serde(default)]
    pins: Vec<Pin>,
}

#[derive(Deserialize)]
struct Pin {
    /// v2/v3 clone URL.
    location: Option<String>,
    /// v1 clone URL.
    #[serde(rename = "repositoryURL")]
    repository_url: Option<String>,
    state: Option<PinState>,
}

#[derive(Deserialize)]
struct PinState {
    version: Option<String>,
}

/// Normalize a Swift package source URL to the OSV `SwiftURL` identity form: strip the
/// scheme (`https://`/`http://`/`git://`/`ssh://`) and any leading `git@`, convert an scp-like
/// `host:owner/repo` to `host/owner/repo`, drop a trailing `.git` and `/`, and lowercase
/// (host and path — Git hosts treat owner/repo case-insensitively, so this avoids a
/// case-mismatch false-clean).
pub fn normalize_package_url(url: &str) -> String {
    let mut s = url.trim();
    for scheme in ["https://", "http://", "git://", "ssh://"] {
        if let Some(rest) = s.strip_prefix(scheme) {
            s = rest;
            break;
        }
    }
    s = s.strip_prefix("git@").unwrap_or(s);
    // scp-like `host:owner/repo` → `host/owner/repo` (only the first colon, the host/path sep).
    let replaced = s.replacen(':', "/", 1);
    let trimmed = replaced
        .strip_suffix(".git")
        .unwrap_or(&replaced)
        .trim_end_matches('/');
    trimmed.to_ascii_lowercase()
}

/// Parse `Package.resolved` into a deduplicated, sorted set of installed packages. The
/// optional `package_swift` text marks the `direct` flag; without it every package is reported
/// transitive (a conservative under-claim that never hides a finding).
///
/// # Errors
///
/// Returns the underlying [`serde_json::Error`] if `Package.resolved` is not valid JSON —
/// failing closed.
pub fn installed_packages(
    resolved: &str,
    package_swift: Option<&str>,
) -> Result<Vec<InstalledPackage>, serde_json::Error> {
    let parsed: Resolved = serde_json::from_str(resolved)?;
    let direct = package_swift.map(direct_set).unwrap_or_default();

    let pins = parsed
        .pins
        .into_iter()
        .chain(parsed.object.into_iter().flat_map(|o| o.pins));

    let mut packages = Vec::new();
    for pin in pins {
        let Some(url) = pin.location.or(pin.repository_url) else {
            continue;
        };
        let Some(version) = pin.state.and_then(|s| s.version) else {
            continue; // pinned to a branch/revision, no release to match
        };
        let name = normalize_package_url(&url);
        packages.push(InstalledPackage {
            direct: direct.contains(&name),
            name,
            version,
        });
    }
    Ok(dedupe(packages))
}

/// The direct-dependency identities from a `Package.swift`: the normalized URL of each
/// `.package(url: "…")` declaration. This is a deliberately small textual scan (not a Swift
/// parser) — it pulls the string literal after each `url:` label, which is where SwiftPM
/// dependency URLs live. A `Package.swift` without parseable URLs yields an empty set.
fn direct_set(package_swift: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let mut rest = package_swift;
    while let Some(pos) = rest.find("url:") {
        rest = &rest[pos + "url:".len()..];
        // The next string literal is the dependency URL.
        let Some(open) = rest.find('"') else { break };
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        set.insert(normalize_package_url(&after[..close]));
        rest = &after[close + 1..];
    }
    set
}

/// Collapse duplicate `(name, version)` rows into one, with `direct` winning if any
/// occurrence was direct, and sort for deterministic output.
fn dedupe(packages: Vec<InstalledPackage>) -> Vec<InstalledPackage> {
    let mut by_key: BTreeMap<(String, String), bool> = BTreeMap::new();
    for p in packages {
        let e = by_key.entry((p.name, p.version)).or_insert(false);
        *e = *e || p.direct;
    }
    by_key
        .into_iter()
        .map(|((name, version), direct)| InstalledPackage {
            name,
            version,
            direct,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn rows(pkgs: &[InstalledPackage]) -> Vec<(&str, &str, bool)> {
        pkgs.iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.direct))
            .collect()
    }

    #[test]
    fn normalizes_urls_to_osv_identity() {
        assert_eq!(
            normalize_package_url("https://github.com/apple/swift-nio.git"),
            "github.com/apple/swift-nio"
        );
        assert_eq!(
            normalize_package_url("git@github.com:apple/swift-nio.git"),
            "github.com/apple/swift-nio"
        );
        assert_eq!(
            normalize_package_url("https://github.com/Sparkle-Project/Sparkle/"),
            "github.com/sparkle-project/sparkle"
        );
    }

    const RESOLVED_V2: &str = r#"{
      "pins": [
        {
          "identity": "swift-nio",
          "kind": "remoteSourceControl",
          "location": "https://github.com/apple/swift-nio.git",
          "state": { "revision": "abc", "version": "2.40.0" }
        },
        {
          "identity": "swift-log",
          "location": "https://github.com/apple/swift-log.git",
          "state": { "revision": "def", "version": "1.4.4" }
        },
        {
          "identity": "branchdep",
          "location": "https://github.com/x/y.git",
          "state": { "revision": "deadbeef", "branch": "main" }
        }
      ],
      "version": 2
    }"#;

    const PACKAGE_SWIFT: &str = r#"
        let package = Package(
            name: "App",
            dependencies: [
                .package(url: "https://github.com/apple/swift-nio.git", from: "2.40.0"),
            ]
        )
    "#;

    #[test]
    fn parses_v2_with_direct_from_package_swift() {
        let pkgs = installed_packages(RESOLVED_V2, Some(PACKAGE_SWIFT)).unwrap();
        assert_eq!(
            rows(&pkgs),
            vec![
                ("github.com/apple/swift-log", "1.4.4", false), // transitive
                ("github.com/apple/swift-nio", "2.40.0", true), // direct (in Package.swift)
            ]
        );
        // The branch-pinned dependency has no version → skipped.
        assert!(pkgs.iter().all(|p| p.name != "github.com/x/y"));
    }

    #[test]
    fn parses_v1_object_pins() {
        let v1 = r#"{
          "object": {
            "pins": [
              { "package": "swift-nio", "repositoryURL": "https://github.com/apple/swift-nio.git",
                "state": { "version": "2.40.0", "revision": "abc" } }
            ]
          },
          "version": 1
        }"#;
        let pkgs = installed_packages(v1, None).unwrap();
        assert_eq!(
            rows(&pkgs),
            vec![("github.com/apple/swift-nio", "2.40.0", false)]
        );
    }

    #[test]
    fn malformed_resolved_is_an_error() {
        assert!(installed_packages("not json", None).is_err());
        assert!(installed_packages(r#"{"version":2}"#, None)
            .unwrap()
            .is_empty());
    }
}
