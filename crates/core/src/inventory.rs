//! The package inventory of a repo: every resolved package each source declares, whether or
//! not it is vulnerable. The scan only keeps matches; SBOM output needs the whole set.
//!
//! A repo has one [`SourceInventory`] per dependency source read (a `Cargo.lock`, a
//! `package-lock.json`, a set of requirements files, ...), each with its coverage level, so an
//! SBOM can say which parts are complete and which declare direct dependencies only.

use crate::{Coverage, DepGraph, DepSource, Ecosystem, RepoId};

/// The root node of every inventory graph: the scanned project itself.
pub const ROOT: &str = "(root)";

/// One resolved package.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Package {
    pub name: String,
    pub version: String,
    /// Declared by the project itself rather than pulled in by another package.
    pub direct: bool,
    /// Installed only for development or tests.
    pub dev: bool,
    /// Where the package comes from, when the lockfile says (crates.io, git, a registry).
    pub source: DepSource,
    /// The package's license: a canonical SPDX expression, or the string as found when it
    /// is not one. `None` when no source knew it.
    pub license: Option<String>,
    /// Where the license came from (`package-lock.json`, `cargo registry`, ...).
    pub license_source: Option<String>,
    /// Hashes of the file the registry serves, as the lockfile records them.
    pub checksums: Vec<Checksum>,
}

/// The hash of a package's published file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct Checksum {
    /// `SHA-1`, `SHA-256`, `SHA-384` or `SHA-512`.
    pub algorithm: &'static str,
    /// Lowercase hex.
    pub hex: String,
}

impl Checksum {
    /// `None` unless `hex` is hexadecimal of the algorithm's length, so a truncated or
    /// placeholder value never reaches a BOM.
    #[must_use]
    pub fn new(algorithm: &'static str, hex: &str) -> Option<Self> {
        let length = match algorithm {
            "SHA-1" => 40,
            "SHA-256" => 64,
            "SHA-384" => 96,
            "SHA-512" => 128,
            _ => return None,
        };
        (hex.len() == length && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| Checksum {
            algorithm,
            hex: hex.to_ascii_lowercase(),
        })
    }
}

impl Package {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        direct: bool,
        dev: bool,
    ) -> Self {
        Package {
            name: name.into(),
            version: version.into(),
            direct,
            dev,
            source: DepSource::default(),
            license: None,
            license_source: None,
            checksums: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_source(mut self, source: DepSource) -> Self {
        self.source = source;
        self
    }
}

/// The packages one source declares.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceInventory {
    pub ecosystem: Ecosystem,
    /// The source file, relative to the repo root.
    pub source: String,
    pub coverage: Coverage,
    /// Why coverage is below full, one line per gap.
    pub coverage_reasons: Vec<String>,
    pub packages: Vec<Package>,
    /// "Requires" edges between package names; [`ROOT`] is the project.
    pub edges: Vec<(String, String)>,
}

impl SourceInventory {
    #[must_use]
    pub fn new(ecosystem: Ecosystem, source: impl Into<String>, packages: Vec<Package>) -> Self {
        SourceInventory {
            ecosystem,
            source: source.into(),
            coverage: Coverage::Full,
            coverage_reasons: Vec::new(),
            packages,
            edges: Vec::new(),
        }
    }

    /// Take the edges of a feeder's dependency graph, its root renamed to [`ROOT`].
    #[must_use]
    pub fn with_graph(mut self, graph: &DepGraph) -> Self {
        let root = graph.root();
        self.edges = graph
            .edges()
            .map(|(from, to)| {
                let from = if from == root { ROOT } else { from };
                (from.to_string(), to.to_string())
            })
            .collect();
        self
    }

    /// Record a coverage gap; the level is the worst one recorded.
    #[must_use]
    pub fn with_gap(mut self, level: Coverage, reason: impl Into<String>) -> Self {
        self.coverage = self.coverage.max(level);
        self.coverage_reasons.push(reason.into());
        self
    }
}

/// Everything one repo declares.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoInventory {
    pub repo: RepoId,
    /// The remote the repo was cloned from (fleet sources), when known.
    pub url: Option<String>,
    /// The commit read, when known.
    pub commit: Option<String>,
    pub sources: Vec<SourceInventory>,
    /// Sources that exist but could not be read: the inventory is incomplete.
    pub errors: Vec<String>,
}

impl RepoInventory {
    #[must_use]
    pub fn new(repo: RepoId) -> Self {
        RepoInventory {
            repo,
            url: None,
            commit: None,
            sources: Vec::new(),
            errors: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn checksums_must_be_hex_of_the_right_length() {
        let hex = "A".repeat(64);
        assert_eq!(Checksum::new("SHA-256", &hex).unwrap().hex, "a".repeat(64));
        assert!(Checksum::new("SHA-512", &hex).is_none());
        assert!(Checksum::new("MD5", &hex).is_none());
        assert!(Checksum::new("SHA-1", &"g".repeat(40)).is_none());
    }

    #[test]
    fn graph_root_becomes_the_shared_root_and_gaps_keep_the_worst_level() {
        let mut graph = DepGraph::new("my-app");
        graph.add_edges("my-app", ["a"]);
        graph.add_edges("a", ["b"]);
        let inv = SourceInventory::new(Ecosystem::Npm, "package-lock.json", Vec::new())
            .with_graph(&graph)
            .with_gap(Coverage::DirectOnly, "x")
            .with_gap(Coverage::Partial, "y");
        assert_eq!(
            inv.edges,
            vec![
                ("a".to_string(), "b".to_string()),
                (ROOT.to_string(), "a".to_string())
            ]
        );
        assert_eq!(inv.coverage, Coverage::Partial);
        assert_eq!(inv.coverage_reasons, vec!["x", "y"]);
    }
}
