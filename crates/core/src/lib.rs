//! Domain types for fleetreach: the stable, I/O-free contract every other crate maps onto.
//!
//! `fleetreach-core` defines the model a fleet scan produces — `FleetReport`,
//! `VulnFinding`, `Occurrence`, `Severity` — and their serde shape. It
//! performs **no I/O** and exposes **no `rustsec` types**, so downstream
//! enrichment (EPSS, reachability, SARIF) lands as additive fields without
//! breaking `schema_version: 1` consumers. `semver` values stay typed and
//! serialize to strings only at the JSON boundary.
//!
//! # Usage
//!
//! ```sh
//! cargo add fleetreach-core
//! ```
//!
//! The per-occurrence verdict — is the *installed* version still vulnerable? — is
//! computed against the advisory's patched range, fail-closed:
//!
//! ```
//! use fleetreach_core::semver::{Version, VersionReq};
//! use fleetreach_core::{DependencyKind, Occurrence, RepoId, Severity};
//!
//! // Severity is ordered worst-last, so `iter().max()` yields the fleet maximum.
//! assert!(Severity::Critical > Severity::High);
//!
//! let occurrence = Occurrence::InRepo {
//!     repo: RepoId("app".into()),
//!     package: "jiff".into(),
//!     installed: Version::new(0, 1, 1),
//!     patched: vec![VersionReq::parse(">=0.1.2").unwrap()],
//!     dependency_kind: DependencyKind::Transitive,
//!     dependency_path: vec![],
//!     active: None,
//!     source: Default::default(),
//! };
//! assert!(occurrence.is_vulnerable()); // installed is below the patched range
//! ```
//!
//! # Minimum supported Rust version
//!
//! 1.89. An MSRV increase is treated as a minor-version bump.

pub mod depgraph;
mod finding;
pub mod osv;
mod outcome;
mod remediation;
mod report;
mod severity;

pub use depgraph::DepGraph;
pub use finding::{
    DepSource, DependencyKind, Ecosystem, Exploitability, Occurrence, ReachVerdict, Reachability,
    RepoId, VulnFinding, WarnFinding, WarnKind,
};
pub use outcome::{RepoOutcome, ScanStatus};
pub use remediation::{remediations, Action, ReachTier, RemediationItem};
pub use report::{max_severity_of, FleetReport, Provenance, Summary, SCHEMA_VERSION};
pub use severity::Severity;

/// Re-exported so every downstream crate links the *same* `semver`, matching
/// the version `rustsec` pulls in (§12, avoid version skew).
pub use semver;
