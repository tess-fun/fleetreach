use serde::{Deserialize, Serialize};

/// Advisory severity, derived from the advisory's CVSS score (`Unknown` when the
/// advisory carries no score).
///
/// Variants are declared in **ascending** order so the derived `Ord` makes
/// `Critical` the greatest. That gives us two things for free:
/// `iter().max()` over a set of severities yields the worst one (drives
/// `Summary::max_severity`), and a "severity descending" sort is a plain reverse.
///
/// Serializes as lowercase strings (`"critical"`, `"high"`, …) per the JSON
/// schema — independent of declaration order.
///
/// ```
/// use fleetreach_core::Severity;
///
/// assert!(Severity::Critical > Severity::High);
/// assert!(Severity::Low > Severity::Unknown);
///
/// let worst = [Severity::Low, Severity::Critical, Severity::Medium]
///     .into_iter()
///     .max();
/// assert_eq!(worst, Some(Severity::Critical));
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}
