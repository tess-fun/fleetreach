//! `NuGetVersion` parsing and ordering — the one piece of NuGet-specific version handling
//! the matcher needs, and the false-clean-critical one.
//!
//! A NuGet version is SemVer 2.0 with two extensions: the numeric core has up to **four**
//! components (`Major.Minor.Patch.Revision`, e.g. `1.1.1.1`) rather than three, and the
//! prerelease labels compare **case-insensitively** (`1.0.0-Beta` == `1.0.0-beta`). Trailing
//! zero components are insignificant (`1.0` == `1.0.0` == `1.0.0.0`), leading zeros are
//! ignored (`01.0` == `1.0`), and `+build` metadata is dropped for ordering. Everything else
//! is SemVer 2.0 precedence: a release outranks its prereleases, prerelease identifiers split
//! on `.` and compare numerically when both are numeric, a numeric identifier is lower than
//! an alphanumeric one, and a longer identifier list outranks a shorter prefix-equal one.
//!
//! The stock `semver` crate is strict three-component SemVer, so it cannot represent the
//! 4-part core; this is a faithful port of `NuGet.Versioning`'s `VersionComparer.Default`.
//! A 3-part SemVer comparator would mis-order any `1.2.3.4`-style version and silently
//! false-clean.

use fleetreach_core::semver::{BuildMetadata, Prerelease, Version as SemverVersion};

/// One prerelease identifier: a numeric run (compared numerically) or an alphanumeric label
/// (compared case-insensitively, lowercased on parse). SemVer 2.0 precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PreId {
    Num(u64),
    Str(String),
}

/// A parsed NuGet version: the verbatim string (for display / `to_semver`), the numeric core
/// (trailing-zero-trimmed), and the prerelease identifiers. Equality is defined by the
/// ordering (so `1.0` equals `1.0.0`), used by the enumerated-version fallback.
#[derive(Debug, Clone)]
pub struct Version {
    raw: String,
    nums: Vec<u64>,
    pre: Vec<PreId>,
}

impl Version {
    fn compare(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        // Numeric core, zero-padded to the longer length.
        let n = self.nums.len().max(other.nums.len());
        for i in 0..n {
            let a = self.nums.get(i).copied().unwrap_or(0);
            let b = other.nums.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => {}
                ord => return ord,
            }
        }
        // A release (no prerelease) outranks any prerelease of the same core.
        match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            (false, false) => {}
        }
        // SemVer 2.0 prerelease precedence.
        let m = self.pre.len().max(other.pre.len());
        for i in 0..m {
            let ord = match (self.pre.get(i), other.pre.get(i)) {
                // A shorter identifier list has lower precedence when otherwise equal.
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,
                (Some(PreId::Num(x)), Some(PreId::Num(y))) => x.cmp(y),
                (Some(PreId::Str(x)), Some(PreId::Str(y))) => x.cmp(y),
                // Numeric identifiers have lower precedence than alphanumeric ones.
                (Some(PreId::Num(_)), Some(PreId::Str(_))) => Ordering::Less,
                (Some(PreId::Str(_)), Some(PreId::Num(_))) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        Ordering::Equal
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.compare(other) == std::cmp::Ordering::Equal
    }
}
impl Eq for Version {}
impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.compare(other)
    }
}
impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

/// Parse a NuGet version string into a [`Version`].
///
/// Accepts `Major.Minor[.Patch[.Revision]][-prerelease][+metadata]`. The numeric core must
/// be one to four integer components (extra components, or a non-integer core, return
/// `None`). `+build` metadata is dropped for ordering. Returns `None` for anything that is
/// not a NuGet version (e.g. a floating range like `[1.0,)` slipping through), so the caller
/// fails closed.
pub fn parse_nuget_version(raw: &str) -> Option<Version> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Drop build metadata; it never affects ordering.
    let no_build = trimmed.split('+').next().unwrap_or(trimmed);
    // Split the numeric core from the prerelease at the first '-'.
    let (core, pre) = match no_build.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (no_build, None),
    };

    let mut nums: Vec<u64> = Vec::new();
    for part in core.split('.') {
        // A NuGet numeric component is a non-negative integer (leading zeros allowed).
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        nums.push(part.parse::<u64>().ok()?);
    }
    if nums.is_empty() || nums.len() > 4 {
        return None;
    }
    // Trailing-zero components are insignificant for ordering and equality.
    while nums.len() > 1 && matches!(nums.last(), Some(0)) {
        nums.pop();
    }

    let pre_ids = match pre {
        None => Vec::new(),
        Some(p) => {
            let mut ids = Vec::new();
            for id in p.split('.') {
                if id.is_empty() {
                    return None;
                }
                if id.bytes().all(|b| b.is_ascii_digit()) {
                    ids.push(PreId::Num(id.parse::<u64>().ok()?));
                } else {
                    // Prerelease labels compare case-insensitively (NuGet ordinal-ignore-case).
                    ids.push(PreId::Str(id.to_ascii_lowercase()));
                }
            }
            ids
        }
    };

    Some(Version {
        raw: no_build.to_string(),
        nums,
        pre: pre_ids,
    })
}

impl Version {
    /// Whether this is a prerelease (carries any prerelease label).
    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

/// Coerce a [`Version`] into the `semver::Version` the shared finding model stores
/// (`Occurrence::installed` / `patched`). **Detection never uses this** — the matcher
/// compares true NuGet versions — so it is only the displayed/remediation form.
///
/// Faithful for the dominant `X.Y.Z[-pre]` shape (a direct parse). Otherwise best-effort:
/// the first three numeric components become `major.minor.patch`, the prerelease labels a
/// SemVer pre-release, and a fourth numeric component (`Revision`) becomes build metadata for
/// display. The one imperfection — a 4th numeric component not affecting SemVer order — only
/// shows for the rare `1.2.3.4`-style version and never changes a detection verdict.
pub fn to_semver(v: &Version) -> SemverVersion {
    if let Ok(sv) = SemverVersion::parse(&v.raw) {
        return sv;
    }
    let mut sv = SemverVersion::new(
        v.nums.first().copied().unwrap_or(0),
        v.nums.get(1).copied().unwrap_or(0),
        v.nums.get(2).copied().unwrap_or(0),
    );
    let tail: Vec<String> = v
        .pre
        .iter()
        .map(|id| match id {
            PreId::Num(n) => n.to_string(),
            PreId::Str(s) => s.clone(),
        })
        .map(|s| sanitize(&s))
        .filter(|s| !s.is_empty())
        .collect();
    if !tail.is_empty() {
        if let Ok(p) = Prerelease::new(&tail.join(".")) {
            sv.pre = p;
        }
    }
    if let Some(rev) = v.nums.get(3) {
        if let Ok(b) = BuildMetadata::new(&rev.to_string()) {
            sv.build = b;
        }
    }
    sv
}

/// Reduce a string to SemVer identifier characters (`[0-9A-Za-z-]`), folding other runs to a
/// single `-` and trimming leading/trailing `-`.
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn v(s: &str) -> Version {
        parse_nuget_version(s).unwrap()
    }

    #[test]
    fn trailing_zeros_and_four_part_core() {
        assert_eq!(v("1.0"), v("1.0.0"));
        assert_eq!(v("1.0.0"), v("1.0.0.0"));
        assert_eq!(v("01.0"), v("1.0")); // leading zeros ignored
        assert!(v("1.0.0") < v("1.0.0.1")); // revision matters
        assert!(v("1.2.3.4") > v("1.2.3"));
        assert!(v("1.2.3.4") < v("1.2.3.5"));
    }

    #[test]
    fn prerelease_orders_below_release_semver_rules() {
        assert!(v("1.0.0-alpha") < v("1.0.0"));
        assert!(v("1.0.0-alpha") < v("1.0.0-alpha.1"));
        assert!(v("1.0.0-alpha.1") < v("1.0.0-alpha.beta"));
        assert!(v("1.0.0-alpha.beta") < v("1.0.0-beta"));
        assert!(v("1.0.0-beta.2") < v("1.0.0-beta.11")); // numeric, not lexical
        assert!(v("1.0.0-rc.1") < v("1.0.0"));
    }

    #[test]
    fn prerelease_is_case_insensitive() {
        assert_eq!(v("1.0.0-Beta"), v("1.0.0-beta"));
        assert_eq!(v("1.0.0-RC.1"), v("1.0.0-rc.1"));
        assert_eq!(v("8.0.0-RC.2.23480.2"), v("8.0.0-rc.2.23480.2"));
    }

    #[test]
    fn build_metadata_is_ignored() {
        assert_eq!(v("1.2.3+abc"), v("1.2.3"));
        assert_eq!(v("1.2.3-rc+abc"), v("1.2.3-rc"));
    }

    #[test]
    fn rejects_non_versions() {
        assert!(parse_nuget_version("").is_none());
        assert!(parse_nuget_version("[1.0,)").is_none());
        assert!(parse_nuget_version("1.2.3.4.5").is_none()); // >4 components
        assert!(parse_nuget_version("1.x").is_none());
    }

    #[test]
    fn to_semver_common_and_fourpart() {
        assert_eq!(to_semver(&v("1.2.3")).to_string(), "1.2.3");
        assert_eq!(to_semver(&v("1.0")).to_string(), "1.0.0");
        assert_eq!(to_semver(&v("1.2.3-rc.1")).to_string(), "1.2.3-rc.1");
        assert_eq!(to_semver(&v("1.2.3.4")).to_string(), "1.2.3+4");
        // Prereleases must stay below the release in the coerced form too.
        assert!(to_semver(&v("1.0.0-rc")) < to_semver(&v("1.0.0")));
    }
}
