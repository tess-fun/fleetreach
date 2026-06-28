//! Julia `VersionNumber` parsing and ordering — the one piece of Julia-specific version
//! handling the matcher needs, and the false-clean-critical one.
//!
//! Julia versions look like SemVer (`major.minor.patch[-prerelease][+build]`) but, unlike
//! strict SemVer, **build metadata is significant for ordering**: Julia's binary `_jll`
//! packages carry a build counter (`8.15.0+0`, `8.15.0+1`) and the OSV advisory ranges use
//! it (59% of Julia bounds carry a `+build`), so `8.15.0+0` and `8.15.0+1` must not compare
//! equal. A stock SemVer comparator ignores build metadata and would silently false-clean a
//! JLL package whose advisory window is keyed on the build counter.
//!
//! This is a faithful port of Julia's `VersionNumber` `isless`: compare `major.minor.patch`
//! numerically; then the prerelease (an **empty** prerelease — a release — ranks **above** a
//! non-empty one); then the build (an **empty** build ranks **below** a non-empty one — the
//! opposite direction). Within a prerelease or build, identifiers split on `.`, a numeric
//! identifier is lower than an alphanumeric one, numerics compare numerically, and a longer
//! identifier list outranks a shorter prefix-equal one.

use fleetreach_core::semver::{BuildMetadata, Prerelease, Version as SemverVersion};

/// One prerelease/build identifier: a numeric run or an alphanumeric label.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Id {
    Num(u64),
    Str(String),
}

/// A parsed Julia `VersionNumber`: the verbatim string (for display / `to_semver`), the
/// `major.minor.patch` core, and the prerelease and build identifier lists. Equality is
/// defined by the ordering.
#[derive(Debug, Clone)]
pub struct Version {
    raw: String,
    nums: [u64; 3],
    pre: Vec<Id>,
    build: Vec<Id>,
}

/// Compare two identifier lists by Julia's `ident_cmp`: pairwise, a numeric identifier is
/// lower than an alphanumeric one, numerics compare numerically, strings lexically, and when
/// one list is a prefix of the other the shorter is lower.
fn ident_cmp(a: &[Id], b: &[Id]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    for (x, y) in a.iter().zip(b.iter()) {
        let ord = match (x, y) {
            (Id::Num(p), Id::Num(q)) => p.cmp(q),
            (Id::Num(_), Id::Str(_)) => Ordering::Less,
            (Id::Str(_), Id::Num(_)) => Ordering::Greater,
            (Id::Str(p), Id::Str(q)) => p.cmp(q),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

impl Version {
    fn compare(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        for i in 0..3 {
            match self.nums[i].cmp(&other.nums[i]) {
                Ordering::Equal => {}
                ord => return ord,
            }
        }
        // Prerelease: an empty prerelease (a release) ranks ABOVE a non-empty one.
        match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            (false, false) => {
                let ord = ident_cmp(&self.pre, &other.pre);
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (true, true) => {}
        }
        // Build: an empty build ranks BELOW a non-empty one (the opposite of prerelease).
        match (self.build.is_empty(), other.build.is_empty()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => ident_cmp(&self.build, &other.build),
            (true, true) => Ordering::Equal,
        }
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

/// Parse a Julia version string into a [`Version`].
///
/// Accepts `major[.minor[.patch]][-prerelease][+build]` (missing numeric components default
/// to 0). Returns `None` if a numeric component is not an integer or overflows, so the caller
/// fails closed. The OSV `"0"` lower bound parses to `0.0.0`.
pub fn parse_julia_version(raw: &str) -> Option<Version> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    // Split off build (`+`), then prerelease (`-`), then the numeric core.
    let (main, build_str) = match trimmed.split_once('+') {
        Some((m, b)) => (m, Some(b)),
        None => (trimmed, None),
    };
    let (core, pre_str) = match main.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (main, None),
    };

    let mut nums = [0u64; 3];
    for (i, part) in core.split('.').enumerate() {
        if i >= 3 {
            return None; // more than major.minor.patch
        }
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        nums[i] = part.parse::<u64>().ok()?;
    }

    Some(Version {
        raw: trimmed.to_string(),
        nums,
        pre: parse_ids(pre_str)?,
        build: parse_ids(build_str)?,
    })
}

/// Parse a dot-separated identifier list (a prerelease or build tail), or an empty list when
/// absent. A numeric identifier becomes [`Id::Num`], anything else [`Id::Str`] (verbatim;
/// Julia identifiers are case-sensitive).
fn parse_ids(s: Option<&str>) -> Option<Vec<Id>> {
    let Some(s) = s else { return Some(Vec::new()) };
    let mut ids = Vec::new();
    for part in s.split('.') {
        if part.is_empty() {
            return None;
        }
        if part.bytes().all(|b| b.is_ascii_digit()) {
            ids.push(Id::Num(part.parse::<u64>().ok()?));
        } else {
            ids.push(Id::Str(part.to_string()));
        }
    }
    Some(ids)
}

impl Version {
    /// Whether this is a prerelease (carries any prerelease identifier).
    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

/// Coerce a [`Version`] into the `semver::Version` the shared finding model stores.
/// **Detection never uses this** — the matcher compares true Julia versions — so it is only
/// the displayed/remediation form. Faithful for the common `X.Y.Z[-pre]` shape (a direct
/// parse). The build counter (`+N`) is kept as SemVer build metadata for display; SemVer
/// ignores it for ordering, the one documented imperfection, which never changes a detection
/// verdict (detection uses the true comparator).
pub fn to_semver(v: &Version) -> SemverVersion {
    if let Ok(sv) = SemverVersion::parse(&v.raw) {
        return sv;
    }
    let mut sv = SemverVersion::new(v.nums[0], v.nums[1], v.nums[2]);
    let pre: Vec<String> = v.pre.iter().map(id_str).filter(|s| !s.is_empty()).collect();
    if !pre.is_empty() {
        if let Ok(p) = Prerelease::new(&pre.join(".")) {
            sv.pre = p;
        }
    }
    let build: Vec<String> = v
        .build
        .iter()
        .map(id_str)
        .filter(|s| !s.is_empty())
        .collect();
    if !build.is_empty() {
        if let Ok(b) = BuildMetadata::new(&build.join(".")) {
            sv.build = b;
        }
    }
    sv
}

fn id_str(id: &Id) -> String {
    match id {
        Id::Num(n) => sanitize(&n.to_string()),
        Id::Str(s) => sanitize(s),
    }
}

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
        parse_julia_version(s).unwrap()
    }

    #[test]
    fn semver_core_ordering() {
        assert!(v("1.0.0") < v("1.0.1"));
        assert!(v("1.2.0") < v("2.0.0"));
        assert_eq!(v("1.2"), v("1.2.0"));
        assert_eq!(v("1"), v("1.0.0"));
    }

    #[test]
    fn prerelease_ranks_below_release() {
        assert!(v("1.0.0-alpha") < v("1.0.0"));
        assert!(v("1.0.0-alpha") < v("1.0.0-alpha.1"));
        assert!(v("1.0.0-alpha.1") < v("1.0.0-beta"));
        assert!(v("1.0.0-2") < v("1.0.0-11")); // numeric identifiers numeric, not lexical
    }

    #[test]
    fn build_metadata_is_significant_and_ranks_above_no_build() {
        // The Julia/JLL-specific rule a SemVer comparator gets wrong.
        assert!(v("8.15.0") < v("8.15.0+0"));
        assert!(v("8.15.0+0") < v("8.15.0+1"));
        assert!(v("8.15.0+1") < v("8.15.0+2"));
        assert_ne!(v("8.15.0+0"), v("8.15.0+1"));
        // A different patch still dominates the build counter.
        assert!(v("8.15.0+9") < v("8.16.0+0"));
    }

    #[test]
    fn rejects_non_versions() {
        assert!(parse_julia_version("").is_none());
        assert!(parse_julia_version("dev").is_none());
        assert!(parse_julia_version("1.2.3.4").is_none());
    }

    #[test]
    fn to_semver_common_shapes() {
        assert_eq!(to_semver(&v("1.2.3")).to_string(), "1.2.3");
        assert_eq!(to_semver(&v("1.2")).to_string(), "1.2.0");
        assert_eq!(to_semver(&v("8.15.0+0")).to_string(), "8.15.0+0");
        assert!(to_semver(&v("1.0.0-rc")) < to_semver(&v("1.0.0")));
    }
}
