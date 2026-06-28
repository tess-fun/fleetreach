//! PEP 440 version parsing and PEP 503 name normalization — the two pieces of
//! Python-specific version handling the matcher needs.
//!
//! Versions are **not** SemVer: PyPI uses [PEP 440] (epochs `1!2.3`, post-releases
//! `1.0.post1`, dev releases `1.0.dev1`, pre-releases `1.0a1`/`1.0rc1`, and local
//! segments `1.0+abc`), so we parse with the `pep440_rs` crate, whose `Ord` implements
//! the PEP 440 ordering the shared OSV matcher relies on.
//!
//! Names are compared after [PEP 503] normalization (lowercase, runs of `-`/`_`/`.`
//! collapsed to a single `-`), so `Flask`/`flask` and `ruamel.yaml`/`ruamel-yaml` match.
//! A missed normalization would silently fail to find an advisory — a false-clean — so
//! both the lockfile names and the OSV `affected[].package.name` are normalized.
//!
//! [PEP 440]: https://peps.python.org/pep-0440/
//! [PEP 503]: https://peps.python.org/pep-0503/#normalized-names

use std::str::FromStr;

use fleetreach_core::semver::{BuildMetadata, Prerelease, Version as SemverVersion};

pub use pep440_rs::Version;

/// Parse a lockfile-resolved version string into a PEP 440 [`Version`]. A leading/
/// trailing whitespace is tolerated; returns `None` for anything PEP 440 cannot parse
/// (a VCS/URL/local-path pin with no release version — not a registry artifact, so it
/// has no PyPI advisory to match, the same stance as the npm feeder's non-SemVer pins).
pub fn parse_pypi_version(raw: &str) -> Option<Version> {
    Version::from_str(raw.trim()).ok()
}

/// Normalize a project name per PEP 503: lowercase, with every run of `-`, `_`, or `.`
/// collapsed to a single `-`. Used on both sides of the index lookup so spelling
/// variants of the same distribution match.
///
/// # Examples
///
/// ```
/// use fleetreach_pypi::normalize_name;
///
/// assert_eq!(normalize_name("Flask"), "flask");
/// assert_eq!(normalize_name("ruamel.yaml"), "ruamel-yaml");
/// assert_eq!(normalize_name("zope__interface"), "zope-interface");
/// ```
pub fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for ch in name.chars() {
        if matches!(ch, '-' | '_' | '.') {
            // Collapse any run of separators into a single `-`.
            if !prev_sep {
                out.push('-');
                prev_sep = true;
            }
        } else {
            out.extend(ch.to_lowercase());
            prev_sep = false;
        }
    }
    out
}

/// Coerce a PEP 440 [`Version`] into the `semver::Version` the shared finding model
/// stores (`Occurrence::installed` / `patched`). **Detection never uses this** — the
/// matcher in [`crate::db`] compares true PEP 440 versions — so this is only the
/// displayed/remediation form.
///
/// It is faithful for the dominant `X.Y.Z` and calendar (`2023.7.22`) shapes (a direct
/// parse) and best-effort otherwise: the release tuple becomes `major.minor.patch`,
/// pre-releases and dev-releases become a semver pre-release tag (so they correctly order
/// **below** the release — what keeps remediation from treating a vulnerable pre-release
/// as already fixed), and epoch / post / local / extra-release segments become build
/// metadata for display fidelity. The one imperfection is the relative order of a
/// `.devN` versus an `aN`/`bN`/`rcN` of the *same* release (semver sorts the tags
/// lexically), which does not occur among resolved lockfile versions in practice.
pub fn to_semver(v: &Version) -> SemverVersion {
    // Dominant case: the PEP 440 string is already valid SemVer — keep it verbatim.
    if let Ok(sv) = SemverVersion::parse(&v.to_string()) {
        return sv;
    }
    let rel = v.release();
    let mut sv = SemverVersion::new(
        rel.first().copied().unwrap_or(0),
        rel.get(1).copied().unwrap_or(0),
        rel.get(2).copied().unwrap_or(0),
    );

    // Pre/dev → semver pre-release so they order below the release.
    let mut pre = v
        .pre()
        .map(|p| sanitize(&p.to_string()))
        .unwrap_or_default();
    if let Some(dev) = v.dev() {
        pre = if pre.is_empty() {
            format!("dev.{dev}")
        } else {
            format!("{pre}.dev.{dev}")
        };
    }
    if !pre.is_empty() {
        if let Ok(p) = Prerelease::new(&pre) {
            sv.pre = p;
        }
    }

    // Epoch / extra release segments / post / local → build metadata (display only).
    let mut build: Vec<String> = Vec::new();
    if v.epoch() != 0 {
        build.push(format!("e{}", v.epoch()));
    }
    if rel.len() > 3 {
        build.extend(rel[3..].iter().map(u64::to_string));
    }
    if let Some(post) = v.post() {
        build.push(format!("post{post}"));
    }
    if !v.local().is_empty() {
        let local = v
            .local()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(".");
        build.push(sanitize(&local));
    }
    if !build.is_empty() {
        if let Ok(b) = BuildMetadata::new(&build.join(".")) {
            sv.build = b;
        }
    }
    sv
}

/// Reduce a string to SemVer pre-release/build identifier characters (`[0-9A-Za-z-]`),
/// folding any other run to a single `-` and trimming leading/trailing `-`.
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

    #[test]
    fn normalizes_pep503_names() {
        assert_eq!(normalize_name("Flask"), "flask");
        assert_eq!(normalize_name("ruamel.yaml"), "ruamel-yaml");
        assert_eq!(normalize_name("zope.interface"), "zope-interface");
        assert_eq!(normalize_name("django_extensions"), "django-extensions");
        assert_eq!(normalize_name("a---b...c"), "a-b-c");
        assert_eq!(normalize_name("Already-Normal"), "already-normal");
    }

    #[test]
    fn parses_pep440_versions() {
        assert!(parse_pypi_version("1.2.3").is_some());
        assert!(parse_pypi_version("2.0").is_some());
        assert!(parse_pypi_version("1.0a1").is_some());
        assert!(parse_pypi_version("1.0.post1").is_some());
        assert!(parse_pypi_version("1!2.3.4").is_some());
        assert!(parse_pypi_version("1.0+local.1").is_some());
        assert!(parse_pypi_version("  1.2.3  ").is_some());
        assert!(parse_pypi_version("not-a-version").is_none());
    }

    #[test]
    fn pep440_ordering_holds() {
        let pre = parse_pypi_version("1.0a1").unwrap();
        let rel = parse_pypi_version("1.0").unwrap();
        let post = parse_pypi_version("1.0.post1").unwrap();
        let epoch = parse_pypi_version("1!0.1").unwrap();
        assert!(pre < rel, "prerelease orders below release");
        assert!(rel < post, "post-release orders above release");
        assert!(rel < epoch, "epoch dominates");
    }

    fn coerce(s: &str) -> SemverVersion {
        to_semver(&parse_pypi_version(s).unwrap())
    }

    #[test]
    fn to_semver_is_faithful_for_common_shapes() {
        assert_eq!(coerce("2.31.0").to_string(), "2.31.0");
        assert_eq!(coerce("2.0").to_string(), "2.0.0");
        assert_eq!(coerce("2023.7.22").to_string(), "2023.7.22");
        assert_eq!(coerce("1.0a1").to_string(), "1.0.0-a1");
        assert_eq!(coerce("1.0.post1").to_string(), "1.0.0+post1");
        assert_eq!(coerce("1.0+abc").to_string(), "1.0.0+abc");
        assert_eq!(coerce("1.2.3.4").to_string(), "1.2.3+4");
    }

    #[test]
    fn to_semver_orders_prerelease_below_release() {
        // The property remediation relies on: a vulnerable pre-release must not coerce to
        // be >= its own release, or a fix at the release would look already-applied.
        assert!(coerce("1.0a1") < coerce("1.0"));
        assert!(coerce("1.0rc1") < coerce("1.0"));
        assert!(coerce("1.0.dev1") < coerce("1.0"));
        assert!(coerce("2.30.0") < coerce("2.31.0"));
    }
}
