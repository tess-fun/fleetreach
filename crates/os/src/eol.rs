//! End-of-life status of an image's distribution release, from a bundled snapshot of
//! endoflife.date (`data/eol.tsv`, refreshed at release time by `scripts/update-eol.py`), so a
//! scan needs no network for it.
//!
//! A release past its end of life gets no more security fixes from its vendor (or only
//! through paid extended support), and so fewer and fewer advisories: matching it finds less
//! than is there, which looks like a healthier image. The scan reports it as a warning.

use fleetreach_core::{DependencyKind, Occurrence, RepoId, WarnFinding, WarnKind};

use crate::distro::OsRelease;

const SNAPSHOT: &str = include_str!("../data/eol.tsv");

/// A release's support dates, as endoflife.date gives them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// The endoflife.date product (`debian`, `rhel`, `alpine-linux`).
    pub product: String,
    /// The distribution's name (`Debian`, `Red Hat Enterprise Linux`).
    pub name: &'static str,
    /// The release within it (`10`, `9`, `3.18`).
    pub cycle: String,
    /// The end of the vendor's standard security support: an ISO date, or `None` when it has ended on a date
    /// the data does not give.
    pub eol: Option<String>,
    /// The end of paid extended support (Debian ELTS, Ubuntu Pro, Red Hat ELS, SUSE LTSS).
    pub extended: Option<String>,
}

/// The endoflife.date product an os-release names, and the distribution's name, if the
/// snapshot covers it.
fn product(os: &OsRelease) -> Option<(&'static str, &'static str)> {
    let stream = os
        .pretty_name
        .as_deref()
        .is_some_and(|n| n.contains("Stream"));
    Some(match os.id.as_str() {
        "almalinux" => ("almalinux", "AlmaLinux"),
        "alpine" => ("alpine-linux", "Alpine Linux"),
        "amzn" => ("amazon-linux", "Amazon Linux"),
        // CentOS Linux ended with 8; 9 and later are only CentOS Stream.
        "centos" if stream || major(os).is_some_and(|m| m >= 9) => {
            ("centos-stream", "CentOS Stream")
        }
        "centos" => ("centos", "CentOS Linux"),
        "debian" => ("debian", "Debian"),
        "fedora" => ("fedora", "Fedora"),
        "mageia" => ("mageia", "Mageia"),
        "ol" => ("oracle-linux", "Oracle Linux"),
        "opensuse-leap" => ("opensuse", "openSUSE Leap"),
        "photon" => ("photon", "Photon OS"),
        "rhel" => ("rhel", "Red Hat Enterprise Linux"),
        "rocky" => ("rocky-linux", "Rocky Linux"),
        "sles" => ("sles", "SUSE Linux Enterprise Server"),
        "sle-micro" | "sl-micro" => ("suse-linux-micro", "SUSE Linux Micro"),
        "ubuntu" => ("ubuntu", "Ubuntu"),
        _ => return None,
    })
}

fn major(os: &OsRelease) -> Option<u32> {
    os.version_id.as_deref()?.split('.').next()?.parse().ok()
}

/// The snapshot's entry for the release an os-release names: the exact `VERSION_ID`
/// (`22.04`, `2023`, `15.6`), else its major and minor (`3.20.10` is Alpine `3.20`), else
/// its major (`9.2` is RHEL `9`). `None` for a distribution or release the snapshot does
/// not list (a rolling release, or one newer than the snapshot).
pub fn lookup(os: &OsRelease) -> Option<Release> {
    let (product, name) = product(os)?;
    let version = os.version_id.as_deref()?;
    let mut parts = version.split('.');
    let major = parts.next()?;
    let mut candidates = vec![version.to_string()];
    candidates.extend(parts.next().map(|minor| format!("{major}.{minor}")));
    candidates.push(major.to_string());
    let rows: Vec<Vec<&str>> = SNAPSHOT
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split('\t').collect::<Vec<_>>())
        .filter(|r| r.len() == 4 && r[0] == product)
        .collect();
    candidates.iter().find_map(|cycle| {
        rows.iter().find(|r| r[1] == cycle).map(|r| Release {
            product: product.to_string(),
            name,
            cycle: cycle.clone(),
            eol: (r[2] != "ended").then(|| r[2].to_string()),
            extended: (r[3] != "-").then(|| r[3].to_string()),
        })
    })
}

/// The snapshot's date (`2026-11-03`), so a report can say how current the data is.
pub fn snapshot_date() -> &'static str {
    SNAPSHOT
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("# endoflife.date snapshot "))
        .and_then(|l| l.split(',').next())
        .unwrap_or("unknown")
}

impl Release {
    /// True when the release's free security support ended before `today` (an ISO date).
    pub fn ended(&self, today: &str) -> bool {
        self.eol.as_deref().is_none_or(|eol| eol < today)
    }
}

/// The warning for an image whose release's free security support ended before `today` (an
/// ISO date), correlated across the fleet by `EOL-<product>-<cycle>`.
pub fn warning(os: &OsRelease, repo: &RepoId, today: &str) -> Option<WarnFinding> {
    let release = lookup(os)?;
    if !release.ended(today) {
        return None;
    }
    let ended = release.eol.as_deref().map_or_else(
        || "reached the end of its standard support".to_string(),
        |d| format!("reached the end of its standard support on {d}"),
    );
    // Matching may still take the extended stream's advisories (SUSE LTSS, Ubuntu Pro), so
    // the warning says what the vendor offers, not what this scan found.
    let after = match release.extended.as_deref().filter(|d| *d >= today) {
        Some(d) => format!("security fixes now come only with paid extended support, until {d}"),
        None => "the vendor publishes no more security fixes for it".to_string(),
    };
    Some(WarnFinding {
        kind: WarnKind::Unmaintained,
        advisory_id: Some(format!("EOL-{}-{}", release.product, release.cycle)),
        title: format!(
            "{} {} {ended} (endoflife.date): {after}",
            release.name, release.cycle
        ),
        occurrences: vec![Occurrence::InRepo {
            repo: repo.clone(),
            package: release.product.clone(),
            installed: crate::scan::to_semver(&release.cycle),
            patched: Vec::new(),
            dependency_kind: DependencyKind::Direct,
            dependency_path: os.pretty_name.iter().cloned().collect(),
            active: None,
            source: Default::default(),
            scope: Default::default(),
            layer: None,
        }],
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::distro::parse_os_release;

    fn os(id: &str, version: &str, pretty: &str) -> OsRelease {
        parse_os_release(&format!(
            "ID={id}\nVERSION_ID=\"{version}\"\nPRETTY_NAME=\"{pretty}\"\n"
        ))
    }

    #[test]
    fn os_release_maps_to_the_snapshot_release() {
        let cycle = |id, v, p| lookup(&os(id, v, p)).map(|r| (r.product, r.cycle));
        let want = |p: &str, c: &str| Some((p.to_string(), c.to_string()));
        assert_eq!(cycle("debian", "10", "Debian 10"), want("debian", "10"));
        assert_eq!(cycle("ubuntu", "20.04", "Ubuntu"), want("ubuntu", "20.04"));
        assert_eq!(
            cycle("alpine", "3.18.4", "Alpine"),
            want("alpine-linux", "3.18")
        );
        assert_eq!(cycle("rhel", "9.2", "RHEL"), want("rhel", "9"));
        assert_eq!(
            cycle("amzn", "2", "Amazon Linux 2"),
            want("amazon-linux", "2")
        );
        assert_eq!(
            cycle("opensuse-leap", "15.5", "Leap"),
            want("opensuse", "15.5")
        );
        assert_eq!(cycle("centos", "7", "CentOS Linux 7"), want("centos", "7"));
        assert_eq!(
            cycle("centos", "8", "CentOS Stream 8"),
            want("centos-stream", "8")
        );
        assert_eq!(
            cycle("centos", "9", "CentOS Stream 9"),
            want("centos-stream", "9")
        );
        assert_eq!(cycle("photon", "4.0", "Photon"), want("photon", "4.0"));
        // Rolling, unknown, or newer than the snapshot: no entry, no warning.
        assert_eq!(cycle("opensuse-tumbleweed", "20261101", "Tumbleweed"), None);
        assert_eq!(cycle("wolfi", "20230201", "Wolfi"), None);
        assert_eq!(cycle("debian", "99", "Debian 99"), None);
    }

    #[test]
    fn end_of_life_is_strictly_before_today() {
        let debian10 = lookup(&os("debian", "10", "Debian 10")).unwrap();
        assert_eq!(debian10.eol.as_deref(), Some("2024-06-30"));
        assert_eq!(debian10.extended.as_deref(), Some("2029-06-30"));
        assert!(debian10.ended("2024-07-01"));
        assert!(!debian10.ended("2024-06-30"));
        assert!(!debian10.ended("2020-01-01"));
        assert!(snapshot_date().starts_with("20"));
    }

    #[test]
    fn a_release_past_its_end_of_life_is_a_warning() {
        let repo = RepoId("img".into());
        let debian10 = os("debian", "10", "Debian GNU/Linux 10 (buster)");
        let w = warning(&debian10, &repo, "2026-11-03").unwrap();
        assert_eq!(w.kind, WarnKind::Unmaintained);
        assert_eq!(w.advisory_id.as_deref(), Some("EOL-debian-10"));
        assert!(
            w.title
                == "Debian 10 reached the end of its standard support on 2024-06-30 \
                    (endoflife.date): security fixes now come only with paid extended support, \
                    until 2029-06-30",
            "{}",
            w.title
        );
        // Before the date, and for a release with no entry: nothing.
        assert!(warning(&debian10, &repo, "2024-06-30").is_none());
        assert!(warning(&os("wolfi", "20230201", "Wolfi"), &repo, "2026-11-03").is_none());
        // Once extended support has ended too, nothing is left.
        let w = warning(&debian10, &repo, "2030-01-01").unwrap();
        assert!(
            w.title
                .ends_with("the vendor publishes no more security fixes for it"),
            "{}",
            w.title
        );
    }
}
