//! What CentOS Linux shipped, for matching its images against Red Hat's advisories.
//!
//! CentOS Linux 6, 7 and 8 rebuilt Red Hat Enterprise Linux from the same sources and
//! published no advisories of their own, so an image is matched against Red Hat's records for
//! the release it rebuilds. Two things differ from RHEL, and this module answers both:
//!
//! - A fix Red Hat released after CentOS ended (or that CentOS never rebuilt) is not in
//!   CentOS's repositories. A bundled snapshot of each release's final repositories
//!   (`data/centos.tsv`, from vault.centos.org by `scripts/update-centos.py`; they no longer
//!   change) gives the highest build CentOS shipped of each binary package, per module stream.
//!   A fix above it is reported as fixed only in another line.
//! - CentOS rebranded some builds: Red Hat's `4.2.5-83.el7_9.2` is CentOS's
//!   `4.2.5-83.el7.centos.2`, which rpm orders below it. [`rebrand`] rewrites a Red Hat
//!   version into CentOS's form so the two compare as the same build.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::rpmver::RpmVersion;

const SNAPSHOT: &str = include_str!("../data/centos.tsv");

/// Highest build per (release, package), each with its module stream (`-` for none).
type Builds = BTreeMap<(&'static str, &'static str), Vec<(&'static str, RpmVersion)>>;

fn builds() -> &'static Builds {
    static BUILDS: OnceLock<Builds> = OnceLock::new();
    BUILDS.get_or_init(|| {
        let mut out = Builds::new();
        for line in SNAPSHOT.lines().filter(|l| !l.starts_with('#')) {
            let mut cols = line.split('\t');
            let (Some(release), Some(name), Some(stream), Some(build)) =
                (cols.next(), cols.next(), cols.next(), cols.next())
            else {
                continue;
            };
            if let Some(v) = RpmVersion::parse(build) {
                out.entry((release, name)).or_default().push((stream, v));
            }
        }
        out
    })
}

/// Red Hat's form of a release (`83.el7_9.2`) in CentOS's rebranded form (`83.el7.centos.2`):
/// the `.el<N>_<M>` z-stream tag becomes `.el<N>.centos`. `None` when there is no such tag.
pub fn rebrand(version: &str) -> Option<String> {
    let at = version.find(".el")?;
    let rest = &version[at + 3..];
    let major = rest.bytes().take_while(u8::is_ascii_digit).count();
    let tail = rest[major..].strip_prefix('_')?;
    let minor = tail.bytes().take_while(u8::is_ascii_digit).count();
    if major == 0 || minor == 0 {
        return None;
    }
    Some(format!(
        "{}.el{}.centos{}",
        &version[..at],
        &rest[..major],
        &tail[minor..]
    ))
}

/// Whether CentOS Linux `release` shipped `fix` (a Red Hat build) of binary package `name`, or
/// a later build. `modules` are the advisory's module streams (`perl:5.24`, comma-separated);
/// a module build's fix is compared with the builds of those streams by version-release, as
/// CentOS's module builds carry their own module tags. With no stream named, any stream's
/// build counts. A package CentOS never shipped has no build: not shipped.
pub fn shipped(release: &str, name: &str, modules: Option<&str>, fix: &str) -> bool {
    let module_fix = fix.contains(".module");
    let (Some(fix), rebranded) = (
        RpmVersion::parse_fix(fix),
        rebrand(fix).and_then(|f| RpmVersion::parse_fix(&f)),
    ) else {
        return false;
    };
    let streams: Vec<&str> = modules.map(|m| m.split(',').collect()).unwrap_or_default();
    builds()
        .get(&(release, name))
        .into_iter()
        .flatten()
        .filter(|(stream, _)| match (module_fix, *stream) {
            (false, s) => s == "-",
            (true, "-") => false,
            (true, s) => streams.is_empty() || streams.contains(&s),
        })
        .any(|(_, build)| {
            let build = if module_fix {
                RpmVersion::parse_fix(&build.to_string())
            } else {
                Some(build.clone())
            };
            build.is_some_and(|b| b >= fix || rebranded.as_ref().is_some_and(|r| b >= *r))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebranding_moves_the_z_stream_tag() {
        assert_eq!(
            rebrand("12:4.2.5-83.el7_9.2").as_deref(),
            Some("12:4.2.5-83.el7.centos.2")
        );
        assert_eq!(
            rebrand("115.12.0-1.el7_9").as_deref(),
            Some("115.12.0-1.el7.centos")
        );
        assert_eq!(rebrand("1.0-1.el7"), None);
        assert_eq!(rebrand("1.0-1.module+el8.4.0+1+2"), None);
        // The rebranded form is the build CentOS shipped: equal, and below the next fix.
        let v = |s: &str| RpmVersion::parse(s);
        assert_eq!(
            v(&rebrand("12:4.2.5-83.el7_9.2").unwrap_or_default()),
            v("12:4.2.5-83.el7.centos.2")
        );
        assert!(v("12:4.2.5-83.el7.centos.2") < v("12:4.2.5-83.el7_9.2"));
    }

    #[test]
    fn a_fix_is_shipped_when_the_final_repositories_have_it() {
        // CentOS 7 ended with openssl 1.0.2k-26: Red Hat's -25 shipped, the ELS -27 did not.
        assert!(shipped("7", "openssl", None, "1:1.0.2k-25.el7_9"));
        assert!(shipped("7", "openssl", None, "1:1.0.2k-26.el7_9"));
        assert!(!shipped("7", "openssl", None, "1:1.0.2k-27.el7_9"));
        // Rebranded: dhcp's last CentOS build is Red Hat's -83.el7_9.2, renamed.
        assert!(shipped("7", "dhclient", None, "12:4.2.5-83.el7_9.2"));
        assert!(!shipped("7", "dhclient", None, "12:4.2.5-83.el7_9.3"));
        // Module streams: perl 5.24's last build, but not perl 5.24's build for 5.30.
        assert!(shipped(
            "8",
            "perl",
            Some("perl:5.24"),
            "4:5.24.4-404.module+el8.1.0+2926+ce7246ad"
        ));
        assert!(!shipped(
            "8",
            "perl",
            Some("perl:5.24"),
            "4:5.24.4-405.module+el8.1.0+2926+ce7246ad"
        ));
        assert!(!shipped(
            "8",
            "perl",
            Some("perl:5.26"),
            "4:5.24.4-404.module+el8.1.0+2926+ce7246ad"
        ));
        // Neither a non-module fix nor a release or package CentOS does not have.
        assert!(!shipped("8", "perl", None, "4:5.30.0-1.el8"));
        assert!(!shipped("9", "openssl", None, "1:1.0.2k-25.el7_9"));
        assert!(!shipped("7", "no-such-package", None, "1.0-1.el7"));
    }
}
