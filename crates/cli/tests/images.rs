//! Container images end to end through the binary: `scan --image` and `[[image]]` on a root
//! filesystem built here, matched against a small Debian OSV export, offline.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;

fn db() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../scan/tests/fixtures/advisory-db")
        .to_string_lossy()
        .into_owned()
}

fn run(args: &[&str], cache: &Path) -> Output {
    Command::cargo_bin("fleetreach")
        .unwrap()
        .args(args)
        .env("FLEETREACH_OSV_SYNC", "off")
        .env("XDG_CACHE_HOME", cache)
        .env_remove("FLEETREACH_OSV_DIR")
        .current_dir(cache)
        .output()
        .unwrap()
}

fn write(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

const STATUS: &str = "Package: zlib1g
Status: install ok installed
Source: zlib
Version: 1:1.2.13.dfsg-1
Architecture: arm64

Package: libssl3
Status: install ok installed
Source: openssl
Version: 3.0.11-1~deb12u1
Architecture: arm64

Package: python3-requests
Status: install ok installed
Source: requests
Version: 2.28.1+dfsg-1
Architecture: all

Package: old-gone
Status: deinstall ok config-files
Version: 1.0-1
Architecture: arm64
";

fn record(id: &str, package: &str, events: &str, urgency: &str) -> String {
    format!(
        r#"{{"id":"{id}","modified":"2026-01-01T00:00:00Z","summary":"issue in {package}",
        "affected":[{{"package":{{"ecosystem":"Debian:12","name":"{package}"}},
        "ranges":[{{"type":"ECOSYSTEM","events":[{events}]}}],
        "ecosystem_specific":{{"urgency":"{urgency}"}}}}]}}"#
    )
}

/// A Debian 12 root filesystem and an OSV directory with a fixed, an already-fixed and an
/// unfixed `unimportant` advisory.
struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("fleetreach-images-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("rootfs");
        write(&root, "etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n");
        write(&root, "var/lib/dpkg/status", STATUS);
        write(
            &root,
            "var/lib/dpkg/info/python3-requests.list",
            "/usr/lib/python3/dist-packages/requests-2.28.1.dist-info/METADATA\n",
        );
        write(
            &root,
            "usr/lib/python3/dist-packages/requests-2.28.1.dist-info/METADATA",
            "Name: requests\nVersion: 2.28.1\n",
        );
        let osv = dir.join("osv/Debian_12");
        write(
            &osv,
            "CVE-2026-0001.json",
            &record(
                "CVE-2026-0001",
                "zlib",
                r#"{"introduced":"0"},{"fixed":"1:1.2.13.dfsg-1+deb12u1"}"#,
                "high",
            ),
        );
        write(
            &osv,
            "CVE-2026-0002.json",
            &record(
                "CVE-2026-0002",
                "openssl",
                r#"{"introduced":"0"},{"fixed":"3.0.11-1~deb12u1"}"#,
                "medium",
            ),
        );
        write(
            &osv,
            "CVE-2026-0003.json",
            &record(
                "CVE-2026-0003",
                "zlib",
                r#"{"introduced":"0"}"#,
                "unimportant",
            ),
        );
        std::fs::create_dir_all(dir.join("cache")).unwrap();
        Fixture { dir }
    }

    fn path(&self, rel: &str) -> String {
        self.dir.join(rel).to_string_lossy().into_owned()
    }

    fn scan(&self, extra: &[&str]) -> (i32, serde_json::Value, String) {
        let osv = self.path("osv");
        let db = db();
        let mut args = vec!["scan", "-q", "--db", &db, "--osv-dir", &osv, "-f", "json"];
        args.extend(extra);
        // Run from a directory with no fleet.toml: with only `--image`, the fleet is the images.
        let cwd = self.dir.join("cache");
        let out = run(&args, &cwd);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let json = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {stderr}"));
        (out.status.code().unwrap_or(-1), json, stderr)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn findings(report: &serde_json::Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = report["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| {
            v["occurrences"].as_array().unwrap().iter().map(move |o| {
                (
                    v["advisory_id"].as_str().unwrap().to_string(),
                    o["package"].as_str().unwrap().to_string(),
                )
            })
        })
        .collect();
    out.sort();
    out
}

#[test]
fn image_os_packages_match_with_dpkg_order_and_keep_unfixed() {
    let fx = Fixture::new("match");
    let rootfs = fx.path("rootfs");
    let (code, report, stderr) = fx.scan(&["--image", &rootfs]);
    assert_eq!(code, 1, "vulnerable image fails the default gate: {stderr}");
    assert_eq!(
        findings(&report),
        vec![
            ("CVE-2026-0001".into(), "debian/zlib".into()),
            ("CVE-2026-0003".into(), "debian/zlib".into()),
        ],
        "the ~deb12u1 install equals its fix, so openssl is clean: {report}"
    );
    assert_eq!(report["outcomes"][0]["repo"], "rootfs");
    assert_eq!(report["outcomes"][0]["status"], "scanned");
    let text = report.to_string();
    assert!(
        text.contains("zlib 1:1.2.13.dfsg-1"),
        "the real version is kept: {text}"
    );
    assert!(text.contains("no fix yet; urgency unimportant"), "{text}");
    // python3-requests owns its dist-info, so it is not matched again as a PyPI package.
    assert!(!text.contains("pypi"), "{text}");
    assert!(report["provenance"]["osv"]
        .to_string()
        .contains("Debian:12"));

    let (_, report, _) = fx.scan(&["--image", &rootfs, "--distro-ignore-unimportant"]);
    assert_eq!(
        findings(&report),
        vec![("CVE-2026-0001".into(), "debian/zlib".into())]
    );
}

#[test]
fn image_in_fleet_toml_and_missing_export_is_an_error() {
    let fx = Fixture::new("toml");
    write(
        &fx.dir,
        "fleet.toml",
        "[[image]]\nid = \"api\"\npath = \"rootfs\"\ndistro = \"Debian:13\"\nowner = \"team-a\"\n",
    );
    let config = fx.path("fleet.toml");
    let (code, report, stderr) = fx.scan(&["-c", &config]);
    assert_eq!(code, 2, "no Debian:13 export: never clean: {stderr}");
    let reason = report["outcomes"][0]["reason"].as_str().unwrap();
    assert!(reason.contains("db sync --distros Debian:13"), "{reason}");
    assert_eq!(report["outcomes"][0]["repo"], "api");
}

#[test]
fn unknown_distribution_is_a_coverage_gap() {
    let fx = Fixture::new("unknown");
    write(
        &fx.dir.join("rootfs"),
        "etc/os-release",
        "ID=mydistro\nVERSION_ID=1\n",
    );
    let rootfs = fx.path("rootfs");
    let (code, report, stderr) = fx.scan(&["--image", &rootfs]);
    assert_eq!(code, 0, "{stderr}");
    let coverage = report["coverage"].to_string();
    assert!(coverage.contains("mydistro"), "{report}");
    let (code, _, _) = fx.scan(&["--image", &rootfs, "--require-full-coverage"]);
    assert_eq!(code, 2);
}

/// A Rocky Linux 8 root filesystem whose rpm database was written by rpm itself (the
/// `fleetreach-os` Berkeley DB fixture: basesystem, libpng 2:1.6.34-11.el8_10, which), beside
/// a stray empty `/usr/lib/sysimage/rpm` database like Oracle Linux 9 ships.
#[test]
fn rpm_image_matches_source_packages_with_rpm_order() {
    let fx = Fixture::new("rpm");
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../os/tests/fixtures/rpmdb");
    let root = fx.dir.join("rpmfs");
    write(
        &root,
        "etc/os-release",
        "ID=\"rocky\"\nVERSION_ID=\"8.10\"\n",
    );
    for (from, to) in [
        ("db-bdb/Packages", "var/lib/rpm/Packages"),
        ("db-empty/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite"),
    ] {
        std::fs::create_dir_all(root.join(to).parent().unwrap()).unwrap();
        std::fs::copy(fixtures.join(from), root.join(to)).unwrap();
    }
    let rocky = |id: &str, package: &str, fixed: &str| {
        format!(
            r#"{{"id":"{id}","modified":"2026-01-01T00:00:00Z","summary":"{package} update",
            "aliases":["CVE-{}"],
            "affected":[{{"package":{{"ecosystem":"Rocky Linux:8","name":"{package}"}},
            "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"{fixed}"}}]}}]}}]}}"#,
            id.trim_start_matches("RLSA-").replace(':', "-")
        )
    };
    let osv = fx.dir.join("osv/Rocky Linux");
    // el8_10 < el8_11 in rpm's order, so libpng is affected; which is already at its fix.
    write(
        &osv,
        "RLSA-2026:1.json",
        &rocky("RLSA-2026:1", "libpng", "2:1.6.34-11.el8_11"),
    );
    write(
        &osv,
        "RLSA-2026:2.json",
        &rocky("RLSA-2026:2", "which", "2.21-21.el8_10"),
    );
    // Without its epoch, 1.6.40 would look newer than the installed 2:1.6.34.
    write(
        &osv,
        "RLSA-2026:3.json",
        &rocky("RLSA-2026:3", "libpng", "1:1.6.40-1.el8"),
    );
    let rootfs = fx.path("rpmfs");
    let (code, report, stderr) = fx.scan(&["--image", &rootfs]);
    assert_eq!(code, 1, "{stderr}");
    assert_eq!(
        findings(&report),
        vec![("RLSA-2026:1".into(), "rocky-linux/libpng".into())],
        "{report}"
    );
    let text = report.to_string();
    assert!(text.contains("libpng 2:1.6.34-11.el8_10"), "{text}");
    assert_eq!(report["vulnerabilities"][0]["ecosystem"], "rpm");
    assert!(
        report["coverage"].as_array().is_none_or(|c| c.is_empty()),
        "the stray empty database is not a gap: {report}"
    );
}

#[test]
fn rpm_distro_without_osv_data_is_a_gap_not_clean() {
    let fx = Fixture::new("rpm-gap");
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../os/tests/fixtures/rpmdb");
    let root = fx.dir.join("rpmfs");
    write(
        &root,
        "etc/os-release",
        "ID=\"ol\"\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"Oracle Linux Server 9.4\"\n",
    );
    std::fs::create_dir_all(root.join("var/lib/rpm")).unwrap();
    std::fs::copy(
        fixtures.join("db-ndb/Packages.db"),
        root.join("var/lib/rpm/Packages.db"),
    )
    .unwrap();
    let rootfs = fx.path("rpmfs");
    let (code, report, stderr) = fx.scan(&["--image", &rootfs, "--require-full-coverage"]);
    assert_eq!(code, 2, "{stderr}");
    assert!(
        report["coverage"]
            .to_string()
            .contains("Oracle Linux Server 9.4"),
        "{report}"
    );
}
