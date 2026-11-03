//! Container images end to end through the binary: `scan --image` and `[[image]]` on a root
//! filesystem built here, matched against a small Debian OSV export, offline.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
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
        // A fixed scan date (2026-11-03), so end-of-life warnings do not appear on their own
        // as the fixtures' releases age.
        .env("SOURCE_DATE_EPOCH", "1793664000")
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

/// A jar or war holding `entries`.
fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in entries {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn language_record(id: &str, ecosystem: &str, package: &str, fixed: &str) -> String {
    format!(
        r#"{{"id":"{id}","modified":"2026-01-01T00:00:00Z","summary":"issue in {package}",
        "affected":[{{"package":{{"ecosystem":"{ecosystem}","name":"{package}"}},
        "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"{fixed}"}}]}}]}}]}}"#
    )
}

#[test]
fn java_archives_and_gems_in_an_image_are_matched() {
    let fx = Fixture::new("java");
    let root = fx.dir.join("rootfs");
    let osv = fx.dir.join("osv");
    write(
        &osv.join("Maven"),
        "GHSA-1.json",
        &language_record(
            "GHSA-1",
            "Maven",
            "org.apache.logging.log4j:log4j-core",
            "2.15.0",
        ),
    );
    write(
        &osv.join("Maven"),
        "GHSA-2.json",
        &language_record(
            "GHSA-2",
            "Maven",
            "org.springframework:spring-core",
            "5.3.21",
        ),
    );
    write(
        &osv.join("Maven"),
        "GHSA-3.json",
        &language_record("GHSA-3", "Maven", "com.other:common", "9.0"),
    );
    write(
        &osv.join("Maven"),
        "GHSA-5.json",
        &language_record(
            "GHSA-5",
            "Maven",
            "org.apache.tomcat:tomcat-catalina",
            "9.0.70",
        ),
    );
    write(
        &osv.join("RubyGems"),
        "GHSA-4.json",
        &language_record("GHSA-4", "RubyGems", "rack", "2.2.9"),
    );
    write(
        &root,
        "usr/local/bundle/specifications/rack-2.2.8.gemspec",
        "Gem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"2.2.8\"\nend\n",
    );
    let log4j = archive(&[(
        "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
        b"groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n",
    )]);
    // Built by Gradle: no pom.properties, only a file name and classes.
    let spring = archive(&[("org/springframework/core/Foo.class", b"")]);
    // Tomcat's: no version in the file name, and an OSGi bundle in the manifest.
    let catalina = archive(&[(
        "META-INF/MANIFEST.MF",
        b"Bundle-SymbolicName: org.apache.tomcat-catalina\nBundle-Version: 9.0.50\n",
    )]);
    std::fs::create_dir_all(root.join("usr/local/tomcat/lib")).unwrap();
    std::fs::write(root.join("usr/local/tomcat/lib/catalina.jar"), catalina).unwrap();
    // The name of an artifact with advisories, with someone else's classes.
    let common = archive(&[("com/acme/Foo.class", b"")]);
    let app = archive(&[
        ("BOOT-INF/lib/log4j-core-2.14.1.jar", &log4j),
        ("BOOT-INF/lib/spring-core-5.3.20.jar", &spring),
        ("BOOT-INF/lib/common-1.0.jar", &common),
    ]);
    std::fs::create_dir_all(root.join("opt")).unwrap();
    std::fs::write(root.join("opt/app.jar"), app).unwrap();
    let rootfs = fx.path("rootfs");
    let (_, report, stderr) = fx.scan(&["--image", &rootfs]);
    let got = findings(&report);
    for (id, package) in [
        ("GHSA-1", "org.apache.logging.log4j:log4j-core"),
        ("GHSA-2", "org.springframework:spring-core"),
        ("GHSA-4", "rack"),
        ("GHSA-5", "org.apache.tomcat:tomcat-catalina"),
    ] {
        assert!(
            got.contains(&(id.to_string(), package.to_string())),
            "{id}: {got:?} {stderr}"
        );
    }
    assert!(!got.iter().any(|(id, _)| id == "GHSA-3"), "{got:?}");
    // Where a nested jar is, and that the unplaced one is a gap.
    let text = report.to_string();
    assert!(
        text.contains("BOOT-INF/lib/log4j-core-2.14.1.jar"),
        "{report}"
    );
    assert!(
        report["coverage"].to_string().contains("common-1.0.jar"),
        "{report}"
    );
}

/// A tar stream of regular files.
fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, data) in files {
        let mut h = [0u8; 512];
        h[..path.len()].copy_from_slice(path.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

/// A `docker save` archive of `layers`, with `history` as its config's.
fn saved_image(path: &Path, layers: &[&[u8]], history: &str) {
    let names: Vec<String> = (0..layers.len())
        .map(|i| format!("l{i}/layer.tar"))
        .collect();
    let diff_ids: Vec<String> = (0..layers.len())
        .map(|i| format!("\"sha256:{}\"", layers[i].len() + i))
        .collect();
    let config = format!(
        r#"{{"rootfs":{{"diff_ids":[{}]}},"history":[{history}]}}"#,
        diff_ids.join(",")
    );
    let manifest = format!(
        r#"[{{"Config":"c.json","Layers":[{}]}}]"#,
        names
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut files: Vec<(&str, &[u8])> = vec![
        ("manifest.json", manifest.as_bytes()),
        ("c.json", config.as_bytes()),
    ];
    for (name, layer) in names.iter().zip(layers) {
        files.push((name, layer));
    }
    std::fs::write(path, tar_of(&files)).unwrap();
}

#[test]
fn findings_name_their_layer_and_the_fleet_rolls_up_by_base() {
    let fx = Fixture::new("layers");
    let os = "ID=debian\nVERSION_ID=\"12\"\n";
    let zlib = STATUS.split("\n\n").next().unwrap();
    let base = tar_of(&[
        ("etc/os-release", os.as_bytes()),
        ("var/lib/dpkg/status", format!("{zlib}\n\n").as_bytes()),
    ]);
    let status = STATUS.replace("Version: 3.0.11-1~deb12u1", "Version: 3.0.9-1");
    let own = tar_of(&[("var/lib/dpkg/status", status.as_bytes())]);
    let other = tar_of(&[("opt/app", b"x")]);
    let history = r#"{"created_by":"/bin/sh -c #(nop) ADD file:a in / "},
        {"created_by":"/bin/sh -c #(nop)  CMD [\"bash\"]","empty_layer":true},
        {"created_by":"/bin/sh -c apt-get install -y libssl3"},
        {"created_by":"/bin/sh -c #(nop)  CMD [\"app\"]","empty_layer":true}"#;
    let (one, two) = (fx.dir.join("one.tar"), fx.dir.join("two.tar"));
    saved_image(&one, &[&base, &own], history);
    saved_image(&two, &[&base, &other], history);
    let (one, two) = (one.to_string_lossy(), two.to_string_lossy());
    let (_, report, stderr) = fx.scan(&["--image", &one, "--image", &two]);
    let mut layers = BTreeMap::new();
    for v in report["vulnerabilities"].as_array().unwrap() {
        for o in v["occurrences"].as_array().unwrap() {
            let id = v["advisory_id"].as_str().unwrap().to_string();
            layers.insert((id, o["repo"].to_string()), o["layer"].clone());
        }
    }
    let zlib_layer = layers
        .iter()
        .find(|((id, _), _)| id == "CVE-2026-0001")
        .map(|(_, l)| l)
        .unwrap_or_else(|| panic!("{report} {stderr}"));
    assert_eq!(zlib_layer["index"], 0);
    assert_eq!(zlib_layer["base"], true);
    let openssl = layers
        .iter()
        .find(|((id, _), _)| id == "CVE-2026-0002")
        .map(|(_, l)| l)
        .unwrap();
    assert_eq!(openssl["index"], 1);
    assert_eq!(openssl["created_by"], "RUN apt-get install -y libssl3");
    assert!(openssl.get("base").is_none(), "{openssl}");
    // Two images on one base: its findings count once, the app's layer not at all.
    let bases = report["base_images"].as_array().unwrap();
    assert_eq!(bases.len(), 1, "{report}");
    assert_eq!(bases[0]["images"].as_array().unwrap().len(), 2);
    assert_eq!(bases[0]["os"], "Debian 12");
    assert_eq!(bases[0]["layers"], 1);
    // CVE-2026-0001 has a fix, CVE-2026-0003 has none.
    assert_eq!(bases[0]["findings"], 2, "{report}");
    assert_eq!(bases[0]["fixable"], 1, "{report}");
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
    // The stray empty database is not a gap; the one gap is Red Hat's VEX, whose open
    // statuses a Rocky image borrows and which this fixture does not load.
    let coverage = report["coverage"].as_array().unwrap();
    assert_eq!(coverage.len(), 1, "{report}");
    let reason = coverage[0]["reason"].as_str().unwrap();
    assert!(
        reason.contains("Red Hat's CSAF VEX is not loaded")
            && reason.contains("Rocky Linux 8")
            && !reason.contains("fixes osv.dev"),
        "{reason}"
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
        "ID=\"centos\"\nVERSION_ID=\"8\"\nPRETTY_NAME=\"CentOS Stream 8\"\n",
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
        report["coverage"].to_string().contains("CentOS Stream 8"),
        "{report}"
    );
    // CentOS Stream 8 reached its end of life on 2024-05-31: a warning, from the bundled
    // snapshot.
    let eol = &report["warnings"][0];
    assert_eq!(eol["kind"], "unmaintained", "{report}");
    assert_eq!(eol["advisory_id"], "EOL-centos-stream-8");
    assert!(
        eol["title"]
            .as_str()
            .unwrap()
            .starts_with("CentOS Stream 8 reached the end of its standard support on 2024-05-31"),
        "{eol}"
    );
    assert_eq!(report["outcomes"][0]["warnings"], 1, "{report}");
}

#[test]
fn vendor_feed_distro_matches_binaries_and_links_the_vendor_page() {
    // Oracle Linux has no osv.dev data: its export is converted from Oracle's OVAL by sync,
    // in the shape written here.
    let fx = Fixture::new("rpm-feed");
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../os/tests/fixtures/rpmdb");
    let root = fx.dir.join("rpmfs");
    write(
        &root,
        "etc/os-release",
        "ID=\"ol\"\nVERSION_ID=\"8.10\"\nPRETTY_NAME=\"Oracle Linux Server 8.10\"\n",
    );
    std::fs::create_dir_all(root.join("var/lib/rpm")).unwrap();
    std::fs::copy(
        fixtures.join("db-bdb/Packages"),
        root.join("var/lib/rpm/Packages"),
    )
    .unwrap();
    let elsa = |id: &str, fixed: &str, module: &str| {
        format!(
            r#"{{"id":"{id}","summary":"{id}: libpng security update (IMPORTANT)",
            "aliases":["CVE-{}"],"database_specific":{{"severity":"HIGH"}},
            "references":[{{"type":"ADVISORY","url":"https://linux.oracle.com/errata/{id}.html"}}],
            "affected":[{{"package":{{"ecosystem":"Oracle Linux:8","name":"libpng"}},{module}
            "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"{fixed}"}}]}}]}}]}}"#,
            id.trim_start_matches("ELSA-")
        )
    };
    let osv = fx.dir.join("osv/Oracle Linux_8");
    write(
        &osv,
        "ELSA-2026-1.json",
        &elsa("ELSA-2026-1", "2:1.6.34-12.el8_10", ""),
    );
    // About a module stream's builds: the installed libpng is no module build.
    write(
        &osv,
        "ELSA-2026-2.json",
        &elsa(
            "ELSA-2026-2",
            "2:1.6.99-1.module+el8.10.0",
            r#""ecosystem_specific":{"module":"libpng:1"},"#,
        ),
    );
    let rootfs = fx.path("rpmfs");
    let (code, report, stderr) = fx.scan(&["--image", &rootfs, "--require-full-coverage"]);
    assert_eq!(code, 1, "{stderr}");
    assert_eq!(
        findings(&report),
        vec![("ELSA-2026-1".into(), "oracle/libpng".into())],
        "{report}"
    );
    assert_eq!(
        report["vulnerabilities"][0]["url"],
        "https://linux.oracle.com/errata/ELSA-2026-1.html"
    );
}

/// A Red Hat CSAF VEX document for one CVE: `fixed` components on the RHEL 8 BaseOS main
/// stream (purl with epoch), `open` components Red Hat lists against the release with a
/// remediation (`no_fix_planned` "Will not fix").
fn red_hat_vex_doc(cve: &str, fixed: &[(&str, &str, &str)], open: &[(&str, &str)]) -> String {
    let mut products = vec![
        r#"{"category":"product_name","name":"Red Hat Enterprise Linux 8","product":{
          "name":"Red Hat Enterprise Linux 8","product_id":"red_hat_enterprise_linux_8",
          "product_identification_helper":{"cpe":"cpe:/o:redhat:enterprise_linux:8"}}}"#
            .to_string(),
        r#"{"category":"product_name","name":"BaseOS 8.10","product":{
          "name":"BaseOS 8.10","product_id":"BaseOS-8.10.0.Z.MAIN.EUS",
          "product_identification_helper":{"cpe":"cpe:/o:redhat:enterprise_linux:8::baseos"}}}"#
            .to_string(),
    ];
    let (mut rels, mut fixed_ids, mut open_ids, mut remediations) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (name, epoch, vr) in fixed {
        let id = format!("{name}-{epoch}:{vr}.x86_64");
        products.push(format!(
            r#"{{"category":"product_version","name":"{id}","product":{{"name":"{id}","product_id":"{id}",
              "product_identification_helper":{{"purl":"pkg:rpm/redhat/{name}@{vr}?arch=x86_64&epoch={epoch}"}}}}}}"#
        ));
        let full = format!("BaseOS-8.10.0.Z.MAIN.EUS:{id}");
        rels.push(format!(
            r#"{{"category":"default_component_of","product_reference":"{id}",
              "relates_to_product_reference":"BaseOS-8.10.0.Z.MAIN.EUS",
              "full_product_name":{{"name":"x","product_id":"{full}"}}}}"#
        ));
        fixed_ids.push(format!("\"{full}\""));
    }
    for (name, details) in open {
        products.push(format!(
            r#"{{"category":"product_version","name":"{name}","product":{{"name":"{name}","product_id":"{name}",
              "product_identification_helper":{{"purl":"pkg:rpm/redhat/{name}"}}}}}}"#
        ));
        let full = format!("red_hat_enterprise_linux_8:{name}");
        rels.push(format!(
            r#"{{"category":"default_component_of","product_reference":"{name}",
              "relates_to_product_reference":"red_hat_enterprise_linux_8",
              "full_product_name":{{"name":"x","product_id":"{full}"}}}}"#
        ));
        remediations.push(format!(
            r#"{{"category":"no_fix_planned","details":"{details}","product_ids":["{full}"]}}"#
        ));
        open_ids.push(format!("\"{full}\""));
    }
    format!(
        r#"{{"document":{{"category":"csaf_vex","csaf_version":"2.0",
          "aggregate_severity":{{"text":"Important"}},
          "publisher":{{"namespace":"https://www.redhat.com","name":"Red Hat Product Security"}},
          "tracking":{{"id":"{cve}","current_release_date":"2026-10-01T00:00:00+00:00"}}}},
        "product_tree":{{"branches":[{{"category":"vendor","name":"Red Hat","branches":[{}]}}],
          "relationships":[{}]}},
        "vulnerabilities":[{{"cve":"{cve}",
          "product_status":{{"fixed":[{}],"known_affected":[{}]}},
          "remediations":[{}]}}]}}"#,
        products.join(","),
        rels.join(","),
        fixed_ids.join(","),
        open_ids.join(","),
        remediations.join(",")
    )
}

/// A RHEL 8 root filesystem (the Berkeley DB fixture: basesystem, libpng
/// 2:1.6.34-11.el8_10, which) and a `Red Hat` export that says nothing about its packages.
fn rhel_fixture(name: &str) -> Fixture {
    let fx = Fixture::new(name);
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../os/tests/fixtures/rpmdb");
    let root = fx.dir.join("rpmfs");
    write(
        &root,
        "etc/os-release",
        "ID=\"rhel\"\nVERSION_ID=\"8.10\"\nPRETTY_NAME=\"Red Hat Enterprise Linux 8.10 (Ootpa)\"\n",
    );
    std::fs::create_dir_all(root.join("var/lib/rpm")).unwrap();
    std::fs::copy(
        fixtures.join("db-bdb/Packages"),
        root.join("var/lib/rpm/Packages"),
    )
    .unwrap();
    for (i, stream) in ["baseos", "appstream", "crb"].iter().enumerate() {
        write(
            &fx.dir.join("osv/Red Hat"),
            &format!("RHSA-2026:{i}.json"),
            &format!(
                r#"{{"id":"RHSA-2026:{i}","modified":"2026-01-01T00:00:00Z","summary":"zsh update",
                "affected":[{{"package":{{"ecosystem":"Red Hat:enterprise_linux:8::{stream}","name":"zsh"}},
                "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"0:5.5.1-11.el8"}}]}}]}}]}}"#
            ),
        );
    }
    fx
}

#[test]
fn red_hat_vex_reports_unfixed_statuses_and_fixes_osv_lacks() {
    let fx = rhel_fixture("rhel-vex");
    let docs = fx.dir.join("csaf-docs");
    write(
        &docs,
        "2026/cve-2026-0101.json",
        &red_hat_vex_doc("CVE-2026-0101", &[("libpng", "2", "1.6.34-12.el8_10")], &[]),
    );
    write(
        &docs,
        "2026/cve-2026-0102.json",
        &red_hat_vex_doc("CVE-2026-0102", &[], &[("which", "Will not fix")]),
    );
    // Fixed already: the installed libpng is past it.
    write(
        &docs,
        "2026/cve-2026-0103.json",
        &red_hat_vex_doc("CVE-2026-0103", &[("libpng", "2", "1.6.34-10.el8_10")], &[]),
    );
    let osv = fx.path("osv");
    let out = run(
        &[
            "db",
            "import",
            "-q",
            "--csaf",
            &docs.to_string_lossy(),
            "--osv-dir",
            &osv,
        ],
        &fx.dir.join("cache"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rootfs = fx.path("rpmfs");
    let (code, report, stderr) = fx.scan(&["--image", &rootfs, "--require-full-coverage"]);
    assert_eq!(code, 1, "{stderr}");
    assert_eq!(
        findings(&report),
        vec![
            ("CVE-2026-0101".into(), "redhat/libpng".into()),
            ("CVE-2026-0102".into(), "redhat/which".into()),
        ],
        "{report}"
    );
    let text = report.to_string();
    assert!(text.contains("1.6.34-12.el8_10"), "the VEX fix: {text}");
    assert!(text.contains("status will not fix"), "{text}");
    assert!(
        text.contains("https://access.redhat.com/security/cve/CVE-2026-0102"),
        "{text}"
    );
    // Derived once: a second scan reads the cached export and agrees.
    let (code2, report2, _) = fx.scan(&["--image", &rootfs]);
    assert_eq!(code2, 1);
    assert_eq!(findings(&report2), findings(&report));
}

#[test]
fn red_hat_without_the_vex_index_is_a_gap() {
    let fx = rhel_fixture("rhel-novex");
    let rootfs = fx.path("rpmfs");
    let (code, report, stderr) = fx.scan(&["--image", &rootfs, "--require-full-coverage"]);
    assert_eq!(code, 2, "{stderr}");
    let coverage = report["coverage"].to_string();
    assert!(
        coverage.contains("fleetreach db sync --source csaf:redhat"),
        "{report}"
    );
}

/// A SUSE CSAF VEX document for one CVE, in SUSE's shape: products by name, components by
/// binary name with `@version` purls, `(product, binary, version)` in each status list.
fn suse_vex_doc(cve: &str, statuses: &[(&str, &str, &str, &str)]) -> String {
    let mut names: Vec<&str> = statuses.iter().map(|s| s.1).collect();
    names.sort_unstable();
    names.dedup();
    let mut products: Vec<String> = names
        .iter()
        .map(|p| {
            format!(
                r#"{{"category":"product_name","name":"{p}","product":{{"name":"{p}","product_id":"{p}"}}}}"#
            )
        })
        .collect();
    let (mut rels, mut by_status) = (Vec::new(), BTreeMap::<&str, Vec<String>>::new());
    for (status, product, name, version) in statuses {
        let id = format!("{name}-{version}");
        let purl = format!("pkg:rpm/suse/{name}@{version}");
        products.push(format!(
            r#"{{"category":"product_version","name":"{id}","product":{{"name":"{id}","product_id":"{id}",
              "product_identification_helper":{{"purl":"{purl}"}}}}}}"#
        ));
        let full = format!("{product}:{id}");
        rels.push(format!(
            r#"{{"category":"default_component_of","product_reference":"{id}",
              "relates_to_product_reference":"{product}",
              "full_product_name":{{"name":"x","product_id":"{full}"}}}}"#
        ));
        by_status
            .entry(status)
            .or_default()
            .push(format!("\"{full}\""));
    }
    let status: Vec<String> = by_status
        .iter()
        .map(|(k, v)| format!("\"{k}\":[{}]", v.join(",")))
        .collect();
    let fixes = by_status
        .get("recommended")
        .map(|v| v.join(","))
        .unwrap_or_default();
    format!(
        r#"{{"document":{{"category":"csaf_vex","csaf_version":"2.0",
          "aggregate_severity":{{"text":"important"}},
          "publisher":{{"namespace":"https://www.suse.com/","name":"SUSE Product Security Team"}},
          "tracking":{{"id":"{cve}","current_release_date":"2026-10-01T00:00:00Z"}}}},
        "product_tree":{{"branches":[{{"category":"vendor","name":"SUSE","branches":[{{
          "category":"product_family","name":"SUSE Linux Enterprise","branches":[{}]}}]}}],
          "relationships":[{}]}},
        "vulnerabilities":[{{"cve":"{cve}","product_status":{{{}}},
          "remediations":[{{"category":"vendor_fix","details":"zypper patch","product_ids":[{fixes}]}}]}}]}}"#,
        products.join(","),
        rels.join(","),
        status.join(",")
    )
}

/// An openSUSE Leap 15.6 root filesystem (the NDB fixture: `libpng16-16`, built from
/// `libpng16`, and `which`) and an `openSUSE` export that says nothing about its packages.
fn leap_fixture(name: &str) -> Fixture {
    let fx = Fixture::new(name);
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../os/tests/fixtures/rpmdb");
    let root = fx.dir.join("rpmfs");
    write(
        &root,
        "etc/os-release",
        "NAME=\"openSUSE Leap\"\nID=\"opensuse-leap\"\nVERSION_ID=\"15.6\"\n",
    );
    std::fs::create_dir_all(root.join("usr/lib/sysimage/rpm")).unwrap();
    std::fs::copy(
        fixtures.join("db-ndb/Packages.db"),
        root.join("usr/lib/sysimage/rpm/Packages.db"),
    )
    .unwrap();
    write(
        &fx.dir.join("osv/openSUSE"),
        "openSUSE-SU-2026:1.json",
        r#"{"id":"openSUSE-SU-2026:1","modified":"2026-01-01T00:00:00Z","summary":"zsh update",
        "affected":[{"package":{"ecosystem":"openSUSE:Leap 15.6","name":"zsh"},
        "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.6-150600.1.1"}]}]}]}"#,
    );
    fx
}

#[test]
fn suse_vex_matches_binaries_and_borrows_sle_fixes() {
    let fx = leap_fixture("leap-vex");
    let leap = "openSUSE Leap 15.6";
    let docs = fx.dir.join("csaf-docs");
    let doc = |cve: &str, statuses: &[(&str, &str, &str, &str)]| {
        write(
            &docs,
            &format!("2026/{}.json", cve.to_lowercase()),
            &suse_vex_doc(cve, statuses),
        );
    };
    // A fix for the binary, which is named apart from its source package.
    doc(
        "CVE-2026-0201",
        &[("recommended", leap, "libpng16-16", "1.6.40-150600.3.20.1")],
    );
    // Still affected: the current build is recommended next to the status.
    doc(
        "CVE-2026-0202",
        &[
            (
                "known_affected",
                leap,
                "libpng16-16",
                "1.6.40-150600.3.17.1",
            ),
            ("recommended", leap, "libpng16-16", "1.6.40-150600.3.17.1"),
        ],
    );
    doc(
        "CVE-2026-0203",
        &[("known_not_affected", leap, "which", "2.21-2.20")],
    );
    // Fixed in the SLE codestream Leap is built from.
    doc(
        "CVE-2026-0204",
        &[(
            "recommended",
            "SUSE Linux Enterprise Server 15 SP6",
            "libpng16-16",
            "1.6.40-150600.3.25.1",
        )],
    );
    let osv = fx.path("osv");
    let out = run(
        &[
            "db",
            "import",
            "-q",
            "--csaf",
            &docs.to_string_lossy(),
            "--provider",
            "suse",
            "--osv-dir",
            &osv,
        ],
        &fx.dir.join("cache"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rootfs = fx.path("rpmfs");
    let (code, report, stderr) = fx.scan(&["--image", &rootfs, "--require-full-coverage"]);
    assert_eq!(code, 1, "{stderr}");
    assert_eq!(
        findings(&report),
        vec![
            ("CVE-2026-0201".into(), "opensuse/libpng16".into()),
            ("CVE-2026-0202".into(), "opensuse/libpng16".into()),
            ("CVE-2026-0204".into(), "opensuse/libpng16".into()),
        ],
        "{report}"
    );
    let titles: Vec<&str> = report["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["title"].as_str().unwrap())
        .collect();
    assert!(
        titles[0].contains("fixed in 0:1.6.40-150600.3.20.1"),
        "{titles:?}"
    );
    assert!(
        titles[1].contains("no fix yet; status affected"),
        "{titles:?}"
    );
    assert!(
        titles[2].contains("fixed only in another line"),
        "{titles:?}"
    );
    assert!(
        report
            .to_string()
            .contains("https://www.suse.com/security/cve/CVE-2026-0201.html"),
        "{report}"
    );
}

#[test]
fn suse_without_the_vex_index_is_a_gap() {
    let fx = leap_fixture("leap-novex");
    let rootfs = fx.path("rpmfs");
    let (code, report, stderr) = fx.scan(&["--image", &rootfs, "--require-full-coverage"]);
    assert_eq!(code, 2, "{stderr}");
    let coverage = report["coverage"].to_string();
    assert!(
        coverage.contains("fleetreach db sync --source csaf:suse"),
        "{report}"
    );
}

#[cfg(unix)]
#[test]
fn bottlerocket_inventory_matches_its_advisories() {
    // Bottlerocket ships no rpm database: its packages are in the application inventory,
    // under the system root that `/usr` links to. The export is converted from Bottlerocket's
    // updateinfo by sync, in the shape written here.
    let fx = Fixture::new("bottlerocket");
    let root = fx.dir.join("brfs");
    let sysroot = "x86_64-bottlerocket-linux-gnu/sys-root";
    write(
        &root,
        &format!("{sysroot}/usr/lib/os-release"),
        "NAME=Bottlerocket\nID=bottlerocket\nVERSION_ID=1.66.0\nVARIANT_ID=aws-k8s-1.33\n",
    );
    write(
        &root,
        &format!("{sysroot}/usr/share/bottlerocket/application-inventory.json"),
        r#"{"Content":[
          {"Name":"runc","Version":"1.3.6","Release":"1.1792624615.46ecbcc6.br1","Epoch":"1",
           "Architecture":"x86_64"},
          {"Name":"kernel-6.12","Version":"6.12.103","Release":"1.1789773142.51308e97.br1",
           "Epoch":"0","Architecture":"x86_64"}]}"#,
    );
    std::os::unix::fs::symlink(format!("./{sysroot}/usr"), root.join("usr")).unwrap();
    let advisory = |id: &str, name: &str, fixed: &str| {
        format!(
            r#"{{"id":"{id}","summary":"{name} update","aliases":[],
            "database_specific":{{"severity":"MEDIUM"}},
            "references":[{{"type":"ADVISORY","url":"https://github.com/bottlerocket-os/bottlerocket-kernel-kit/blob/develop/advisories/9.6.1/{id}.toml"}}],
            "affected":[{{"package":{{"ecosystem":"Bottlerocket","name":"{name}"}},
            "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"{fixed}"}}]}}]}}]}}"#
        )
    };
    let osv = fx.dir.join("osv/Bottlerocket");
    write(
        &osv,
        "BRSA-1.json",
        &advisory(
            "BRSA-1",
            "kernel-6.12",
            "0:6.12.113-1.1793052464.3031f223.br1",
        ),
    );
    // From before runc moved to upstream versions (epoch 1): the OS version, epoch 0.
    write(
        &osv,
        "GHSA-1.json",
        &advisory("GHSA-1", "runc", "0:1.19.0-2b1a7872"),
    );
    let rootfs = fx.path("brfs");
    let (code, report, stderr) = fx.scan(&["--image", &rootfs, "--require-full-coverage"]);
    assert_eq!(code, 1, "{stderr}");
    assert_eq!(
        findings(&report),
        vec![("BRSA-1".into(), "bottlerocket/kernel-6.12".into())],
        "{report}"
    );
    assert!(report["vulnerabilities"][0]["url"]
        .as_str()
        .unwrap()
        .ends_with("/BRSA-1.toml"));
}
