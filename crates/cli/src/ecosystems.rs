//! `fleetreach ecosystems`: the coverage matrix (spec 16, row 7). One row per ecosystem: the
//! files read and the coverage each gives, where advisories come from, the version comparator,
//! what it was checked against and the result. The website's ecosystem overview is generated
//! from this table (`website/scripts/ecosystems.mjs`), and a test runs every listed file through
//! the scan's own detection, so the page cannot name a file the scanner does not pick up.

use clap::{Args, ValueEnum};
use serde::Serialize;

/// One file (or file family) an ecosystem reads.
#[derive(Debug, Serialize)]
pub(crate) struct Input {
    /// As shown: a file name, a glob, or a path inside an image.
    pub(crate) file: &'static str,
    /// `full`, `direct-only` or `partial`, optionally followed by when.
    pub(crate) coverage: &'static str,
    /// Files that make a repo with only them scanned in this ecosystem, for the detection test;
    /// empty where the input is not found in a checkout (an image path).
    #[serde(skip)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) probe: &'static [(&'static str, &'static str)],
}

#[derive(Debug, Serialize)]
pub(crate) struct Row {
    pub(crate) name: &'static str,
    /// The docs page under `/docs/ecosystems/`.
    pub(crate) page: &'static str,
    pub(crate) reads: &'static [Input],
    pub(crate) advisories: &'static str,
    pub(crate) comparator: &'static str,
    /// The independent implementation or data the matching was checked against.
    pub(crate) checked_against: &'static str,
    pub(crate) result: &'static str,
}

const fn full(file: &'static str, probe: &'static [(&'static str, &'static str)]) -> Input {
    Input {
        file,
        coverage: "full",
        probe,
    }
}

const PYPROJECT: &str = "[project]\nname = \"p\"\ndependencies = [\"requests==2.31.0\"]\n";

pub(crate) const MATRIX: &[Row] = &[
    Row {
        name: "Rust",
        page: "rust",
        reads: &[full("Cargo.lock", &[("Cargo.lock", "version = 3\n")])],
        advisories: "RustSec, osv.dev crates.io export",
        comparator: "SemVer (`semver` crate, as RustSec)",
        checked_against: "Trivy and Grype on 600 real lockfiles",
        result: "every row only fleetreach reports traced to a RustSec record neither tool reads",
    },
    Row {
        name: "Go",
        page: "go",
        reads: &[full("go.mod", &[("go.mod", "module m\n\ngo 1.22\n")])],
        advisories: "osv.dev or vuln.go.dev",
        comparator: "Go module versions (pseudo-versions included)",
        checked_against: "47,000 real go.mod files from the module proxy, plus fuzzing",
        result: "no panics; pseudo-version and replace traps fixed and pinned by tests",
    },
    Row {
        name: "npm",
        page: "npm",
        reads: &[
            full("package-lock.json", &[("package-lock.json", "{}")]),
            full(
                "pnpm-lock.yaml",
                &[("pnpm-lock.yaml", "lockfileVersion: '9.0'\n")],
            ),
            full("yarn.lock", &[("yarn.lock", "")]),
            full("bun.lock", &[("bun.lock", "{}")]),
        ],
        advisories: "osv.dev",
        comparator: "SemVer (`node-semver` rules)",
        checked_against: "OSV ranges on real lockfiles; npm, pnpm, yarn and bun package lists",
        result: "511 of 511 vulnerable cases found; 35 of 39 package sets identical, 4 explained",
    },
    Row {
        name: "PyPI",
        page: "pypi",
        reads: &[
            full("uv.lock", &[("uv.lock", "version = 1\n")]),
            full("poetry.lock", &[("poetry.lock", "")]),
            full("Pipfile.lock", &[("Pipfile.lock", "{}")]),
            full(
                "pylock.toml",
                &[("pylock.toml", "lock-version = \"1.0\"\n")],
            ),
            Input {
                file: "requirements*.txt",
                coverage: "full when every line is pinned, else direct-only",
                probe: &[("requirements.txt", "requests==2.31.0\n")],
            },
            Input {
                file: "pyproject.toml",
                coverage: "direct-only; partial when resolved with --resolve-python",
                probe: &[("pyproject.toml", PYPROJECT)],
            },
        ],
        advisories: "osv.dev",
        comparator: "PEP 440 (`pep440_rs`)",
        checked_against: "OSV ranges and version lists; `uv pip compile` for resolution",
        result: "100% recall and precision on 3,000 advisories; 69 of 69 resolutions agree",
    },
    Row {
        name: "RubyGems",
        page: "rubygems",
        reads: &[full("Gemfile.lock", &[("Gemfile.lock", "")])],
        advisories: "osv.dev",
        comparator: "`Gem::Version`",
        checked_against: "RubyGems 3.3+ `Gem::Version`",
        result: "agrees; golden tests pin it",
    },
    Row {
        name: "Packagist",
        page: "packagist",
        reads: &[full("composer.lock", &[("composer.lock", "{}")])],
        advisories: "osv.dev",
        comparator: "Composer `version_compare`",
        checked_against: "`composer/semver`",
        result: "185,000 version pairs, 100% agreement",
    },
    Row {
        name: "NuGet",
        page: "nuget",
        reads: &[
            full("packages.lock.json", &[("packages.lock.json", "{}")]),
            Input {
                file: "obj/project.assets.json",
                coverage: "full",
                probe: &[
                    ("app.csproj", "<Project/>"),
                    ("obj/project.assets.json", "{}"),
                ],
            },
            full("packages.config", &[("packages.config", "<packages/>")]),
            Input {
                file: "*.csproj, *.fsproj, *.vbproj",
                coverage: "direct-only",
                probe: &[("app.csproj", "<Project/>")],
            },
        ],
        advisories: "osv.dev",
        comparator: "`NuGetVersion`",
        checked_against: "`NuGet.Versioning` (.NET)",
        result: "167,539 version pairs, 100% agreement",
    },
    Row {
        name: "Maven",
        page: "maven",
        reads: &[
            full("gradle.lockfile", &[("gradle.lockfile", "")]),
            full(
                "versions.lock",
                &[("versions.lock", ""), ("versions.props", "")],
            ),
            Input {
                file: "pom.xml",
                coverage:
                    "full when resolved, partial when some POMs are missing, else direct-only",
                probe: &[("pom.xml", "<project/>")],
            },
            Input {
                file: "build.gradle, build.gradle.kts",
                coverage: "partial: read, not run",
                probe: &[("build.gradle", "")],
            },
        ],
        advisories: "osv.dev",
        comparator: "`ComparableVersion`",
        checked_against: "Apache Maven `ComparableVersion`; `mvn dependency:list`",
        result:
            "710,000+ version pairs, 100% agreement; Spring Boot 2.7 resolves the same 85 artifacts",
    },
    Row {
        name: "GitHub Actions",
        page: "github-actions",
        reads: &[Input {
            file: ".github/workflows/*.yml",
            coverage: "full for tag refs; a commit or branch ref is listed, not matched",
            probe: &[(".github/workflows/ci.yml", "on: push\n")],
        }],
        advisories: "osv.dev",
        comparator: "SemVer on tags (`v4` as `4.0.0`)",
        checked_against: "fixture workflows",
        result: "padded tags matched; tj-actions/changed-files caught",
    },
    Row {
        name: "Swift",
        page: "swift",
        reads: &[full("Package.resolved", &[("Package.resolved", "{}")])],
        advisories: "osv.dev",
        comparator: "SemVer, packages named by URL",
        checked_against: "11,188 real Swift Package Index URLs",
        result: "no panics; 27 of 30 OSV packages matched real URLs",
    },
    Row {
        name: "Hex",
        page: "hex",
        reads: &[full("mix.lock", &[("mix.lock", "%{}\n")])],
        advisories: "osv.dev",
        comparator: "SemVer",
        checked_against: "real mix.lock files from 12 Elixir projects",
        result: "no parse errors",
    },
    Row {
        name: "Julia",
        page: "julia",
        reads: &[full("Manifest.toml", &[("Manifest.toml", "")])],
        advisories: "osv.dev",
        comparator: "`VersionNumber`",
        checked_against: "Julia `VersionNumber`, the whole General registry",
        result: "307,740 version pairs, 100% agreement",
    },
    Row {
        name: "Container images",
        page: "container-images",
        reads: &[
            full("var/lib/dpkg/status", &[]),
            full("lib/apk/db/installed", &[]),
            full("var/lib/rpm", &[]),
            Input {
                file: "Java, Ruby, Go and Rust packages in the image",
                coverage: "full when identified, else partial",
                probe: &[],
            },
        ],
        advisories: "osv.dev distro exports; Red Hat and SUSE CSAF VEX; Amazon, Oracle, Photon, \
                     Fedora and Bottlerocket feeds",
        comparator: "dpkg, apk-tools and rpm",
        checked_against: "Trivy and Grype on 217 public images",
        result: "every difference explained",
    },
];

/// Ecosystems with osv.dev records that are not matched, and why.
pub(crate) const NOT_PLANNED: &str = "Pub, CRAN, Hackage and opam are not matched: osv.dev holds \
                                      96 records for the four together. The decision is \
                                      revisited if that volume grows.";

#[derive(Args)]
pub struct EcosystemsArgs {
    #[arg(short, long, value_enum, default_value_t = Format::Table)]
    format: Format,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Table,
    Markdown,
    Json,
}

#[derive(Serialize)]
struct Matrix {
    schema: &'static str,
    ecosystems: &'static [Row],
    not_planned: &'static str,
}

fn reads_text(row: &Row, code: bool) -> String {
    row.reads
        .iter()
        .map(|input| {
            let file = if code {
                input
                    .file
                    .split(", ")
                    .map(|f| {
                        if f.contains(' ') || !f.contains(['.', '/', '*']) {
                            f.to_string()
                        } else {
                            format!("`{f}`")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                input.file.to_string()
            };
            format!("{file} ({})", input.coverage)
        })
        .collect::<Vec<_>>()
        .join(if code { "<br>" } else { "; " })
}

pub(crate) fn markdown() -> String {
    let mut out = String::from(
        "| Ecosystem | Reads (coverage) | Advisories | Version rules | Checked against | Result |\n\
         |-----------|------------------|------------|---------------|-----------------|--------|\n",
    );
    for row in MATRIX {
        out.push_str(&format!(
            "| [{}](/fleetreach/docs/ecosystems/{}/) | {} | {} | {} | {} | {} |\n",
            row.name,
            row.page,
            reads_text(row, true),
            row.advisories,
            row.comparator,
            row.checked_against,
            row.result
        ));
    }
    out.push('\n');
    out.push_str(NOT_PLANNED);
    out.push('\n');
    out
}

fn table() -> String {
    let mut out = String::new();
    for row in MATRIX {
        out.push_str(row.name);
        out.push('\n');
        for (label, value) in [
            ("reads", reads_text(row, false)),
            ("advisories", row.advisories.to_string()),
            ("version rules", row.comparator.replace('`', "")),
            ("checked against", row.checked_against.replace('`', "")),
            ("result", row.result.to_string()),
        ] {
            out.push_str(&format!("  {label:<16}{value}\n"));
        }
    }
    out.push('\n');
    out.push_str(NOT_PLANNED);
    out.push('\n');
    out
}

pub fn run_ecosystems(args: &EcosystemsArgs) -> u8 {
    let text = match args.format {
        Format::Table => table(),
        Format::Markdown => markdown(),
        Format::Json => {
            let matrix = Matrix {
                schema: "fleetreach-ecosystems/1",
                ecosystems: MATRIX,
                not_planned: NOT_PLANNED,
            };
            match serde_json::to_string_pretty(&matrix) {
                Ok(json) => json + "\n",
                Err(e) => {
                    eprintln!("error: {e}");
                    return 2;
                }
            }
        }
    };
    print!("{text}");
    0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::config::Repo;
    use crate::orchestrate::{discover_lockfiles, plan_repo};
    use fleetreach_core::{Ecosystem, RepoId};

    fn ecosystem(page: &str) -> Option<Ecosystem> {
        Some(match page {
            "rust" => Ecosystem::Cargo,
            "go" => Ecosystem::Go,
            "npm" => Ecosystem::Npm,
            "pypi" => Ecosystem::Pypi,
            "rubygems" => Ecosystem::RubyGems,
            "packagist" => Ecosystem::Packagist,
            "nuget" => Ecosystem::NuGet,
            "maven" => Ecosystem::Maven,
            "github-actions" => Ecosystem::GitHubActions,
            "swift" => Ecosystem::Swift,
            "hex" => Ecosystem::Hex,
            "julia" => Ecosystem::Julia,
            _ => return None,
        })
    }

    #[test]
    fn every_listed_file_is_picked_up_by_the_scan() {
        let mut probed = 0;
        for row in MATRIX {
            for input in row.reads {
                if input.probe.is_empty() {
                    continue;
                }
                let eco = ecosystem(row.page).expect(row.page);
                let dir = tempfile::tempdir().unwrap();
                for (path, body) in input.probe {
                    let path = dir.path().join(path);
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    std::fs::write(path, body).unwrap();
                }
                let repo = Repo {
                    id: RepoId("r".to_string()),
                    path: dir.path().to_path_buf(),
                    glob: true,
                    glob_max_depth: 4,
                    vex_product_id: None,
                    ecosystem: None,
                };
                let found = if eco == Ecosystem::Cargo {
                    !discover_lockfiles(&repo).0.is_empty()
                } else {
                    plan_repo(&repo).units.iter().any(|u| u.ecosystem == eco)
                };
                assert!(found, "{} is not scanned as {}", input.file, row.name);
                probed += 1;
            }
        }
        assert!(probed >= 22, "{probed}");
    }

    #[test]
    fn coverage_uses_the_report_levels() {
        for row in MATRIX {
            for input in row.reads {
                assert!(
                    ["full", "direct-only", "partial"].iter().any(|level| input
                        .coverage
                        .split([' ', ';', ':'])
                        .next()
                        == Some(level)),
                    "{}: {}",
                    row.name,
                    input.coverage
                );
            }
        }
    }

    #[test]
    fn every_ecosystem_page_is_listed() {
        let pages = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../website/src/content/docs/docs/ecosystems");
        for entry in std::fs::read_dir(pages).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            let Some(page) = name.strip_suffix(".md") else {
                continue;
            };
            if page != "index" {
                assert!(
                    MATRIX.iter().any(|r| r.page == page),
                    "{page} not in MATRIX"
                );
            }
        }
    }
}
