//! `fleet.toml` validation: malformed config is always a typed error, never a
//! panic (§13).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fleetreach_cli::config::{Config, ConfigError, DEFAULT_GLOB_MAX_DEPTH};

fn base() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn parse(text: &str) -> Result<Config, ConfigError> {
    Config::from_str(text, &base(), "test.toml")
}

#[test]
fn parses_optional_ecosystem_override() {
    use fleetreach_core::Ecosystem;
    let cfg = parse(
        r#"
        [[repo]]
        id = "go"
        path = "repos/repo-vuln"
        ecosystem = "go"

        [[repo]]
        id = "rust"
        path = "repos/repo-vuln"
        ecosystem = "rust"

        [[repo]]
        id = "auto"
        path = "repos/repo-vuln"
        "#,
    )
    .expect("valid config");
    assert_eq!(cfg.repos[0].ecosystem, Some(Ecosystem::Go));
    assert_eq!(cfg.repos[1].ecosystem, Some(Ecosystem::Cargo)); // `rust` aliases cargo
    assert_eq!(cfg.repos[2].ecosystem, None); // absent -> auto-detect at scan time
}

#[test]
fn rejects_an_unknown_ecosystem() {
    let err = parse(
        r#"
        [[repo]]
        id = "x"
        path = "repos/repo-vuln"
        ecosystem = "haskell"
        "#,
    )
    .expect_err("unknown ecosystem rejected");
    assert!(matches!(err, ConfigError::Parse { .. }));
}

#[test]
fn accepts_pypi_and_python_ecosystem_aliases() {
    for eco in ["pypi", "python"] {
        let cfg = parse(&format!(
            r#"
            [[repo]]
            id = "x"
            path = "repos/repo-vuln"
            ecosystem = "{eco}"
            "#
        ))
        .unwrap_or_else(|e| panic!("`{eco}` should parse: {e:?}"));
        assert_eq!(
            cfg.repos[0].ecosystem,
            Some(fleetreach_core::Ecosystem::Pypi)
        );
    }
}

#[test]
fn accepts_rubygems_and_ruby_ecosystem_aliases() {
    for eco in ["rubygems", "ruby"] {
        let cfg = parse(&format!(
            r#"
            [[repo]]
            id = "x"
            path = "repos/repo-vuln"
            ecosystem = "{eco}"
            "#
        ))
        .unwrap_or_else(|e| panic!("`{eco}` should parse: {e:?}"));
        assert_eq!(
            cfg.repos[0].ecosystem,
            Some(fleetreach_core::Ecosystem::RubyGems)
        );
    }
}

#[test]
fn accepts_maven_ecosystem_aliases() {
    for eco in ["maven", "gradle", "java"] {
        let cfg = parse(&format!(
            r#"
            [[repo]]
            id = "x"
            path = "repos/repo-vuln"
            ecosystem = "{eco}"
            "#
        ))
        .unwrap_or_else(|e| panic!("`{eco}` should parse: {e:?}"));
        assert_eq!(
            cfg.repos[0].ecosystem,
            Some(fleetreach_core::Ecosystem::Maven)
        );
    }
}

#[test]
fn accepts_github_actions_ecosystem_aliases() {
    for eco in ["githubactions", "actions", "gha"] {
        let cfg = parse(&format!(
            r#"
            [[repo]]
            id = "x"
            path = "repos/repo-vuln"
            ecosystem = "{eco}"
            "#
        ))
        .unwrap_or_else(|e| panic!("`{eco}` should parse: {e:?}"));
        assert_eq!(
            cfg.repos[0].ecosystem,
            Some(fleetreach_core::Ecosystem::GitHubActions)
        );
    }
}

#[test]
fn accepts_hex_elixir_ecosystem_aliases() {
    for eco in ["hex", "elixir"] {
        let cfg = parse(&format!(
            r#"
            [[repo]]
            id = "x"
            path = "repos/repo-vuln"
            ecosystem = "{eco}"
            "#
        ))
        .unwrap_or_else(|e| panic!("`{eco}` should parse: {e:?}"));
        assert_eq!(
            cfg.repos[0].ecosystem,
            Some(fleetreach_core::Ecosystem::Hex)
        );
    }
}

#[test]
fn accepts_swift_ecosystem() {
    let cfg = parse(
        r#"
        [[repo]]
        id = "x"
        path = "repos/repo-vuln"
        ecosystem = "swift"
        "#,
    )
    .expect("`swift` should parse");
    assert_eq!(
        cfg.repos[0].ecosystem,
        Some(fleetreach_core::Ecosystem::Swift)
    );
}

#[test]
fn accepts_julia_ecosystem() {
    let cfg = parse(
        r#"
        [[repo]]
        id = "x"
        path = "repos/repo-vuln"
        ecosystem = "julia"
        "#,
    )
    .expect("`julia` should parse");
    assert_eq!(
        cfg.repos[0].ecosystem,
        Some(fleetreach_core::Ecosystem::Julia)
    );
}

#[test]
fn accepts_nuget_dotnet_ecosystem_aliases() {
    for eco in ["nuget", "dotnet"] {
        let cfg = parse(&format!(
            r#"
            [[repo]]
            id = "x"
            path = "repos/repo-vuln"
            ecosystem = "{eco}"
            "#
        ))
        .unwrap_or_else(|e| panic!("`{eco}` should parse: {e:?}"));
        assert_eq!(
            cfg.repos[0].ecosystem,
            Some(fleetreach_core::Ecosystem::NuGet)
        );
    }
}

#[test]
fn accepts_packagist_composer_php_ecosystem_aliases() {
    for eco in ["packagist", "composer", "php"] {
        let cfg = parse(&format!(
            r#"
            [[repo]]
            id = "x"
            path = "repos/repo-vuln"
            ecosystem = "{eco}"
            "#
        ))
        .unwrap_or_else(|e| panic!("`{eco}` should parse: {e:?}"));
        assert_eq!(
            cfg.repos[0].ecosystem,
            Some(fleetreach_core::Ecosystem::Packagist)
        );
    }
}

#[test]
fn accepts_a_valid_config_and_applies_glob_default() {
    let cfg = parse(
        r#"
        [fleet]

        [[repo]]
        id = "a"
        path = "repos/repo-vuln"

        [[repo]]
        id = "b"
        path = "repos/repo-glob"
        glob = true
        glob_max_depth = 2
        "#,
    )
    .expect("valid config");

    assert_eq!(cfg.repos.len(), 2);
    assert_eq!(cfg.repos[0].id.0, "a");
    assert!(!cfg.repos[0].glob);
    assert_eq!(cfg.repos[0].glob_max_depth, DEFAULT_GLOB_MAX_DEPTH); // unset -> default
    assert!(cfg.repos[1].glob);
    assert_eq!(cfg.repos[1].glob_max_depth, 2);
}

#[test]
fn rejects_unknown_fields() {
    let err = parse(
        r#"
        [[repo]]
        id = "a"
        path = "repos/repo-vuln"
        nonsense = true
        "#,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::Parse { .. }), "got {err:?}");
}

#[test]
fn rejects_missing_path() {
    let err = parse(
        r#"
        [[repo]]
        id = "a"
        path = "repos/does-not-exist"
        "#,
    )
    .unwrap_err();
    assert!(
        matches!(err, ConfigError::PathMissing { .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_duplicate_repo_id() {
    let err = parse(
        r#"
        [[repo]]
        id = "dup"
        path = "repos/repo-vuln"

        [[repo]]
        id = "dup"
        path = "repos/repo-warn"
        "#,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::DuplicateRepoId(id) if id == "dup"));
}

#[test]
fn rejects_empty_ignore_reason() {
    let err = parse(
        r#"
        [[settings.ignore]]
        id = "RUSTSEC-2020-0071"
        reason = "   "
        "#,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::EmptyIgnoreReason(id) if id == "RUSTSEC-2020-0071"));
}

#[test]
fn accepts_justified_ignore() {
    let cfg = parse(
        r#"
        [[settings.ignore]]
        id = "RUSTSEC-2020-0071"
        reason = "dev-dependency only"
        "#,
    )
    .expect("valid ignore");
    assert_eq!(cfg.ignores.len(), 1);
    assert_eq!(cfg.ignores[0].id, "RUSTSEC-2020-0071");
}

#[test]
fn parses_vex_settings_and_product_id() {
    let cfg = parse(
        r#"
        [settings.vex]
        author = "secteam@acme.example"
        role = "Document Creator"
        scope = "build"
        product_id_base = "https://acme.example/fleet/"

        [[repo]]
        id = "a"
        path = "repos/repo-vuln"
        vex_product_id = "pkg:cargo/core-lib@1.4.0"
        "#,
    )
    .expect("valid vex config");
    assert_eq!(cfg.vex.author.as_deref(), Some("secteam@acme.example"));
    assert_eq!(cfg.vex.role.as_deref(), Some("Document Creator"));
    assert_eq!(cfg.vex.scope, Some(fleetreach_report::VexScope::Build));
    assert_eq!(
        cfg.vex.product_id_base.as_deref(),
        Some("https://acme.example/fleet/")
    );
    assert_eq!(
        cfg.repos[0].vex_product_id.as_deref(),
        Some("pkg:cargo/core-lib@1.4.0")
    );
}

#[test]
fn vex_settings_default_to_empty() {
    let cfg = parse(
        r#"
        [[repo]]
        id = "a"
        path = "repos/repo-vuln"
        "#,
    )
    .expect("valid config");
    assert!(cfg.vex.author.is_none());
    assert!(cfg.vex.scope.is_none());
    assert!(cfg.repos[0].vex_product_id.is_none());
}

#[test]
fn rejects_invalid_vex_scope() {
    let err = parse(
        r#"
        [settings.vex]
        scope = "ephemeral"
        "#,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidVexScope(s) if s == "ephemeral"));
}

#[test]
fn accepts_approved_vex_assertion() {
    let cfg = parse(
        r#"
        [[settings.vex_assertion]]
        id            = "RUSTSEC-2020-0071"
        repo          = "core-lib"
        justification = "component_not_present"
        reason        = "dev-dependency only"
        approved_by   = "secteam"
        "#,
    )
    .expect("valid assertion");
    assert_eq!(cfg.vex_assertions.len(), 1);
    let a = &cfg.vex_assertions[0];
    assert_eq!(a.id, "RUSTSEC-2020-0071");
    assert_eq!(a.repo.as_ref().map(|r| r.0.as_str()), Some("core-lib"));
    assert_eq!(a.justification.as_deref(), Some("component_not_present"));
    assert_eq!(a.approved_by, "secteam");
}

#[test]
fn rejects_not_affected_assertion_without_approver() {
    let err = parse(
        r#"
        [[settings.vex_assertion]]
        id          = "RUSTSEC-2020-0071"
        reason      = "dev-dependency only"
        approved_by = "  "
        "#,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::EmptyAssertionApprover(id) if id == "RUSTSEC-2020-0071"));
}

#[test]
fn rejects_unknown_justification_label() {
    let err = parse(
        r#"
        [[settings.vex_assertion]]
        id            = "RUSTSEC-2020-0071"
        justification = "i_just_dont_think_it_applies"
        reason        = "trust me"
        approved_by   = "secteam"
        "#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidVexJustification { id, .. } if id == "RUSTSEC-2020-0071"
    ));
}
