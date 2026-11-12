//! Copyleft conflicts (spec 16, row 20): a runtime dependency whose license asks something of
//! the repo that uses it, judged with what `fleet.toml` says about that repo.
//!
//! Three rules, each about a license the dependency *requires*: every way to satisfy its
//! expression names it, so `MIT OR GPL-3.0-only` requires nothing and is never a conflict.
//!
//! - **network copyleft**: AGPL or SSPL in a repo whose exposure is `open`. Both ask that
//!   people using the software over a network can get its source, which a service on the
//!   internet triggers without ever distributing a binary.
//! - **copyleft in proprietary or permissive code**: GPL, AGPL, SSPL, OSL or EUPL in a repo
//!   declared `proprietary`, or one whose own license offers only permissive terms. Shipping
//!   the repo puts it under the dependency's terms. LGPL, MPL and other weak copyleft are left
//!   out: they bind the library, not the program that links it.
//! - **GPL-2.0-only incompatibility**: a repo that can only be GPL-2.0 using Apache-2.0,
//!   GPL-3.0, AGPL-3.0 or LGPL-3.0 code, which the FSF lists as incompatible with GPLv2.
//!
//! Dev-only packages are never shipped and never conflict. A package `[[settings.licenses.
//! exception]]` allows a license for does not conflict over that license. Whether code is
//! linked, vendored or run as a separate program is not known here, so a conflict is a
//! warning to look at by default (`conflicts = "warn"`), not a legal finding.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use spdx::{Expression, LicenseItem, LicenseReq, ParseMode};

use crate::licenses::{category, normalize, req_id, Category, Decision, Verdict};

/// What a repo's `[[repo]] license` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoLicense {
    /// `proprietary`, `LicenseRef-Proprietary` or npm's `UNLICENSED`.
    Proprietary,
    /// An SPDX expression, canonical.
    Spdx(String),
}

impl RepoLicense {
    /// Parse a `[[repo]] license` value.
    pub fn parse(s: &str) -> Result<RepoLicense, String> {
        let s = s.trim();
        if ["proprietary", "LicenseRef-Proprietary", "UNLICENSED"]
            .iter()
            .any(|p| p.eq_ignore_ascii_case(s))
        {
            return Ok(RepoLicense::Proprietary);
        }
        match normalize(&[s.to_string()]).and_then(|l| l.expression) {
            Some(expression) => Ok(RepoLicense::Spdx(expression)),
            None => Err(format!(
                "`{s}` is not an SPDX expression, `proprietary` or `UNLICENSED`"
            )),
        }
    }

    fn label(&self) -> &str {
        match self {
            RepoLicense::Proprietary => "proprietary",
            RepoLicense::Spdx(e) => e,
        }
    }
}

/// What the rules know about one repo.
#[derive(Debug, Clone, Default)]
pub struct RepoFacts {
    pub license: Option<RepoLicense>,
    /// Its exposure is `open` (internet-facing).
    pub open: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rule {
    NetworkCopyleft,
    CopyleftInProprietary,
    CopyleftInPermissive,
    Gpl2Incompatible,
}

impl Rule {
    pub fn label(self) -> &'static str {
        match self {
            Rule::NetworkCopyleft => "network copyleft",
            Rule::CopyleftInProprietary => "copyleft in proprietary code",
            Rule::CopyleftInPermissive => "copyleft in permissive code",
            Rule::Gpl2Incompatible => "GPL-2.0-only incompatible",
        }
    }
}

/// One conflict.
#[derive(Debug, Clone, Serialize)]
pub struct Conflict {
    pub repo: String,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    /// The dependency's license expression the rule read.
    pub license: String,
    /// The repo's own license, as `fleet.toml` gives it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_license: Option<String>,
    pub rule: Rule,
    pub verdict: Verdict,
    pub reason: String,
}

fn network(id: &str) -> bool {
    id.starts_with("AGPL-") || id.starts_with("SSPL-")
}

fn strong(id: &str) -> bool {
    ["GPL-", "AGPL-", "SSPL-", "OSL-", "EUPL-"]
        .iter()
        .any(|p| id.starts_with(p))
}

fn gpl2_incompatible(id: &str) -> bool {
    id == "Apache-2.0"
        || ["GPL-3.0", "AGPL-3.0", "LGPL-3.0"]
            .iter()
            .any(|p| id.starts_with(p))
}

/// The ids in `family` that `expression` requires: none when some way to satisfy it avoids
/// them all. `excepted` ids do not count.
fn required(
    expression: &Expression,
    family: fn(&str) -> bool,
    excepted: Option<&BTreeSet<String>>,
) -> Vec<String> {
    let counts = |id: &str| family(id) && !excepted.is_some_and(|e| e.contains(id));
    if expression.evaluate(|req| !counts(&req_id(req))) {
        return Vec::new();
    }
    let mut ids: Vec<String> = expression
        .requirements()
        .map(|r| req_id(&r.req))
        .filter(|id| counts(id))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// GPL-2.0 without `+` or `-or-later`.
fn gpl2_only(req: &LicenseReq) -> bool {
    match &req.license {
        LicenseItem::Spdx { id, or_later } => {
            !or_later && matches!(id.name, "GPL-2.0-only" | "GPL-2.0")
        }
        LicenseItem::Other(_) => false,
    }
}

fn permissive(req: &LicenseReq) -> bool {
    matches!(
        category(&req_id(req)),
        Category::Notice | Category::Unencumbered
    )
}

/// Every conflict between the repos' runtime packages and what the repos are. `verdict` is
/// `[settings.licenses] conflicts`; `allow` finds nothing.
pub fn find(
    decisions: &[Decision],
    repos: &BTreeMap<String, RepoFacts>,
    verdict: Verdict,
    exceptions: &BTreeMap<String, (BTreeSet<String>, String)>,
) -> Vec<Conflict> {
    if verdict == Verdict::Allow {
        return Vec::new();
    }
    let mut out = Vec::new();
    for d in decisions.iter().filter(|d| !d.dev) {
        let Some(facts) = repos.get(&d.repo) else {
            continue;
        };
        let declared = d
            .license
            .as_deref()
            .and_then(|l| normalize(&[l.to_string()]))
            .and_then(|l| l.expression);
        let Some(license) = declared.or_else(|| d.detected.clone()) else {
            continue;
        };
        let Ok(expression) = Expression::parse_mode(&license, ParseMode::LAX) else {
            continue;
        };
        let excepted = exceptions.get(&d.package).map(|(ids, _)| ids);
        let own = facts.license.as_ref();
        let own_expression = match own {
            Some(RepoLicense::Spdx(e)) => Expression::parse_mode(e, ParseMode::LAX).ok(),
            _ => None,
        };
        // A repo that is itself under the dependency's terms has nothing to conflict with.
        let own_requires = |family: fn(&str) -> bool| {
            own_expression
                .as_ref()
                .is_some_and(|e| !e.evaluate(|req| !family(&req_id(req))))
        };
        let push = |out: &mut Vec<Conflict>, rule: Rule, reason: String| {
            out.push(Conflict {
                repo: d.repo.clone(),
                ecosystem: d.ecosystem.clone(),
                package: d.package.clone(),
                version: d.version.clone(),
                license: license.clone(),
                repo_license: own.map(|l| l.label().to_string()),
                rule,
                verdict,
                reason,
            });
        };
        let ids = required(&expression, network, excepted);
        if facts.open && !ids.is_empty() && !own_requires(network) {
            let ids = ids.join(", ");
            push(
                &mut out,
                Rule::NetworkCopyleft,
                format!(
                    "requires {ids}, and the repo's exposure is open: users of the service over \
                     a network are owed its source"
                ),
            );
            continue;
        }
        let ids = required(&expression, strong, excepted);
        if !ids.is_empty() {
            let ids = ids.join(", ");
            match (own, &own_expression) {
                (Some(RepoLicense::Proprietary), _) => {
                    push(
                        &mut out,
                        Rule::CopyleftInProprietary,
                        format!(
                            "requires {ids}, and the repo is proprietary: distributing it puts \
                             it under {ids}"
                        ),
                    );
                    continue;
                }
                (Some(RepoLicense::Spdx(e)), Some(parsed))
                    if !own_requires(strong) && parsed.evaluate(permissive) =>
                {
                    push(
                        &mut out,
                        Rule::CopyleftInPermissive,
                        format!(
                            "requires {ids}, and the repo is licensed {e}: distributed with it, \
                             the repo is bound by {ids}"
                        ),
                    );
                    continue;
                }
                _ => {}
            }
        }
        let ids = required(&expression, gpl2_incompatible, excepted);
        if !ids.is_empty() {
            if let Some(parsed) = &own_expression {
                if !parsed.evaluate(|req| !gpl2_only(req)) {
                    let ids = ids.join(", ");
                    push(
                        &mut out,
                        Rule::Gpl2Incompatible,
                        format!(
                            "requires {ids}, which is incompatible with the repo's GPL-2.0-only"
                        ),
                    );
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn dep(repo: &str, name: &str, license: &str, dev: bool) -> Decision {
        Decision {
            repo: repo.into(),
            ecosystem: "npm".into(),
            package: name.into(),
            version: "1.0.0".into(),
            license: Some(license.into()),
            source: None,
            category: category(license),
            verdict: Verdict::Allow,
            reason: String::new(),
            dev,
            detected: None,
            undeclared: vec![],
        }
    }

    fn facts(license: Option<&str>, open: bool) -> RepoFacts {
        RepoFacts {
            license: license.map(|l| RepoLicense::parse(l).unwrap()),
            open,
        }
    }

    fn run(repo: RepoFacts, deps: &[(&str, &str, bool)]) -> Vec<(String, Rule)> {
        let decisions: Vec<Decision> = deps
            .iter()
            .map(|(name, license, dev)| dep("r", name, license, *dev))
            .collect();
        let repos = BTreeMap::from([("r".to_string(), repo)]);
        find(&decisions, &repos, Verdict::Warn, &BTreeMap::new())
            .into_iter()
            .map(|c| (c.package, c.rule))
            .collect()
    }

    #[test]
    fn repo_licenses_parse() {
        assert_eq!(
            RepoLicense::parse("Proprietary").unwrap(),
            RepoLicense::Proprietary
        );
        assert_eq!(
            RepoLicense::parse("UNLICENSED").unwrap(),
            RepoLicense::Proprietary
        );
        assert_eq!(
            RepoLicense::parse("MIT/Apache-2.0").unwrap(),
            RepoLicense::Spdx("MIT OR Apache-2.0".into())
        );
        assert!(RepoLicense::parse("our own terms").is_err());
    }

    #[test]
    fn agpl_conflicts_only_in_an_open_service_and_only_when_required() {
        let deps = [
            ("agpl", "AGPL-3.0-only", false),
            ("choice", "MIT OR AGPL-3.0-only", false),
            ("sspl", "SSPL-1.0", false),
            ("test-agpl", "AGPL-3.0-only", true),
        ];
        assert_eq!(
            run(facts(None, true), &deps),
            vec![
                ("agpl".into(), Rule::NetworkCopyleft),
                ("sspl".into(), Rule::NetworkCopyleft)
            ]
        );
        assert!(run(facts(None, false), &deps).is_empty());
        // An AGPL service may use AGPL code.
        assert!(run(facts(Some("AGPL-3.0-or-later"), true), &deps[..1]).is_empty());
    }

    #[test]
    fn strong_copyleft_conflicts_with_proprietary_and_permissive_repos() {
        let deps = [
            ("gpl", "GPL-3.0-only", false),
            ("lgpl", "LGPL-2.1-or-later", false),
            ("mpl", "MPL-2.0", false),
            ("eupl", "EUPL-1.2", false),
            ("dual", "GPL-2.0-only OR Apache-2.0", false),
        ];
        assert_eq!(
            run(facts(Some("proprietary"), false), &deps),
            vec![
                ("gpl".into(), Rule::CopyleftInProprietary),
                ("eupl".into(), Rule::CopyleftInProprietary)
            ]
        );
        assert_eq!(
            run(facts(Some("MIT OR Apache-2.0"), false), &deps),
            vec![
                ("gpl".into(), Rule::CopyleftInPermissive),
                ("eupl".into(), Rule::CopyleftInPermissive)
            ]
        );
        assert!(run(facts(Some("GPL-3.0-or-later"), false), &deps).is_empty());
        assert!(
            run(facts(None, false), &deps).is_empty(),
            "nothing declared"
        );
    }

    #[test]
    fn gpl2_only_repos_cannot_take_apache_or_gplv3() {
        let deps = [
            ("apache", "Apache-2.0", false),
            ("gpl3", "GPL-3.0-or-later", false),
            ("gpl2plus", "GPL-2.0-or-later", false),
            ("either", "MIT OR Apache-2.0", false),
            ("lgpl3", "LGPL-3.0-only", false),
        ];
        assert_eq!(
            run(facts(Some("GPL-2.0-only"), false), &deps),
            vec![
                ("apache".into(), Rule::Gpl2Incompatible),
                ("gpl3".into(), Rule::Gpl2Incompatible),
                ("lgpl3".into(), Rule::Gpl2Incompatible)
            ]
        );
        assert!(run(facts(Some("GPL-2.0-or-later"), false), &deps).is_empty());
        assert!(run(facts(Some("GPL-2.0+"), false), &deps).is_empty());
    }

    #[test]
    fn exceptions_and_allow_silence_conflicts() {
        let decisions = vec![dep("r", "gpl", "GPL-3.0-only", false)];
        let repos = BTreeMap::from([("r".to_string(), facts(Some("proprietary"), false))]);
        let exceptions = BTreeMap::from([(
            "gpl".to_string(),
            (
                BTreeSet::from(["GPL-3.0-only".to_string()]),
                "separate process".to_string(),
            ),
        )]);
        assert!(find(&decisions, &repos, Verdict::Warn, &exceptions).is_empty());
        assert!(find(&decisions, &repos, Verdict::Allow, &BTreeMap::new()).is_empty());
        let denied = find(&decisions, &repos, Verdict::Deny, &BTreeMap::new());
        assert_eq!(denied[0].verdict, Verdict::Deny);
        assert_eq!(denied[0].repo_license.as_deref(), Some("proprietary"));
    }
}
