//! Exposure context and SSVC deployer decisions (spec 08).
//!
//! Each vulnerable in-repo occurrence gets the four SSVC decision points: Exploitation from
//! the KEV/EPSS enrichment, Automatable from the advisory's CVSS vector, System Exposure and
//! Human Impact from the repo's context in `fleet.toml`. The published deployer table turns
//! them into an action. Two rules keep this fail-closed:
//!
//! - Without exploitation data no decision is made at all; guessing `none` would be a
//!   false-clean in priority form.
//! - Context a repo does not set falls back to `[settings.context.defaults]`, then to the
//!   most urgent values (`open`, `mission-failure`, `catastrophic`), and the repo is marked.
//!
//! A sound signal that the code cannot run (a phantom dependency or a `NotReachable`
//! verdict, the same signals that make VEX say `not_affected`) forces `defer`.

use std::collections::BTreeMap;

use fleetreach_core::ssvc::{
    self, Exploitation, Exposure, MissionImpact, Outcome, SafetyImpact, DEPLOYER_TABLE,
};
use fleetreach_core::{
    FleetReport, Occurrence, ReachVerdict, RepoContext, RepoId, SsvcDecision, SsvcReport,
    VulnFinding,
};

use crate::config::{Config, ContextFields};

/// What the scan knows about exploitation, beyond the per-finding KEV/EPSS fields.
#[derive(Debug, Clone, Copy)]
pub struct Inputs {
    /// KEV/EPSS enrichment ran, so a finding without a KEV entry is genuinely not in KEV.
    pub exploitation_known: bool,
    /// `[settings.ssvc] poc_epss`: EPSS at or above this counts as a public proof of concept.
    pub poc_epss: Option<f32>,
}

/// Fill `report.context` and `report.ssvc` from the config. Does nothing when no repo has any
/// context and no defaults are configured.
pub fn annotate(report: &mut FleetReport, config: &Config, inputs: Inputs) {
    let enabled = config.context_defaults.is_some()
        || config
            .context
            .values()
            .any(ContextFields::has_decision_points);
    let contexts: BTreeMap<RepoId, RepoContext> = config
        .repos
        .iter()
        .filter_map(|repo| {
            let own = config.context.get(&repo.id);
            if !enabled && own.is_none() {
                return None;
            }
            Some((repo.id.clone(), resolve(&repo.id, own, config, enabled)))
        })
        .collect();
    report.context = contexts.values().cloned().collect();
    if !enabled {
        return;
    }
    if !inputs.exploitation_known {
        report.ssvc = Some(SsvcReport {
            table: DEPLOYER_TABLE.to_string(),
            decisions: Vec::new(),
            not_computed: Some(
                "no exploitation data: run with --enrich, or --kev-file offline".to_string(),
            ),
        });
        return;
    }
    let mut decisions: Vec<SsvcDecision> = report
        .vulnerabilities
        .iter()
        .flat_map(|v| v.occurrences.iter().map(move |occ| (v, occ)))
        .filter_map(|(v, occ)| decide(v, occ, &contexts, inputs))
        .collect();
    decisions.sort_by(|a, b| {
        b.outcome
            .cmp(&a.outcome)
            .then_with(|| a.advisory_id.cmp(&b.advisory_id))
            .then_with(|| a.repo.cmp(&b.repo))
            .then_with(|| a.package.cmp(&b.package))
    });
    report.ssvc = Some(SsvcReport {
        table: DEPLOYER_TABLE.to_string(),
        decisions,
        not_computed: None,
    });
}

/// A repo's context with defaults applied. With SSVC enabled, anything still missing takes
/// the most urgent value and the repo is marked `fail_closed`.
fn resolve(
    repo: &RepoId,
    own: Option<&ContextFields>,
    config: &Config,
    enabled: bool,
) -> RepoContext {
    let empty = ContextFields::default();
    let own = own.unwrap_or(&empty);
    let defaults = config.context_defaults.as_ref().unwrap_or(&empty);
    let exposure = own.exposure.or(defaults.exposure);
    let mission_impact = own.mission_impact.or(defaults.mission_impact);
    let safety_impact = own.safety_impact.or(defaults.safety_impact);
    let fail_closed =
        enabled && (exposure.is_none() || mission_impact.is_none() || safety_impact.is_none());
    RepoContext {
        repo: repo.clone(),
        exposure: exposure.or(enabled.then_some(Exposure::Open)),
        mission_impact: mission_impact.or(enabled.then_some(MissionImpact::MissionFailure)),
        safety_impact: safety_impact.or(enabled.then_some(SafetyImpact::Catastrophic)),
        owner: own.owner.clone().or_else(|| defaults.owner.clone()),
        tags: if own.tags.is_empty() {
            defaults.tags.clone()
        } else {
            own.tags.clone()
        },
        fail_closed,
    }
}

/// The decision for one occurrence, or `None` for a toolchain advisory (no repo context) or
/// an occurrence that is not vulnerable.
fn decide(
    v: &VulnFinding,
    occ: &Occurrence,
    contexts: &BTreeMap<RepoId, RepoContext>,
    inputs: Inputs,
) -> Option<SsvcDecision> {
    let Occurrence::InRepo {
        repo,
        package,
        installed,
        active,
        ..
    } = occ
    else {
        return None;
    };
    if !occ.is_vulnerable() {
        return None;
    }
    let ctx = contexts.get(repo)?;
    let (exposure, mission, safety) = (ctx.exposure?, ctx.mission_impact?, ctx.safety_impact?);

    let mut why: Vec<String> = Vec::new();
    let exploitation = if v.exploit.kev {
        why.push("in CISA KEV".to_string());
        Exploitation::Active
    } else if let (Some(epss), Some(min)) = (v.exploit.epss, inputs.poc_epss) {
        if epss >= min {
            why.push(format!("EPSS {:.0}% >= poc_epss", epss * 100.0));
            Exploitation::PublicPoc
        } else {
            Exploitation::None
        }
    } else {
        Exploitation::None
    };
    let automatable = ssvc::automatable(v.cvss_vector.as_deref());
    if v.cvss_vector.is_none() {
        why.push("no CVSS vector, automatable assumed".to_string());
    }
    if ctx.fail_closed {
        why.push("repo context incomplete, most urgent values used".to_string());
    }
    let human_impact = ssvc::human_impact(safety, mission);
    let table = ssvc::deployer_outcome(exploitation, exposure, automatable, human_impact);

    let not_running = if *active == Some(false) {
        Some("not_built: optional dependency is never compiled")
    } else if matches!(
        v.reachability.as_ref().map(|r| &r.verdict),
        Some(ReachVerdict::NotReachable)
    ) {
        Some("not_reachable: no path to the vulnerable code")
    } else {
        None
    };
    let outcome = match not_running {
        Some(reason) => {
            why.insert(0, format!("{reason} (table said {table})"));
            Outcome::Defer
        }
        None => table,
    };

    Some(SsvcDecision {
        advisory_id: v.advisory_id.clone(),
        repo: repo.clone(),
        package: package.clone(),
        installed: installed.to_string(),
        exploitation,
        exposure,
        automatable,
        human_impact,
        outcome,
        vector: ssvc::vector(exploitation, exposure, automatable, human_impact),
        rationale: why.join("; "),
        owner: ctx.owner.clone(),
    })
}

/// Whether any decision is at or above `threshold` (the `--fail-on-ssvc` gate).
#[must_use]
pub fn gate_hit(report: &FleetReport, threshold: Outcome) -> bool {
    report
        .ssvc
        .as_ref()
        .is_some_and(|s| s.decisions.iter().any(|d| d.outcome >= threshold))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::path::Path;

    use super::*;

    fn config(toml: &str) -> Config {
        Config::from_str(toml, Path::new(env!("CARGO_MANIFEST_DIR")), "fleet.toml").unwrap()
    }

    /// One KEV finding on `pkg 1.0.0` in repo `a` with an automatable vector, plus `extra`
    /// fields merged into the finding and the occurrence.
    fn report(finding: serde_json::Value, occurrence: serde_json::Value) -> FleetReport {
        let mut v = serde_json::json!({
            "advisory_id": "GHSA-test", "aliases": [], "title": "t", "severity": "critical",
            "url": null, "kev": true,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "occurrences": [],
        });
        let mut occ = serde_json::json!({
            "kind": "in_repo", "repo": "a", "package": "pkg", "installed": "1.0.0",
            "patched": [">=1.0.1"], "dependency_kind": "direct",
        });
        for (target, extra) in [(&mut v, finding), (&mut occ, occurrence)] {
            for (k, val) in extra.as_object().unwrap() {
                target[k] = val.clone();
            }
        }
        v["occurrences"] = serde_json::json!([occ, {
            "kind": "toolchain", "channel": "stable", "installed": null, "patched": [],
        }]);
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "provenance": {
                "tool_version": "t", "rustsec_crate_version": "t", "db_commit": null,
                "db_timestamp": null, "host_os": "t", "host_arch": "t", "generated_at": "t",
            },
            "summary": {
                "repos_scanned": 1, "repos_errored": 0, "vuln_count": 1, "warn_count": 0,
                "max_severity": "critical", "stale_ignores": [],
            },
            "vulnerabilities": [v], "warnings": [], "outcomes": [],
        }))
        .unwrap()
    }

    const OPEN: &str = r#"
        [[repo]]
        id = "a"
        path = "."
        exposure = "open"
        mission_impact = "mission-failure"
        safety_impact = "negligible"
    "#;

    const KNOWN: Inputs = Inputs {
        exploitation_known: true,
        poc_epss: None,
    };

    fn decide_one(cfg: &str, report: &mut FleetReport, inputs: Inputs) -> SsvcDecision {
        annotate(report, &config(cfg), inputs);
        let decisions = &report.ssvc.as_ref().unwrap().decisions;
        assert_eq!(decisions.len(), 1, "toolchain occurrences get no decision");
        decisions[0].clone()
    }

    #[test]
    fn sound_not_reachable_and_phantom_force_defer() {
        let unreachable = serde_json::json!({ "reachability": {
            "verdict": { "kind": "not_reachable" }, "config": "c", "engine": "static-mir-rta",
        }});
        let d = decide_one(OPEN, &mut report(unreachable, serde_json::json!({})), KNOWN);
        assert_eq!(d.outcome, Outcome::Defer);
        assert!(d.rationale.starts_with("not_reachable"), "{}", d.rationale);
        assert!(d.rationale.contains("table said immediate"));

        let phantom = serde_json::json!({ "active": false });
        let d = decide_one(OPEN, &mut report(serde_json::json!({}), phantom), KNOWN);
        assert_eq!(d.outcome, Outcome::Defer);
        assert!(d.rationale.starts_with("not_built"));
    }

    #[test]
    fn unknown_reachability_never_changes_the_outcome() {
        let unknown = serde_json::json!({ "reachability": {
            "verdict": { "kind": "unknown", "reason": "r" }, "config": "c", "engine": "e",
        }});
        let d = decide_one(OPEN, &mut report(unknown, serde_json::json!({})), KNOWN);
        assert_eq!(d.outcome, Outcome::Immediate);
    }

    #[test]
    fn defaults_fill_what_a_repo_does_not_set() {
        let cfg = r#"
            [settings.context.defaults]
            exposure = "controlled"
            mission_impact = "degraded"
            safety_impact = "negligible"
            owner = "platform"

            [[repo]]
            id = "a"
            path = "."
            exposure = "small"
        "#;
        let mut r = report(serde_json::json!({ "kev": false }), serde_json::json!({}));
        let d = decide_one(cfg, &mut r, KNOWN);
        assert_eq!(d.vector, "E:N/X:S/A:Y/HI:L");
        assert_eq!(d.outcome, Outcome::Defer);
        assert_eq!(d.owner.as_deref(), Some("platform"));
        assert!(!r.context[0].fail_closed);
    }

    #[test]
    fn poc_epss_is_opt_in() {
        let epss = || {
            report(
                serde_json::json!({ "kev": false, "epss": 0.6 }),
                serde_json::json!({}),
            )
        };
        let d = decide_one(OPEN, &mut epss(), KNOWN);
        assert_eq!(d.exploitation, Exploitation::None);
        let inputs = Inputs {
            exploitation_known: true,
            poc_epss: Some(0.5),
        };
        let d = decide_one(OPEN, &mut epss(), inputs);
        assert_eq!(d.exploitation, Exploitation::PublicPoc);
        assert!(d.rationale.contains("EPSS 60%"));
    }

    #[test]
    fn owner_alone_lists_context_without_turning_ssvc_on() {
        let cfg = "[[repo]]\nid = \"a\"\npath = \".\"\nowner = \"team\"\n";
        let mut r = report(serde_json::json!({}), serde_json::json!({}));
        annotate(&mut r, &config(cfg), KNOWN);
        assert!(r.ssvc.is_none());
        assert_eq!(r.context[0].owner.as_deref(), Some("team"));
        assert_eq!(r.context[0].exposure, None);
    }
}
