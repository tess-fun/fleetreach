//! CISA Vulnrichment (spec 08, phase 4): CISA's own SSVC Exploitation and Automatable
//! assessments, published per CVE at <https://github.com/cisagov/vulnrichment>.
//!
//! When CISA has assessed a CVE, its values are better evidence than the proxies fleetreach
//! derives (KEV membership, the CVSS vector), so they are used where present. They can only
//! raise Exploitation (a KEV entry stays `active`), and they replace the CVSS-derived
//! Automatable. Records are fetched under `--enrich` (each CVE id is sent to GitHub, as EPSS
//! already sends them to FIRST) and cached for a day, or read from a local clone with
//! `--vulnrichment-dir`.

use std::collections::BTreeMap;
use std::path::Path;

use fleetreach_core::ssvc::{Automatable, Exploitation};
use serde::{Deserialize, Serialize};

/// CISA's assessment of one CVE.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CisaSsvc {
    pub exploitation: Option<Exploitation>,
    pub automatable: Option<Automatable>,
}

/// CVE id to CISA's assessment, for the CVEs CISA has assessed.
pub type Vulnrichment = BTreeMap<String, CisaSsvc>;

/// The record's path in the repository: `2024/3xxx/CVE-2024-3400.json`.
#[must_use]
pub fn record_path(cve: &str) -> Option<String> {
    if !crate::enrich::is_valid_cve(cve) {
        return None;
    }
    let rest = cve.strip_prefix("CVE-")?;
    let (year, seq) = rest.split_once('-')?;
    let bucket = seq.parse::<u64>().ok()? / 1000;
    Some(format!("{year}/{bucket}xxx/{cve}.json"))
}

/// Read CISA's SSVC values from a record (the `CISA-ADP` container's `ssvc` metric). `None`
/// when the record carries no SSVC assessment.
#[must_use]
pub fn parse(body: &str) -> Option<CisaSsvc> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let adps = value.pointer("/containers/adp")?.as_array()?;
    let options = adps
        .iter()
        .filter(|adp| {
            adp.pointer("/providerMetadata/shortName")
                .and_then(|s| s.as_str())
                == Some("CISA-ADP")
        })
        .flat_map(|adp| {
            adp.get("metrics")
                .and_then(|m| m.as_array())
                .into_iter()
                .flatten()
        })
        .find(|m| m.pointer("/other/type").and_then(|t| t.as_str()) == Some("ssvc"))?
        .pointer("/other/content/options")?
        .as_array()?;
    let value_of = |key: &str| {
        options.iter().find_map(|o| {
            o.get(key)
                .and_then(|v| v.as_str())
                .map(|v| v.trim().to_ascii_lowercase())
        })
    };
    let exploitation = value_of("Exploitation").and_then(|v| match v.as_str() {
        "none" => Some(Exploitation::None),
        "poc" | "public poc" | "public-poc" => Some(Exploitation::PublicPoc),
        "active" => Some(Exploitation::Active),
        _ => None,
    });
    let automatable = value_of("Automatable").and_then(|v| match v.as_str() {
        "no" => Some(Automatable::No),
        "yes" => Some(Automatable::Yes),
        _ => None,
    });
    (exploitation.is_some() || automatable.is_some()).then_some(CisaSsvc {
        exploitation,
        automatable,
    })
}

/// Read the records for `cves` from a local clone of the repository.
#[must_use]
pub fn from_dir(dir: &Path, cves: &[String]) -> Vulnrichment {
    cves.iter()
        .filter_map(|cve| {
            let body = std::fs::read_to_string(dir.join(record_path(cve)?)).ok()?;
            Some((cve.clone(), parse(&body)?))
        })
        .collect()
}

/// Fetch the records for `cves` from GitHub, best-effort: a CVE CISA has not assessed (a
/// 404) is cached as such, a failed request is skipped and retried next run.
#[cfg(feature = "network")]
#[must_use]
pub fn fetch(cves: &[String]) -> Vulnrichment {
    use rayon::prelude::*;

    const BASE: &str = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop";
    let cache = crate::osvdb::private_subdir("vulnrichment");
    let lookups: Vec<(String, Option<CisaSsvc>)> = cves
        .par_iter()
        .filter_map(|cve| {
            let path = record_path(cve)?;
            if let Some(hit) = cache.as_deref().and_then(|dir| cache::read(dir, cve)) {
                return Some((cve.clone(), hit));
            }
            let found = crate::enrich::http_get_optional(&format!("{BASE}/{path}")).ok()?;
            let assessed = found.as_deref().and_then(parse);
            if let Some(dir) = cache.as_deref() {
                cache::write(dir, cve, assessed);
            }
            Some((cve.clone(), assessed))
        })
        .collect();
    lookups
        .into_iter()
        .filter_map(|(cve, assessed)| Some((cve, assessed?)))
        .collect()
}

#[cfg(feature = "network")]
mod cache {
    use std::path::Path;

    use super::CisaSsvc;

    /// A day: CISA updates Exploitation as evidence appears.
    const TTL: u64 = 86_400;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Entry {
        assessed: Option<CisaSsvc>,
        fetched_unix: u64,
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    /// `Some(assessment)` for a fresh entry (the assessment itself may be `None`: CISA has
    /// none), `None` when there is no fresh entry.
    pub(super) fn read(dir: &Path, cve: &str) -> Option<Option<CisaSsvc>> {
        let text = std::fs::read_to_string(dir.join(format!("{cve}.json"))).ok()?;
        let entry: Entry = serde_json::from_str(&text).ok()?;
        (now().saturating_sub(entry.fetched_unix) < TTL).then_some(entry.assessed)
    }

    pub(super) fn write(dir: &Path, cve: &str, assessed: Option<CisaSsvc>) {
        if crate::osvdb::create_private_dir(dir).is_err() {
            return;
        }
        let entry = Entry {
            assessed,
            fetched_unix: now(),
        };
        if let Ok(json) = serde_json::to_string(&entry) {
            let _ = std::fs::write(dir.join(format!("{cve}.json")), json);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn record_paths_bucket_by_thousands() {
        assert_eq!(
            record_path("CVE-2024-3400").as_deref(),
            Some("2024/3xxx/CVE-2024-3400.json")
        );
        assert_eq!(
            record_path("CVE-2021-44228").as_deref(),
            Some("2021/44xxx/CVE-2021-44228.json")
        );
        assert_eq!(
            record_path("CVE-2023-0001").as_deref(),
            Some("2023/0xxx/CVE-2023-0001.json")
        );
        assert_eq!(record_path("GHSA-xxxx-yyyy-zzzz"), None);
        assert_eq!(record_path("CVE-2024-../../etc"), None);
    }

    fn record(options: &str) -> String {
        format!(
            r#"{{"containers": {{"cna": {{}}, "adp": [
                {{"providerMetadata": {{"shortName": "CVE"}}, "metrics": []}},
                {{"providerMetadata": {{"shortName": "CISA-ADP"}}, "metrics": [
                    {{"other": {{"type": "kev", "content": {{}}}}}},
                    {{"other": {{"type": "ssvc", "content": {{"options": {options}}}}}}}
                ]}}
            ]}}}}"#
        )
    }

    #[test]
    fn parses_cisas_ssvc_options() {
        let body = record(
            r#"[{"Exploitation": "poc"}, {"Automatable": "no"}, {"Technical Impact": "total"}]"#,
        );
        assert_eq!(
            parse(&body),
            Some(CisaSsvc {
                exploitation: Some(Exploitation::PublicPoc),
                automatable: Some(Automatable::No),
            })
        );
        let body = record(r#"[{"Exploitation": "active"}, {"Automatable": "yes"}]"#);
        assert_eq!(
            parse(&body).unwrap().exploitation,
            Some(Exploitation::Active)
        );
    }

    #[test]
    fn a_record_without_an_assessment_is_none() {
        assert_eq!(parse(r#"{"containers": {"cna": {}}}"#), None);
        assert_eq!(parse(&record(r#"[{"Technical Impact": "partial"}]"#)), None);
        assert_eq!(parse("not json"), None);
    }

    /// Live: needs the network. `cargo test --features network -- --ignored vulnrichment`.
    #[cfg(feature = "network")]
    #[test]
    #[ignore = "fetches from GitHub"]
    fn fetches_a_real_record() {
        let got = fetch(&["CVE-2024-3400".into(), "CVE-2099-0001".into()]);
        assert_eq!(
            got.get("CVE-2024-3400"),
            Some(&CisaSsvc {
                exploitation: Some(Exploitation::Active),
                automatable: Some(Automatable::Yes),
            })
        );
        assert!(!got.contains_key("CVE-2099-0001"));
    }

    #[test]
    fn reads_a_local_clone() {
        let dir = std::env::temp_dir().join("fleetreach_vulnrichment_test");
        std::fs::create_dir_all(dir.join("2024/3xxx")).unwrap();
        std::fs::write(
            dir.join("2024/3xxx/CVE-2024-3400.json"),
            record(r#"[{"Exploitation": "active"}, {"Automatable": "yes"}]"#),
        )
        .unwrap();
        let got = from_dir(&dir, &["CVE-2024-3400".into(), "CVE-2024-3401".into()]);
        assert_eq!(got.len(), 1);
        assert_eq!(got["CVE-2024-3400"].automatable, Some(Automatable::Yes));
    }
}
