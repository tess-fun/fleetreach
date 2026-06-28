//! Exploit-risk enrichment from external feeds: the CISA Known Exploited
//! Vulnerabilities (KEV) catalog, FIRST's EPSS scores, and NVD CVSS severity.
//!
//! This crosses the lockfile/rustsec trust boundary into external HTTP feeds, so
//! it is **opt-in** (`--enrich`, or implied by `--fail-on-kev`/`--min-epss`) and
//! best-effort. Every feed is authoritative, structured JSON, parsed-not-trusted.
//! `--kev-file`/`--epss-file` use local copies for offline/CI use.
//!
//! Advisories are matched by their CVE aliases: KEV, EPSS, and NVD are keyed by
//! CVE.
//!
//! NVD CVSS is a **severity backfill**: RustSec advisories for vendored C
//! libraries (e.g. `openssl-src`) carry no CVSS of their own, so they scan as
//! `unknown` even when the underlying CVE is HIGH (RUSTSEC-2022-0014 =
//! CVE-2022-0778, CVSS 7.5). When a finding is `unknown` but has a CVE alias, we
//! pull the CVSS base score from NVD and fill the real severity. An optional
//! `NVD_API_KEY` env var raises NVD's rate limit.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fleetreach_core::{Severity, VulnFinding};

/// CVE → exploit signals, used to annotate findings.
#[derive(Debug, Default, Clone)]
pub struct Enrichment {
    /// CVE ids present in the CISA KEV catalog.
    pub kev: BTreeSet<String>,
    /// CVE → EPSS probability (0.0–1.0).
    pub epss: BTreeMap<String, f32>,
    /// CVE → CVSS base score (0.0–10.0) recovered from NVD, used to backfill the
    /// severity *and* the numeric score of advisories that carry no CVSS of their
    /// own. Empty on the offline (`*_file`) path.
    pub cvss: BTreeMap<String, f32>,
}

impl Enrichment {
    /// Fetch over the network: the full KEV catalog, EPSS for `cves`, and NVD
    /// CVSS scores for `backfill_cves` (the CVE aliases of findings that scan
    /// as `unknown`). NVD lookups are best-effort and never abort enrichment.
    /// Requires the `network` feature; otherwise use [`from_files`](Self::from_files).
    #[cfg(feature = "network")]
    pub fn fetch(cves: &[String], backfill_cves: &[String]) -> Result<Self, String> {
        Ok(Self {
            kev: parse_kev(&net::http_get(net::KEV_URL)?)?,
            epss: net::fetch_epss(cves)?,
            cvss: net::fetch_nvd_scores(backfill_cves),
        })
    }

    /// Load from local files (offline): KEV catalog JSON and/or EPSS CSV
    /// (`cve,epss,…`). A `None` path contributes no data. The NVD CVSS
    /// backfill is network-only, so it is empty here.
    pub fn from_files(kev_path: Option<&Path>, epss_path: Option<&Path>) -> Result<Self, String> {
        let kev = match kev_path {
            Some(p) => parse_kev(&read(p)?)?,
            None => BTreeSet::new(),
        };
        let epss = match epss_path {
            Some(p) => parse_epss_csv(&read(p)?),
            None => BTreeMap::new(),
        };
        Ok(Self {
            kev,
            epss,
            cvss: BTreeMap::new(),
        })
    }

    /// Annotate each finding from its CVE aliases: `kev` if any alias is in the
    /// catalog, `epss` to the maximum score across its aliases. For findings
    /// that scan as `unknown`, backfill both the severity and the numeric CVSS
    /// score from the worst NVD score across its aliases (never downgrading a
    /// severity the advisory already carries).
    pub fn apply(&self, findings: &mut [VulnFinding]) {
        for finding in findings {
            let cves: Vec<&String> = finding
                .aliases
                .iter()
                .filter(|a| a.starts_with("CVE-"))
                .collect();
            finding.exploit.kev = cves.iter().any(|c| self.kev.contains(*c));
            finding.exploit.epss = cves
                .iter()
                .filter_map(|c| self.epss.get(*c).copied())
                .fold(None, |acc, v| Some(acc.map_or(v, |a: f32| a.max(v))));

            if finding.severity == Severity::Unknown {
                let worst = cves
                    .iter()
                    .filter_map(|c| self.cvss.get(*c).copied())
                    .fold(None, |acc, v| Some(acc.map_or(v, |a: f32| a.max(v))));
                if let Some(score) = worst {
                    let sev = severity_from_score(f64::from(score));
                    if sev > Severity::Unknown {
                        finding.severity = sev;
                        finding.cvss_score = Some(score);
                    }
                }
            }
        }
    }
}

/// Re-rank by exploit risk: KEV first, then EPSS desc, then severity desc, then
/// id — the action queue.
pub fn rank(findings: &mut [VulnFinding]) {
    findings.sort_by(|a, b| {
        let ae = a.exploit.epss.unwrap_or(-1.0);
        let be = b.exploit.epss.unwrap_or(-1.0);
        b.exploit
            .kev
            .cmp(&a.exploit.kev)
            .then(be.partial_cmp(&ae).unwrap_or(Ordering::Equal))
            .then(b.severity.cmp(&a.severity))
            .then(a.advisory_id.cmp(&b.advisory_id))
    });
}

/// Map a CVSS base score (0.0–10.0) to a qualitative severity per the CVSS v3
/// bands. A 0.0 score (CVSS "None") stays `Unknown`, matching how an absent
/// score is treated in `scan::map_severity`.
fn severity_from_score(score: f64) -> Severity {
    match score {
        s if s >= 9.0 => Severity::Critical,
        s if s >= 7.0 => Severity::High,
        s if s >= 4.0 => Severity::Medium,
        s if s > 0.0 => Severity::Low,
        _ => Severity::Unknown,
    }
}

fn parse_kev(body: &str) -> Result<BTreeSet<String>, String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("KEV JSON: {e}"))?;
    let entries = value
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or("KEV JSON missing `vulnerabilities` array")?;
    Ok(entries
        .iter()
        .filter_map(|e| e.get("cveID").and_then(|c| c.as_str()))
        .map(String::from)
        .collect())
}

/// A well-formed CVE id (`CVE-YYYY-NNNN`, 4+ digit sequence). Advisory aliases are
/// DB-supplied and get interpolated into KEV/EPSS/NVD request URLs, so validate them
/// strictly (not just a `CVE-` prefix) to prevent query-parameter injection from a
/// crafted alias like `CVE-1&inject=1`. Only the network feature builds the request
/// URLs, so this is gated with it.
#[cfg(feature = "network")]
pub(crate) fn is_valid_cve(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("CVE-") else {
        return false;
    };
    let mut parts = rest.splitn(2, '-');
    let year = parts.next().unwrap_or_default();
    let seq = parts.next().unwrap_or_default();
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && seq.len() >= 4
        && seq.bytes().all(|b| b.is_ascii_digit())
}

/// Parse the bulk EPSS CSV (`cve,epss,percentile`), skipping comment/header lines.
fn parse_epss_csv(body: &str) -> BTreeMap<String, f32> {
    let mut out = BTreeMap::new();
    for line in body.lines() {
        if line.starts_with('#') || line.starts_with("cve") {
            continue;
        }
        let mut parts = line.split(',');
        if let (Some(cve), Some(score)) = (parts.next(), parts.next()) {
            if let Ok(score) = score.trim().parse::<f32>() {
                out.insert(cve.trim().to_string(), score);
            }
        }
    }
    out
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

/// All HTTP-fetching enrichment, gated as a unit behind the `network` feature so
/// the default build is pure-Rust (no `ureq`/rustls). The parsing/ranking above is
/// always available; only the live KEV/EPSS/NVD I/O lives here.
#[cfg(feature = "network")]
mod net {
    use std::collections::BTreeMap;
    use std::sync::OnceLock;
    use std::time::Duration;

    pub(super) const KEV_URL: &str =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    const EPSS_API: &str = "https://api.first.org/data/v1/epss";
    const NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    /// A shared HTTP agent with explicit connect/read/write/overall timeouts, so a
    /// slow or stalled feed (a slowloris-style dribble) cannot hang the whole scan
    /// indefinitely. Built once; reused across all enrichment requests.
    fn agent() -> &'static ureq::Agent {
        static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
        AGENT.get_or_init(|| {
            ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout_read(Duration::from_secs(30))
                .timeout_write(Duration::from_secs(30))
                .timeout(Duration::from_secs(60))
                .build()
        })
    }

    pub(super) fn http_get(url: &str) -> Result<String, String> {
        agent()
            .get(url)
            .call()
            .map_err(|e| format!("GET {url}: {e}"))?
            .into_string()
            .map_err(|e| format!("reading {url}: {e}"))
    }

    pub(super) fn fetch_epss(cves: &[String]) -> Result<BTreeMap<String, f32>, String> {
        let mut out = BTreeMap::new();
        let cve_ids: Vec<&str> = cves
            .iter()
            .filter(|c| super::is_valid_cve(c))
            .map(String::as_str)
            .collect();
        // Chunk to keep request URLs bounded.
        for chunk in cve_ids.chunks(100) {
            if chunk.is_empty() {
                continue;
            }
            let url = format!("{EPSS_API}?cve={}", chunk.join(","));
            merge_epss_json(&http_get(&url)?, &mut out)?;
        }
        Ok(out)
    }

    fn merge_epss_json(body: &str, out: &mut BTreeMap<String, f32>) -> Result<(), String> {
        let value: serde_json::Value =
            serde_json::from_str(body).map_err(|e| format!("EPSS JSON: {e}"))?;
        if let Some(rows) = value.get("data").and_then(|d| d.as_array()) {
            for row in rows {
                if let (Some(cve), Some(score)) = (
                    row.get("cve").and_then(|c| c.as_str()),
                    row.get("epss").and_then(|s| s.as_str()),
                ) {
                    if let Ok(score) = score.parse::<f32>() {
                        out.insert(cve.to_string(), score);
                    }
                }
            }
        }
        Ok(())
    }

    /// Best-effort: fetch CVSS base scores from NVD for `cves`. Used to backfill the
    /// severity and numeric score of advisories whose RustSec entry carries no CVSS.
    /// Per-CVE failures are skipped silently — the finding simply stays `unknown`,
    /// as it would without enrichment, so there is no regression. NVD's public API
    /// allows one CVE per request and rate-limits anonymous callers, so we space the
    /// requests out; an `NVD_API_KEY` env var raises the limit.
    pub(super) fn fetch_nvd_scores(cves: &[String]) -> BTreeMap<String, f32> {
        let mut out = BTreeMap::new();
        let api_key = std::env::var("NVD_API_KEY").ok();
        let cve_ids: Vec<&String> = cves.iter().filter(|c| super::is_valid_cve(c)).collect();
        for (i, cve) in cve_ids.iter().enumerate() {
            // Stay under NVD's anonymous rate limit (5 requests / 30s); a key lifts
            // it to 50, so a shorter delay suffices.
            if i > 0 {
                let delay = if api_key.is_some() { 700 } else { 6000 };
                std::thread::sleep(Duration::from_millis(delay));
            }
            let url = format!("{NVD_API}?cveId={cve}");
            if let Ok(body) = nvd_get(&url, api_key.as_deref()) {
                if let Some(score) = parse_nvd_score(&body, cve) {
                    out.insert((*cve).clone(), score);
                }
            }
        }
        out
    }

    fn nvd_get(url: &str, api_key: Option<&str>) -> Result<String, String> {
        let mut req = agent().get(url);
        if let Some(key) = api_key {
            req = req.set("apiKey", key);
        }
        req.call()
            .map_err(|e| format!("GET {url}: {e}"))?
            .into_string()
            .map_err(|e| format!("reading {url}: {e}"))
    }

    /// Pull the best available CVSS base score for `cve` from an NVD 2.0 response.
    /// Prefers the newest CVSS version present (v4.0, then v3.1, v3.0, v2); the
    /// `baseScore` lives under `cvssData` in every version.
    pub(super) fn parse_nvd_score(body: &str, cve: &str) -> Option<f32> {
        let value: serde_json::Value = serde_json::from_str(body).ok()?;
        let metrics = value
            .get("vulnerabilities")?
            .as_array()?
            .iter()
            .find(|v| v.pointer("/cve/id").and_then(|id| id.as_str()) == Some(cve))
            .and_then(|v| v.pointer("/cve/metrics"))?;
        [
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ]
        .iter()
        .find_map(|key| {
            metrics
                .get(key)
                .and_then(|m| m.as_array())
                .and_then(|arr| arr.first())
                .and_then(|m| m.pointer("/cvssData/baseScore"))
                .and_then(serde_json::Value::as_f64)
        })
        .map(|s| s as f32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A trimmed NVD 2.0 response, shaped like the real CVE-2022-0778 payload.
    #[cfg(feature = "network")]
    const NVD_BODY: &str = r#"{
      "vulnerabilities": [{
        "cve": {
          "id": "CVE-2022-0778",
          "metrics": {
            "cvssMetricV31": [{ "cvssData": { "baseScore": 7.5 } }],
            "cvssMetricV2": [{ "cvssData": { "baseScore": 5.0 } }]
          }
        }
      }]
    }"#;

    #[cfg(feature = "network")]
    #[test]
    fn parses_nvd_score_prefers_v31() {
        assert_eq!(net::parse_nvd_score(NVD_BODY, "CVE-2022-0778"), Some(7.5));
    }

    #[cfg(feature = "network")]
    #[test]
    fn nvd_score_falls_back_to_older_cvss_versions() {
        let body = r#"{"vulnerabilities":[{"cve":{"id":"CVE-1","metrics":{
            "cvssMetricV2":[{"cvssData":{"baseScore":9.1}}]}}}]}"#;
        assert_eq!(net::parse_nvd_score(body, "CVE-1"), Some(9.1));
    }

    #[cfg(feature = "network")]
    #[test]
    fn nvd_score_reads_cvss_v40() {
        // Newest entries (e.g. CVE-2025-24898) carry only a v4.0 metric.
        let body = r#"{"vulnerabilities":[{"cve":{"id":"CVE-1","metrics":{
            "cvssMetricV40":[{"cvssData":{"baseScore":6.3}}]}}}]}"#;
        assert_eq!(net::parse_nvd_score(body, "CVE-1"), Some(6.3));
    }

    #[cfg(feature = "network")]
    #[test]
    fn nvd_score_none_when_cve_absent_or_unscored() {
        // Wrong CVE in the response.
        assert_eq!(net::parse_nvd_score(NVD_BODY, "CVE-9999-9999"), None);
        // No metrics at all.
        let empty = r#"{"vulnerabilities":[{"cve":{"id":"CVE-1","metrics":{}}}]}"#;
        assert_eq!(net::parse_nvd_score(empty, "CVE-1"), None);
    }

    #[cfg(feature = "network")]
    #[test]
    fn cve_validation_blocks_url_injection() {
        assert!(is_valid_cve("CVE-2022-0778"));
        assert!(is_valid_cve("CVE-2026-12345678"));
        // A crafted alias must not pass (it would inject into the EPSS/NVD query URL).
        assert!(!is_valid_cve("CVE-2022-0778&inject=1"));
        assert!(!is_valid_cve("CVE-2022-0778 OR 1=1"));
        assert!(!is_valid_cve("CVE-22-1"));
        assert!(!is_valid_cve("CVE-2022-abc"));
        assert!(!is_valid_cve("GHSA-xxxx"));
        assert!(!is_valid_cve("CVE-"));
    }

    #[test]
    fn score_bands_match_cvss_v3() {
        assert_eq!(severity_from_score(0.0), Severity::Unknown);
        assert_eq!(severity_from_score(3.9), Severity::Low);
        assert_eq!(severity_from_score(4.0), Severity::Medium);
        assert_eq!(severity_from_score(7.0), Severity::High);
        assert_eq!(severity_from_score(9.0), Severity::Critical);
    }
}
