//! SSVC deployer decisions (spec 08): the CISA / CERT/CC Stakeholder-Specific Vulnerability
//! Categorization model, which turns four decision points into an action instead of a score.
//!
//! The decision points and their values are SSVC's own and must not change; only the table
//! that maps them to outcomes is meant to be customized. [`deployer_outcome`] is the published
//! example table `ssvc:DT_DP:1.0.0` and [`human_impact`] the published `ssvc:HI:2.0.2`
//! combination of Safety Impact and Mission Impact, both unit-tested row by row.
//!
//! ```
//! use fleetreach_core::ssvc::{
//!     automatable, deployer_outcome, human_impact, Automatable, Exploitation, Exposure,
//!     MissionImpact, Outcome, SafetyImpact,
//! };
//!
//! let hi = human_impact(SafetyImpact::Negligible, MissionImpact::MissionFailure);
//! let a = automatable(Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
//! assert_eq!(a, Automatable::Yes);
//! assert_eq!(
//!     deployer_outcome(Exploitation::Active, Exposure::Open, a, hi),
//!     Outcome::Immediate
//! );
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

/// The id of the embedded decision table, recorded in the report so a gate is traceable.
pub const DEPLOYER_TABLE: &str = "ssvc:DT_DP:1.0.0";

/// Exploitation `v1.1.0`: evidence of exploitation of the vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Exploitation {
    None,
    PublicPoc,
    Active,
}

/// System Exposure `v1.0.1`: how reachable the deployed system is to an attacker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Exposure {
    Small,
    Controlled,
    Open,
}

/// Automatable `v2.0.0`: whether an attacker can reliably automate steps 1 to 4 of the
/// kill chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Automatable {
    No,
    Yes,
}

/// Mission Impact `v2.0.0`, configured per repo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MissionImpact {
    Degraded,
    MefSupportCrippled,
    MefFailure,
    MissionFailure,
}

/// Safety Impact `v2.0.1`, configured per repo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SafetyImpact {
    Negligible,
    Marginal,
    Critical,
    Catastrophic,
}

/// Human Impact `v2.0.2`, derived from Safety Impact and Mission Impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HumanImpact {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// The deployer's action, ordered least to most urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Defer,
    Scheduled,
    OutOfCycle,
    Immediate,
}

impl Outcome {
    /// Every outcome, most urgent first (the order views list them in).
    pub const ALL: [Outcome; 4] = [
        Outcome::Immediate,
        Outcome::OutOfCycle,
        Outcome::Scheduled,
        Outcome::Defer,
    ];

    /// The SSVC label, as used in config and on the command line.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Defer => "defer",
            Outcome::Scheduled => "scheduled",
            Outcome::OutOfCycle => "out-of-cycle",
            Outcome::Immediate => "immediate",
        }
    }

    /// Parse a label (`defer`, `scheduled`, `out-of-cycle`, `immediate`).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Outcome::ALL.into_iter().find(|o| o.label() == s)
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// `ssvc:HI:2.0.2`: Human Impact from Safety Impact and Mission Impact.
#[must_use]
pub fn human_impact(safety: SafetyImpact, mission: MissionImpact) -> HumanImpact {
    use HumanImpact::{High, Low, Medium, VeryHigh};
    use MissionImpact::{Degraded, MefFailure, MefSupportCrippled, MissionFailure};
    match (safety, mission) {
        (SafetyImpact::Catastrophic, _) | (_, MissionFailure) => VeryHigh,
        (SafetyImpact::Negligible | SafetyImpact::Marginal, Degraded | MefSupportCrippled) => Low,
        (SafetyImpact::Negligible | SafetyImpact::Marginal, MefFailure) => Medium,
        (SafetyImpact::Critical, Degraded) => Medium,
        (SafetyImpact::Critical, MefSupportCrippled | MefFailure) => High,
    }
}

/// `ssvc:DT_DP:1.0.0`, row-major in the published order: Exploitation, then System Exposure,
/// then Automatable, then Human Impact. `D`efer, `S`cheduled, `O`ut-of-cycle, `I`mmediate.
const DEPLOYER_ROWS: &[u8; 72] =
    b"DDSSDSSSDSSSSSSSDSSSSSSODSSSSSSSDSSSSSSOSSSOSSOOSSOOSOOOSSOOOOOOSOOIOOII";

/// The deployer outcome for one set of decision points, from the published example table.
#[must_use]
pub fn deployer_outcome(
    exploitation: Exploitation,
    exposure: Exposure,
    automatable: Automatable,
    human_impact: HumanImpact,
) -> Outcome {
    DecisionTable::deployer().outcome(exploitation, exposure, automatable, human_impact)
}

/// A deployer decision table: the published `ssvc:DT_DP:1.0.0`, or an organization's own
/// remapping of the same four inputs to outcomes (SSVC keeps the decision points fixed and
/// expects the outcomes to be customized).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionTable {
    /// Recorded in the report, so a gate result is traceable to the table that made it.
    pub id: String,
    rows: [Outcome; 72],
}

impl Default for DecisionTable {
    fn default() -> Self {
        Self::deployer()
    }
}

impl DecisionTable {
    /// The published example table, `ssvc:DT_DP:1.0.0`.
    #[must_use]
    pub fn deployer() -> Self {
        let mut rows = [Outcome::Defer; 72];
        for (i, row) in rows.iter_mut().enumerate() {
            *row = match DEPLOYER_ROWS[i] {
                b'D' => Outcome::Defer,
                b'S' => Outcome::Scheduled,
                b'O' => Outcome::OutOfCycle,
                _ => Outcome::Immediate,
            };
        }
        DecisionTable {
            id: DEPLOYER_TABLE.to_string(),
            rows,
        }
    }

    /// Parse a CSV in CERT/CC's published layout: a header row naming the columns, which must
    /// include `Exploitation`, `System Exposure` (or `Exposure`), `Automatable` and
    /// `Human Impact`; the outcome is the last column. A leading `row` column and version
    /// suffixes in the header (`Exploitation v1.1.0`) are fine. Values use SSVC's names,
    /// with spaces or dashes (`public poc`, `out-of-cycle`). Every one of the 72 combinations
    /// must appear exactly once, so a table can never leave a finding undecided.
    ///
    /// # Errors
    ///
    /// A missing column, an unknown value, or a duplicate or missing combination.
    pub fn from_csv(text: &str, id: impl Into<String>) -> Result<Self, String> {
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        let header = lines.next().ok_or("the table is empty")?;
        let columns: Vec<String> = split_csv(header)
            .iter()
            .map(|c| c.to_ascii_lowercase())
            .collect();
        let find = |names: &[&str]| {
            columns
                .iter()
                .position(|c| names.iter().any(|n| c.starts_with(n)))
                .ok_or_else(|| format!("no `{}` column in the header", names[0]))
        };
        let e_col = find(&["exploitation"])?;
        let x_col = find(&["system exposure", "exposure"])?;
        let a_col = find(&["automatable"])?;
        let h_col = find(&["human impact"])?;
        let o_col = columns.len() - 1;
        if [e_col, x_col, a_col, h_col].contains(&o_col) {
            return Err("the last column must be the outcome".to_string());
        }
        let mut rows: [Option<Outcome>; 72] = [None; 72];
        for (n, line) in lines.enumerate() {
            let fields = split_csv(line);
            let at = |col: usize| {
                fields
                    .get(col)
                    .map(|f| f.trim().to_ascii_lowercase().replace(' ', "-"))
                    .ok_or_else(|| format!("row {}: too few columns", n + 1))
            };
            let value = |col: usize, names: &[&str]| -> Result<usize, String> {
                let v = at(col)?;
                names.iter().position(|name| *name == v).ok_or_else(|| {
                    format!("row {}: `{v}` is not one of {}", n + 1, names.join(", "))
                })
            };
            let e = value(e_col, &["none", "public-poc", "active"])?;
            let x = value(x_col, &["small", "controlled", "open"])?;
            let a = value(a_col, &["no", "yes"])?;
            let h = value(h_col, &["low", "medium", "high", "very-high"])?;
            let outcome = Outcome::parse(&at(o_col)?).ok_or_else(|| {
                format!(
                    "row {}: outcome `{}` is not one of defer, scheduled, out-of-cycle, immediate",
                    n + 1,
                    fields.get(o_col).map_or("", |f| f.trim())
                )
            })?;
            let slot = &mut rows[e * 24 + x * 8 + a * 4 + h];
            if slot.replace(outcome).is_some() {
                return Err(format!("row {}: this combination is already listed", n + 1));
            }
        }
        let missing = rows.iter().filter(|r| r.is_none()).count();
        if missing > 0 {
            return Err(format!(
                "{missing} of the 72 combinations are missing; every one must be listed"
            ));
        }
        Ok(DecisionTable {
            id: id.into(),
            rows: rows.map(|r| r.unwrap_or(Outcome::Immediate)),
        })
    }

    /// The outcome for one set of decision points.
    #[must_use]
    pub fn outcome(
        &self,
        exploitation: Exploitation,
        exposure: Exposure,
        automatable: Automatable,
        human_impact: HumanImpact,
    ) -> Outcome {
        self.rows[exploitation as usize * 24
            + exposure as usize * 8
            + automatable as usize * 4
            + human_impact as usize]
    }
}

/// Split one CSV line, honoring double-quoted fields (CERT/CC quote the outcome header).
fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    fields.push(field);
    fields
}

/// Automatable from a CVSS vector: `yes` when the attack is network-borne, low complexity,
/// and needs no privileges or user interaction (v3 `AV:N/AC:L/PR:N/UI:N`, v4 additionally
/// `AT:N`). No vector, or one that cannot be read, is `yes`: an unknown never lowers
/// priority.
#[must_use]
pub fn automatable(vector: Option<&str>) -> Automatable {
    let Some(vector) = vector else {
        return Automatable::Yes;
    };
    let metric = |name: &str| {
        vector
            .split('/')
            .find_map(|part| part.strip_prefix(name)?.strip_prefix(':'))
    };
    let mut required = vec![("AV", "N"), ("AC", "L"), ("PR", "N"), ("UI", "N")];
    if vector.starts_with("CVSS:4") {
        required.push(("AT", "N"));
    } else if !vector.starts_with("CVSS:3") {
        return Automatable::Yes;
    }
    // A vector missing a required metric is unreadable, which counts as `yes`.
    let mut all_easy = true;
    for (name, easy) in required {
        match metric(name) {
            None => return Automatable::Yes,
            Some(value) => all_easy &= value == easy,
        }
    }
    if all_easy {
        Automatable::Yes
    } else {
        Automatable::No
    }
}

/// The short decision vector shown next to an outcome, e.g. `E:A/X:O/A:Y/HI:VH`.
#[must_use]
pub fn vector(
    exploitation: Exploitation,
    exposure: Exposure,
    automatable: Automatable,
    human_impact: HumanImpact,
) -> String {
    let e = match exploitation {
        Exploitation::None => "N",
        Exploitation::PublicPoc => "P",
        Exploitation::Active => "A",
    };
    let x = match exposure {
        Exposure::Small => "S",
        Exposure::Controlled => "C",
        Exposure::Open => "O",
    };
    let a = match automatable {
        Automatable::No => "N",
        Automatable::Yes => "Y",
    };
    let hi = match human_impact {
        HumanImpact::Low => "L",
        HumanImpact::Medium => "M",
        HumanImpact::High => "H",
        HumanImpact::VeryHigh => "VH",
    };
    format!("E:{e}/X:{x}/A:{a}/HI:{hi}")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    /// `data/csv/ssvc/deployer_patch_application_priority_1_0_0.csv` from
    /// <https://github.com/CERTCC/SSVC>, columns: exploitation, exposure, automatable,
    /// human impact, outcome.
    const PUBLISHED_DEPLOYER: &str = "\
none,small,no,low,defer
none,small,no,medium,defer
none,small,no,high,scheduled
none,small,no,very high,scheduled
none,small,yes,low,defer
none,small,yes,medium,scheduled
none,small,yes,high,scheduled
none,small,yes,very high,scheduled
none,controlled,no,low,defer
none,controlled,no,medium,scheduled
none,controlled,no,high,scheduled
none,controlled,no,very high,scheduled
none,controlled,yes,low,scheduled
none,controlled,yes,medium,scheduled
none,controlled,yes,high,scheduled
none,controlled,yes,very high,scheduled
none,open,no,low,defer
none,open,no,medium,scheduled
none,open,no,high,scheduled
none,open,no,very high,scheduled
none,open,yes,low,scheduled
none,open,yes,medium,scheduled
none,open,yes,high,scheduled
none,open,yes,very high,out-of-cycle
public poc,small,no,low,defer
public poc,small,no,medium,scheduled
public poc,small,no,high,scheduled
public poc,small,no,very high,scheduled
public poc,small,yes,low,scheduled
public poc,small,yes,medium,scheduled
public poc,small,yes,high,scheduled
public poc,small,yes,very high,scheduled
public poc,controlled,no,low,defer
public poc,controlled,no,medium,scheduled
public poc,controlled,no,high,scheduled
public poc,controlled,no,very high,scheduled
public poc,controlled,yes,low,scheduled
public poc,controlled,yes,medium,scheduled
public poc,controlled,yes,high,scheduled
public poc,controlled,yes,very high,out-of-cycle
public poc,open,no,low,scheduled
public poc,open,no,medium,scheduled
public poc,open,no,high,scheduled
public poc,open,no,very high,out-of-cycle
public poc,open,yes,low,scheduled
public poc,open,yes,medium,scheduled
public poc,open,yes,high,out-of-cycle
public poc,open,yes,very high,out-of-cycle
active,small,no,low,scheduled
active,small,no,medium,scheduled
active,small,no,high,out-of-cycle
active,small,no,very high,out-of-cycle
active,small,yes,low,scheduled
active,small,yes,medium,out-of-cycle
active,small,yes,high,out-of-cycle
active,small,yes,very high,out-of-cycle
active,controlled,no,low,scheduled
active,controlled,no,medium,scheduled
active,controlled,no,high,out-of-cycle
active,controlled,no,very high,out-of-cycle
active,controlled,yes,low,out-of-cycle
active,controlled,yes,medium,out-of-cycle
active,controlled,yes,high,out-of-cycle
active,controlled,yes,very high,out-of-cycle
active,open,no,low,scheduled
active,open,no,medium,out-of-cycle
active,open,no,high,out-of-cycle
active,open,no,very high,immediate
active,open,yes,low,out-of-cycle
active,open,yes,medium,out-of-cycle
active,open,yes,high,immediate
active,open,yes,very high,immediate";

    /// `data/csv/ssvc/human_impact_1_0_0.csv` from the same repository.
    const PUBLISHED_HUMAN_IMPACT: &str = "\
negligible,degraded,low
negligible,mef support crippled,low
negligible,mef failure,medium
negligible,mission failure,very high
marginal,degraded,low
marginal,mef support crippled,low
marginal,mef failure,medium
marginal,mission failure,very high
critical,degraded,medium
critical,mef support crippled,high
critical,mef failure,high
critical,mission failure,very high
catastrophic,degraded,very high
catastrophic,mef support crippled,very high
catastrophic,mef failure,very high
catastrophic,mission failure,very high";

    fn parse<T: serde::de::DeserializeOwned>(label: &str) -> T {
        let json = format!("\"{}\"", label.replace(' ', "-"));
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("`{label}`: {e}"))
    }

    #[test]
    fn deployer_table_matches_every_published_row() {
        let rows: Vec<&str> = PUBLISHED_DEPLOYER.lines().collect();
        assert_eq!(rows.len(), 72);
        for row in rows {
            let f: Vec<&str> = row.split(',').collect();
            let got = deployer_outcome(parse(f[0]), parse(f[1]), parse(f[2]), parse(f[3]));
            assert_eq!(got, parse::<Outcome>(f[4]), "row `{row}`");
        }
    }

    #[test]
    fn a_csv_in_the_published_layout_round_trips() {
        let csv = format!(
            "row,Exploitation v1.1.0,System Exposure v1.0.1,Automatable v2.0.0,Human Impact v2.0.2,\"Defer, Scheduled, Out-of-Cycle, Immediate v1.0.0\"\n{}",
            PUBLISHED_DEPLOYER
                .lines()
                .enumerate()
                .map(|(i, l)| format!("{i},{l}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let table = DecisionTable::from_csv(&csv, "custom").unwrap();
        assert_eq!(table.rows, DecisionTable::deployer().rows);
        assert_eq!(table.id, "custom");
    }

    #[test]
    fn a_custom_csv_must_cover_every_combination_once() {
        let header = "exploitation,exposure,automatable,human impact,outcome\n";
        let all = PUBLISHED_DEPLOYER.replace("immediate", "out-of-cycle");
        let stricter = DecisionTable::from_csv(&format!("{header}{all}"), "c").unwrap();
        assert_eq!(
            stricter.outcome(
                Exploitation::Active,
                Exposure::Open,
                Automatable::Yes,
                HumanImpact::VeryHigh
            ),
            Outcome::OutOfCycle
        );
        let short: String = PUBLISHED_DEPLOYER
            .lines()
            .skip(1)
            .collect::<Vec<_>>()
            .join("\n");
        let err = DecisionTable::from_csv(&format!("{header}{short}"), "c").unwrap_err();
        assert!(
            err.contains("1 of the 72 combinations are missing"),
            "{err}"
        );
        let dup = format!("{header}{PUBLISHED_DEPLOYER}\nnone,small,no,low,defer");
        let err = DecisionTable::from_csv(&dup, "c").unwrap_err();
        assert!(err.contains("already listed"), "{err}");
        let bad = format!(
            "{header}{}",
            PUBLISHED_DEPLOYER.replacen("defer", "later", 1)
        );
        let err = DecisionTable::from_csv(&bad, "c").unwrap_err();
        assert!(err.contains("outcome `later`"), "{err}");
        let err = DecisionTable::from_csv("exploitation,automatable,outcome\n", "c").unwrap_err();
        assert!(err.contains("no `system exposure` column"), "{err}");
    }

    #[test]
    fn human_impact_matches_every_published_row() {
        let rows: Vec<&str> = PUBLISHED_HUMAN_IMPACT.lines().collect();
        assert_eq!(rows.len(), 16);
        for row in rows {
            let f: Vec<&str> = row.split(',').collect();
            assert_eq!(
                human_impact(parse(f[0]), parse(f[1])),
                parse::<HumanImpact>(f[2]),
                "row `{row}`"
            );
        }
    }

    #[test]
    fn automatable_reads_cvss_v3_and_v4() {
        let yes = Automatable::Yes;
        let no = Automatable::No;
        assert_eq!(
            automatable(Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
            yes
        );
        assert_eq!(
            automatable(Some("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")),
            no
        );
        assert_eq!(
            automatable(Some("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
            no
        );
        assert_eq!(
            automatable(Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")),
            no
        );
        assert_eq!(
            automatable(Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")),
            no
        );
        assert_eq!(
            automatable(Some(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            )),
            yes
        );
        assert_eq!(
            automatable(Some(
                "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            )),
            no
        );
        assert_eq!(
            automatable(Some(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            )),
            no
        );
    }

    #[test]
    fn unknown_or_unreadable_vectors_are_automatable() {
        assert_eq!(automatable(None), Automatable::Yes);
        assert_eq!(
            automatable(Some("AV:N/AC:L/Au:N/C:P/I:P/A:P")),
            Automatable::Yes
        );
        assert_eq!(automatable(Some("CVSS:3.1/AV:L")), Automatable::Yes);
        assert_eq!(automatable(Some("garbage")), Automatable::Yes);
    }

    #[test]
    fn outcomes_order_and_labels_round_trip() {
        assert!(Outcome::Immediate > Outcome::OutOfCycle);
        assert!(Outcome::Scheduled > Outcome::Defer);
        for o in Outcome::ALL {
            assert_eq!(Outcome::parse(o.label()), Some(o));
            assert_eq!(serde_json::to_string(&o).unwrap(), format!("\"{o}\""));
        }
        assert_eq!(Outcome::parse("urgent"), None);
    }

    #[test]
    fn vector_is_compact() {
        assert_eq!(
            vector(
                Exploitation::PublicPoc,
                Exposure::Controlled,
                Automatable::No,
                HumanImpact::VeryHigh
            ),
            "E:P/X:C/A:N/HI:VH"
        );
    }
}
