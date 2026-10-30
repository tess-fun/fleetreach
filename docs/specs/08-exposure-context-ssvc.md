# Spec 08: Exposure context and SSVC decisions

Status: draft · Gap: CTEM scoping (from the CTEM notes) · CTEM stage: scoping, prioritization · Effort: M

## Problem

fleetreach ranks by blast radius, severity, KEV and EPSS, but every repo counts the same.
A critical CVE in an internal test tool and the same CVE in the internet-facing payments API
get the same weight. CTEM's core criticism of plain scanners is exactly this: prioritization
without business context. Every exposure-management and ASPM platform adds asset criticality
and exposure; we have no way to express them.

## What competitors do

- **ASPM / CTEM platforms** map repos to services and tag them with business criticality,
  internet exposure and data sensitivity, then combine CVSS, EPSS, reachability, asset
  criticality and exploit data into one priority. No standard defines the tags or weights;
  each vendor has its own.
  ([CTEM stages](https://www.armorcode.com/blog/mastering-the-5-stages-of-the-ctem-framework-a-practical-guide),
  [ASPM context](https://apiiro.com/application-security-posture-management/))
- **Dependency-Track** has project tags and a policy engine, but no exposure model.
- **CVSS v4 environmental metrics** let the consumer set Confidentiality/Integrity/
  Availability requirements (CR/IR/AR) and modified base metrics (e.g. MAV) to get a
  CVSS-BE / CVSS-BTE score. It is a score, it needs a full vector per advisory, and most OSV
  records do not carry v4 vectors.
- **CISA / CERT/CC SSVC** is a decision model, not a score. The **deployer** decision table
  (`ssvc:DT_DP:1.0.0`) maps four decision points to an action:
  - Exploitation: `none` | `public-poc` | `active`
  - System Exposure: `small` | `controlled` | `open`
  - Automatable: `no` | `yes`
  - Human Impact: `low` | `medium` | `high` | `very-high` (from Safety Impact × Mission Impact)
  - Outcome: **Defer**, **Scheduled**, **Out-of-Cycle**, **Immediate**

  The table is published as an example that organizations are encouraged to customize;
  the decision points and their values are not to be changed.
  ([deployer tree](https://certcc.github.io/SSVC/howto/deployer_tree/),
  [customizing](https://certcc.github.io/SSVC/howto/tree_customization/))

## Decision

Use **SSVC deployer decisions** as the context model. It is an open, citable standard; it
needs only per-repo context (exposure, impact) plus data we already have (KEV, EPSS, CVSS
vector, reachability); and its output is an action, which is what a fleet owner and a CI
gate need. CVSS v4 environmental scoring is a non-goal for now.

## Goals

1. Per-repo context in `fleet.toml` (and as source defaults in Spec 06).
2. An SSVC outcome per finding occurrence, with the decision-point vector shown.
3. Fleet views and gates that use outcomes: weighted blast radius, `fix-first` and
   `remediation` ordering, `--fail-on-ssvc`.
4. Owners, so the queue can be split by team (input to Specs 07 and 09).

## Design

### Config

```toml
[settings.context.defaults]       # applied when a repo sets nothing
exposure       = "open"           # fail-closed default
mission_impact = "mef-failure"
safety_impact  = "negligible"

[[repo]]
id             = "payments-api"
path           = "../payments-api"
exposure       = "open"             # small | controlled | open
mission_impact = "mission-failure"  # degraded | mef-support-crippled | mef-failure | mission-failure
safety_impact  = "negligible"       # negligible | marginal | critical | catastrophic
owner          = "team-payments"    # free text; GitHub team or email
tags           = ["pci", "tier-1"]
```

Values use SSVC's own names so the config reads like the standard. If no defaults are
configured, missing context resolves to `exposure = open` and Human Impact `very-high`
(never lowers priority), and the summary line reports how many repos ran on defaults.

### Deriving the decision points (per occurrence)

| Point | Source | Rule |
|-------|--------|------|
| Exploitation | `--enrich` KEV, EPSS, OSV references | `active` if in KEV. `public-poc` if an OSV reference is typed `EVIDENCE` (to verify against the OSV schema) or EPSS ≥ `[settings.ssvc] poc_epss` (default off; documented as a proxy). Else `none`. |
| Automatable | CVSS vector | v3: `AV:N/AC:L/PR:N/UI:N` → `yes`. v4: `AV:N/AC:L/AT:N/PR:N/UI:N` → `yes`. Otherwise `no`. No vector → `yes` (conservative). Phase 2: prefer CISA Vulnrichment's published `Automatable` when the CVE has it. |
| System Exposure | repo context | as configured |
| Human Impact | repo context | SSVC table `ssvc:HI:2.0.2` from safety × mission |

Without enrichment data (no `--enrich`, no `--kev-file`/`--epss-file`), Exploitation is
unknown and SSVC outcomes are not computed (the views say why). Guessing `none` would be a
false-clean in priority form.

Reachability interaction: a **sound** `NotReachable` (static engine) or a phantom optional
dependency forces outcome `Defer` with justification `not_reachable` / `not_built`,
consistent with the OpenVEX `not_affected` statements already emitted. Heuristic or
`Unknown` reachability never changes the outcome.

### Decision table

The 72-row `ssvc:DT_DP:1.0.0` table is embedded as a const and unit-tested row by row against
the published table. Organizations can override it: `[settings.ssvc] table = "ssvc.csv"`
(same 4 inputs, outcomes renamed or remapped). A custom table is recorded in the report
(`ssvc.table = "custom:<sha256>"`), so a gate result is always traceable.

### Output

- Per occurrence (additive): `context: {exposure, human_impact, owner, tags}` and
  `ssvc: {table, exploitation, exposure, automatable, human_impact, outcome, rationale}`.
- `-f ssvc`: findings grouped Immediate → Out-of-Cycle → Scheduled → Defer, each row with
  the decision vector (`E:A EXP:O A:Y HI:VH`).
- `impact`, `packages`, `blast`: extra column "max outcome" and a weighted reach
  (repos weighted by outcome: Immediate 8, Out-of-Cycle 4, Scheduled 2, Defer 0; weights
  configurable).
- `fix-first` and `remediation`: order by max outcome, then the existing keys.
- `-f owners`: remediation queue split by owner (input to Spec 07 reviewers and Spec 09
  tickets).
- SARIF: outcome as a result property and mapped to `level`
  (Immediate/Out-of-Cycle = error, Scheduled = warning, Defer = note).
- OpenVEX/CycloneDX: unchanged (SSVC is prioritization, not exploitability status).

### Gating

`--fail-on-ssvc <outcome>`: exit 1 if any occurrence is at or above the outcome. Works
alongside `--fail-on` (either trips the gate). Recommended CI default for teams adopting
context: `--fail-on-ssvc out-of-cycle`.

## Testing

- Table test: all 72 rows plus the 16-row Human Impact table.
- Derivation tests: CVSS v3/v4 vectors for Automatable; KEV/EPSS combinations; missing
  enrichment; sound NotReachable override.
- Golden views on the demo fleet with context added (one open + very-high repo, one small).

## Phasing

1. Context fields + owners + `-f owners`: S.
2. SSVC derivation, table, `-f ssvc`, `--fail-on-ssvc`: M.
3. Outcome-weighted blast radius in fleet views; custom tables: S.
4. Vulnrichment as an Automatable source: S.

## Open questions

- Defaults when nothing is configured: the fail-closed choice (`open` + `very-high`) will
  push many findings to Out-of-Cycle on first use. Alternative: no SSVC until at least
  `[settings.context.defaults]` exists. Proposal: the latter, with a hint.
- Should `tags` drive defaults (e.g. `tags = ["internet"]` → `exposure = open`) via
  `[settings.context.tag_rules]`? Useful with Spec 06 topics.
