# CTEM notes

Working notes on whether Continuous Threat Exposure Management (CTEM) should shape
fleetreach. Started 2026-10-30, after the competitive analysis
(https://claude.ai/artifact/WFVHTdpXcT7mYoSWZnRo5w).

## What CTEM is

- A Gartner framework (2022), a *program*, not a product category. Five recurring
  stages: **scoping, discovery, prioritization, validation, mobilization**.
- Sold in practice by exposure-management / ASPM platforms (Tenable, XM Cyber, Wiz,
  ASPM vendors) that aggregate findings from many scanners and rank them against
  business context and attack paths.

## Where fleetreach already sits

| Stage | fleetreach today | Strength |
|-------|------------------|----------|
| Scoping | `fleet.toml` lists repos; no business context per repo | weak |
| Discovery | lockfiles across the fleet, 12 ecosystems | good, with format gaps |
| Prioritization | blast radius, KEV/EPSS, fix-first, remediation queue | strongest |
| Validation | reachability: sound Rust MIR, govulncheck, npm/Python import graphs | good for Rust/Go |
| Mobilization | remediation queue says what to bump; nothing hands it off | half |

## Initial position

- Use CTEM as a **lens and positioning vocabulary**, not a product direction.
  Building a CTEM platform is cross-domain (cloud, identity, network) = scope creep,
  same failure mode as the closed `polyglot-osv` and `agent-supply-chain` explorations.
- fleetreach = a strong CTEM *component* for the dependency attack surface.

## Candidate ideas the lens surfaces

1. **Scoping: per-repo business context** in `fleet.toml` (`criticality`,
   `exposure = "internet"`, `owner`), so blast radius weights repos by importance,
   not only counts them. Fleet-native, no server, no single-repo tool can do it.
2. **Mobilization:** fix PRs, or a ticket-ready export grouped by owner
   (competitive gap #4).
3. **Interop:** be a clean input to CTEM aggregators. SARIF + OpenVEX exist;
   CycloneDX export (gap #5) would close most of the rest.

## Research findings (2026-10-30)

- **Stages**: the five stages run as a loop; mobilization feeds the next scoping round.
  Gartner's own examples of validation are breach-and-attack simulation and automated
  pentesting; vendors stretch it to "is this exposure real", which is where reachability and
  re-scan verification of a fix fit. Most CTEM material is vendor marketing; treat stats
  attributed to Gartner as unverified.
- **No standard for business context** in ASPM/CTEM: each vendor tags repos with
  criticality, internet exposure and data sensitivity and blends CVSS, EPSS, reachability,
  asset criticality and exploit data with its own weights. Known failure mode: stale
  criticality or ownership gives confident but wrong rankings.
- **CVSS v4 environmental** (CR/IR/AR, modified base metrics such as MAV) can be set only by
  the consumer and produces CVSS-BE/BTE scores. Needs a full vector per advisory; OSV rarely
  has v4 vectors. Rejected for now.
- **SSVC deployer table** (`ssvc:DT_DP:1.0.0`, CERT/CC): Exploitation
  (none/public-poc/active) × System Exposure (small/controlled/open) × Automatable (no/yes) ×
  Human Impact (low/medium/high/very-high, from Safety × Mission) → Defer / Scheduled /
  Out-of-Cycle / Immediate. 72 rows; Immediate only for Active + Open; Active never Defer.
  Published as an example meant to be customized (outcome labels and which points are used),
  decision points and values not. **Chosen** as the context model: open, citable, needs only
  per-repo context plus data fleetreach already has (KEV, EPSS, CVSS vector, reachability).
- **Aggregator inputs**: SARIF, CycloneDX (with VEX), SPDX, generic JSON. fleetreach has
  SARIF + OpenVEX; CycloneDX is the missing piece.

## Outcome

The CTEM lens became one spec (08, context + SSVC) and reframed the competitive gaps by
stage. All gaps now have specs under [`specs/`](specs/00-roadmap.md), with a proposed order
for the prioritization session.

Sources: [SSVC deployer tree](https://certcc.github.io/SSVC/howto/deployer_tree/),
[SSVC customization](https://certcc.github.io/SSVC/howto/tree_customization/),
[CTEM stages (ArmorCode)](https://www.armorcode.com/blog/mastering-the-5-stages-of-the-ctem-framework-a-practical-guide),
[CTEM is a workflow (Deepinfo)](https://www.deepinfo.com/blog/ctem-is-not-a-product-category/),
[CVSS v4 overview (Rapid7)](https://www.rapid7.com/blog/post/2023/08/14/whats-new-in-cvss-v4/),
[ASPM context (Apiiro)](https://apiiro.com/application-security-posture-management/).
