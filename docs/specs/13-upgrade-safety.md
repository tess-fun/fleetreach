# Spec 13: Upgrade safety

Status: phase 1 implemented (unreleased; fleet evidence and risk; no alternatives, which need registry version lists; CI status of the evidence repos not done; phase 2 not started) · Gap: #10 · CTEM stage: mobilization · Effort: S (fleet evidence) to L (API diff)

## Problem

The remediation queue picks the minimal version that clears every grouped advisory and flags
semver-major jumps as `breaking`. It says nothing about whether the upgrade is likely to break
the caller. Without that, fix PRs (Spec 07) stall in review.

## What competitors do

- **Endor Labs upgrade impact analysis**: diffs the current and target versions, overlays the
  changes on the application's call graph (direct and transitive), flags removed or changed
  functions on reached paths with a confidence, and checks version conflicts; it gives each
  upgrade a remediation risk. Never recommends downgrades; recommendations only for
  vulnerable dependencies.
  ([docs](https://docs.endorlabs.com/upgrades-and-remediation/upgrade-impact-analysis))
- **OSV-Scanner guided remediation**: ranks patches by dependency depth, severity and how
  many vulnerabilities they fix, and lets the user cap depth.
- **Dependabot**: "most conservative update" within existing ranges.

## Goals

1. **Fleet evidence** (cheap, unique): for each proposed upgrade, show how many repos in the
   fleet already run the target version (or newer in the same major) and pass CI.
2. **Conservative target selection**: prefer the smallest version that clears the advisories
   *and* stays within existing ranges; show the alternative when a major bump would clear more.
3. **API-change analysis for Rust** using the call graph we already have.
4. A single `risk` field per remediation row: `low` | `medium` | `high` with reasons.

Non-goals: running the repo's tests (CI does that on the Spec 07 PR), API diffs for every
ecosystem.

## Design

### 1. Fleet evidence (phase 1)

From the same scan: for remediation item `(pkg, to)`, count repos whose lockfile already has
`pkg` at `to` or a later version with the same major. Displayed as `in fleet: 7 repos @1.38+`.
Optionally (Spec 06 + `gh`), whether those repos' default-branch CI is green. Rationale: your
own fleet is the best evidence that an upgrade is survivable, and no single-repo tool can see
it.

### 2. Target selection (phase 1)

`RemediationItem` gains `alternatives[]`: the minimal in-range fix (if one exists), the
minimal fix overall, and the latest in the same major. `Action::Upgrade.to` stays the
minimal fix; Spec 07 picks `lock-bump` when an in-range alternative exists.

### 3. Rust API impact (phase 2)

- Run `cargo-semver-checks` (external tool, optional) between `pkg@current` and `pkg@to`
  to list breaking API changes.
- Intersect the changed items with the functions the repo actually calls in that crate,
  from the static reachability graph (`--reachability=static` cache). Output:
  `API changes: 4 breaking, 0 used by this repo` or the list of used items.
- Without the static graph, fall back to "used" = name appears in source (heuristic, labelled).

### 4. Risk

| Signal | Effect |
|--------|--------|
| in-range (`lock-bump`) | low |
| major bump, fleet evidence ≥ 3 repos | medium |
| major bump, no fleet evidence | high |
| Rust: breaking API items used by the repo | high, items listed |
| Rust: breaking API items, none used | lowers by one level |

Shown in `remediation`, `remediation-json`, and Spec 07 PR bodies.

## Testing

- Fleet evidence on the demo fleet (fixtures with mixed versions).
- `cargo-semver-checks` integration on two pinned crate versions with a known break, with
  and without the break being called.

## Phasing

1. Fleet evidence + alternatives + risk: S.
2. Rust API impact: M/L.
3. JVM API impact: only if Spec 12 goes ahead (shares the bytecode call graph).
