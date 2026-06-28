# OpenVEX consumer compatibility matrix

How fleetreach's OpenVEX output (`fleetreach scan -f vex`) behaves when fed back
into real consumers to suppress findings (spec §15). A schema-valid `not_affected`
suppresses **nothing** unless its identifiers byte-match what the consumer emits
for that crate (spec §4) — this matrix records where that holds, verified by
running the pinned tools (see "How it was verified").

**Status legend:** ✅ verified suppression · ⚠️ works with a caveat · ❌ does not
suppress.

## Matrix

| Consumer | Version | Source | not_affected honored | Matches vuln by | Matches package by | Notes |
|---|---|---|---|---|---|---|
| **Trivy** | 0.71.2 | `fs` (Cargo.lock) | ✅ | **alias** — finding is `CVE-…`, our `name` is `RUSTSEC-…` with the CVE in `aliases`; matched | the crate PURL in **`products`** (`pkg:cargo/<name>@<ver>`) | fleetreach's real output suppresses as-is |
| **Grype** | v0.79.0 | `dir:` / SBOM-of-dir | ❌ | — | — | `--vex` errors: *"source type not supported for VEX"*. Grype only applies VEX to a **container-image** source |
| Grype | v0.79.0 | container image | ❓ | (untested) | product = image ref + subcomponent PURL | the supported grype path; needs an image fixture to verify |
| Trivy | 0.71.2 | compiled binary | ❌ (by design) | — | `pkg:rustbinary/<name>@<ver>` | §4.2 divergence: a binary scan keys components under `pkg:rustbinary`; use `--vex-alias-rustbinary` or scan from source |

## Why the crate PURL is a `products` entry

The decisive finding: Trivy's `fs` VEX matching is **package-centric** — it matches
a statement when a `products` entry's PURL equals the vulnerable package. It does
**not** honor fleetreach's `product = <repo>` + `subcomponent = <crate>` relationship
form, because the scan's root component (`/scan`, an application with no PURL) never
matches the repo product — which is frequently a generated IRI no scanner can match
anyway. So fleetreach lists the crate PURL in **both** `products` (for matching) and
`subcomponents` (the relationship, for consumers that use it), keeping the repo as
the first product (fleet correlation + the drift-gate key). Validated: with this
shape, Trivy suppresses `CVE-2020-26235` on `time@0.2.7`.

## Resolved from §17 ("unverified, check before building")

- **Which id each consumer matches on.** Trivy matches on **aliases**, so
  fleetreach's `RUSTSEC-…` `name` with `aliases: [CVE…, GHSA…]` is honored — no need
  to emit the CVE as the primary name. (Grype keys findings under the GHSA; Trivy
  under the CVE — both reachable via our alias list.)
- **Product vs subcomponent matching.** Trivy `fs` uses `products`, not
  `subcomponents` (see above). Grype `dir`/SBOM does not do VEX at all.
- **OpenVEX 0.2.0 namespace** is accepted by both pinned versions.

## How it was verified

Locally via the pinned official images (`anchore/grype:v0.79.0`,
`aquasec/trivy:0.71.2`) against `crates/cli/tests/fixtures/roundtrip/` (a
`Cargo.lock` pinning `time@0.2.7` = RUSTSEC-2020-0071 / CVE-2020-26235 /
GHSA-wcg3-cvx6-7396), feeding back the **real** `fleetreach -f vex` document.
`crates/cli/tests/vex_roundtrip.rs` encodes this: the Trivy test asserts real
suppression; the Grype test is a canary that flags if source-scan VEX ever becomes
supported. The `vex-roundtrip` CI job runs both against the pinned versions.

(Grype v0.79.0's bundled DB can exceed its own 5-day freshness cap depending on the
run date; the test sets `GRYPE_DB_VALIDATE_AGE=false` so the baseline still runs.)
