# Spec 14: Decisions on the remaining gaps

Status: draft · Gaps: #11, #12 and two smaller items

These gaps from the competitive analysis do not get a feature spec. Each has a decision and
the small amount of work that decision implies.

## Container and OS package scanning (gap #11): not building

- **Decision**: out of scope. Trivy, Grype and OSV-Scanner do this well and are free.
- **Work**: document the pairing. fleetreach's OpenVEX output already suppresses findings in
  Trivy (validated with Docker, see the VEX feature notes); add a CI recipe that runs Trivy on
  images with `--vex fleetreach.vex.json`, and once Spec 05 lands, a recipe that merges
  fleetreach's CycloneDX with Syft's image SBOM.

## Proprietary or curated vulnerability research (gap #12): not building

- **Decision**: out of scope. fleetreach's trust boundary is "structured advisory data plus
  your own config". OSV aggregates GHSA, PyPA, RustSec, Go and others; the gap to commercial
  feeds is days of disclosure lead time on some advisories, which a single maintainer cannot
  close.
- **Work**: none. If a paid feed ever matters, the integration point is an extra OSV-format
  directory under Spec 01's `--osv-dir`, which already works for any OSV-shaped data.

## SAST, secrets, IaC: not building

- Not raised as a gap for the fleet user, listed for completeness. Different product.

## `--enrich` NVD lookups are slow without an API key: small fix, no spec

- Document `NVD_API_KEY` prominently in `--help` and the enrichment docs.
- Cache NVD responses per CVE (same cache root as Spec 01) with a TTL.
- Prefer CVSS from OSV records when present and only call NVD for gaps.
- Respect NVD's published rate limits with a token bucket rather than fixed sleeps.

Estimate: S. Implemented (uncommitted): per-CVE cache under `~/.cache/fleetreach/nvd/`, waits only between real requests, a time estimate when no key is set, and `NVD_API_KEY` documented. Preferring OSV CVSS over NVD remains open.
