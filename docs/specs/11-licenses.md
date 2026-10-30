# Spec 11: License inventory and policy

Status: draft · Gap: #8 · CTEM stage: discovery (compliance exposure) · Effort: M

## Problem

No license data at all. Legal and compliance teams ask for a fleet license inventory and
policy enforcement at the same time as security, and every commercial competitor, Trivy,
Dependency-Track and cargo-deny (for Rust) provide it.

## What competitors do

- **Trivy**: classifies licenses with Google's license classification into Forbidden
  (CRITICAL), Restricted (HIGH), Reciprocal (MEDIUM), Notice / Permissive / Unencumbered
  (LOW) and Unknown (UNKNOWN); only matches at ≥ 0.9 classifier confidence by default; a
  "full" mode also scans license files.
  ([license scanning](https://trivy.dev/latest/docs/scanner/license))
- **cargo-deny**: allow/deny lists of SPDX identifiers with SPDX expression evaluation,
  per-crate exceptions, confidence threshold for license-file detection.
- **deps.dev**: `GetVersion` returns `licenses[]` as SPDX expressions per package version.
  ([API](https://docs.deps.dev/api/v3/))
- **Dependency-Track, Snyk, Socket, Endor, Mend, Sonatype**: inventory + policy + reports.

## Goals

1. A license (SPDX expression) for every package occurrence, with its source recorded.
2. Policy: allow/deny lists and categories, SPDX expression evaluation, exceptions.
3. Fleet rollup: which licenses appear in how many repos; violations as findings that gate.

Non-goals: legal advice, scanning source files for license text (phase 3 at most), notice
file generation (could follow later).

## Design

### Where license data comes from (best available, recorded per package)

| Priority | Source | Notes |
|----------|--------|-------|
| 1 | Lockfile field | `composer.lock` `license`; `package-lock.json` v2+ entries carry `license` for many packages (to verify coverage); SBOM input (Spec 05) |
| 2 | Local installed metadata | `node_modules/*/package.json`, `site-packages/*.dist-info/METADATA` (`License-Expression`, PEP 639), `~/.cargo/registry/src/*/Cargo.toml`, `~/.m2` POMs, NuGet `.nuspec` in the global packages folder |
| 3 | Registry metadata (opt-in network) | crates.io, npm registry, PyPI JSON, RubyGems, Packagist, NuGet, Maven POM; cached per (ecosystem, name, version) forever |
| 4 | deps.dev (opt-in, discloses names) | one source for all ecosystems |

`license_source` is reported per occurrence. No data → `unknown`.

### Normalization

- Parse with the `spdx` crate (pure Rust, used by cargo-deny). Non-SPDX strings mapped by a
  small table of common spellings (`"Apache 2.0"`, `"BSD"` → ambiguous, stays `unknown`).
- Maven `<licenses>` names and URLs mapped by a URL table (e.g. apache.org/licenses/LICENSE-2.0).

### Policy

```toml
[settings.licenses]
allow      = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0"]
deny       = ["AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0"]
categories = { reciprocal = "warn", restricted = "deny", forbidden = "deny" }
unknown    = "deny"            # fail-closed default; "warn" to relax
scope      = "runtime"         # ignore dev-only packages for policy
[[settings.licenses.exception]]
package = "ring"
allow   = ["OpenSSL"]
reason  = "reviewed by legal 2026-09"
```

- Expression evaluation: `A OR B` passes if either side passes; `A AND B` needs both;
  `WITH` exceptions treated as the base license plus the exception id.
- Category table: Google license classification data (Apache-2.0 licensed) bundled.

### Output

- `-f licenses`: fleet rollup (license, category, repos, packages), then violations.
- Violations are findings (`kind = license`) in JSON and SARIF (rule id
  `license/<spdx-id>`), gated by `--fail-on-license` (default on when `[settings.licenses]`
  exists).
- CycloneDX `licenses` filled when Spec 05 output runs.

## Fail-closed rules

- `unknown` license with a policy present is a violation unless `unknown = "warn"`.
- A network lookup failure gives `unknown`, never "allowed".

## Testing

- Golden: license rollup for the demo fleet and `~/fa-testbed` sample, checked against
  cargo-deny (Rust) and Trivy (others) on the same repos; disagreements triaged.
- Expression evaluation unit tests from cargo-deny's test vectors where license-compatible.

## Phasing

1. Lockfile + local-metadata sources, `-f licenses` inventory: M.
2. Policy and gating: S.
3. Registry and deps.dev sources: S/M.
