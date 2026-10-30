# Spec 10: Supply-chain signals beyond known CVEs

Status: draft · Gap: #7 (malware) · CTEM stage: discovery, prioritization · Effort: M

## Problem

fleetreach detects malware only when an OSV `MAL-` record exists for the exact version.
Recent npm and PyPI worm and typosquat waves were caught by behavioural analysis within
minutes of publication; OSV records arrive later. There is no signal for "this dependency
looks wrong" before an advisory exists.

## What competitors do

- **Socket**: alerts per package version, including install scripts (high), network access
  (medium), obfuscated code and high-entropy strings (high), possible typosquat (critical;
  name 1–2 characters from a more popular package), protestware; policies map alerts to
  block/warn/ignore. A firewall wraps npm, pip, uv, cargo and others at install time.
  ([alert types](https://docs.socket.dev/docs/issues-list),
  [policies](https://docs.socket.dev/docs/enabled-issues))
- **Sonatype Firewall, JFrog Curation, Aikido safe-chain**: block at the registry proxy or
  install command.
- **Semgrep Supply Chain**: malicious dependency detection for C#, Go, JS/TS, Python, Ruby.
- **Renovate / pnpm**: `minimumReleaseAge` cooldowns so brand-new versions are not adopted.

What fleetreach should not do: analyse package code (that is Socket's product and needs a
research team) or sit in the install path. What it can do cheaply and well: lockfile-level
and fleet-level signals that need no package download, explained precisely.

## Goals

1. Make known malware (OSV `MAL-`) a first-class, always-gating category.
2. Lockfile hygiene signals already present in the files we parse.
3. Typosquat detection against popular names, offline.
4. Release-age signal (cooldown), opt-in network.
5. Fleet novelty: a dependency that appears in the fleet for the first time (with Spec 09).

## Design

All signals are `WarnFinding`s with new `WarnKind`s, shown in a `-f supply-chain` view and
gated by `--fail-on-warnings` or per-kind `--fail-on-signal <kind>`. Malware is the exception
and gates as a vulnerability.

### 1. Malware

- Findings from `MAL-` records get `kind = malware`, severity `critical`, are excluded from
  `--min-severity` filtering, ignore entries for them require `approved_by` (as VEX
  assertions do), and they lead every view.
- Remediation action is `remove` (not `upgrade`): any version of a malicious package is
  suspect, and the advice is to rotate credentials of any machine that installed it.

### 2. Lockfile hygiene (offline)

| Signal | Source | Ecosystems |
|--------|--------|------------|
| `install-script` | `hasInstallScript: true` in `package-lock.json` (and pnpm `requiresBuild`) | npm, pnpm |
| `non-registry-source` | git, tarball URL, path dependencies | all |
| `unexpected-registry` | `resolved` host not in `[settings.registries]` allowlist (dependency confusion, lockfile injection) | npm, yarn, pnpm, PyPI (uv/poetry source URLs), Cargo (`source`), Composer `dist.url` |
| `missing-integrity` | registry package without `integrity`/checksum | npm, yarn, Cargo, uv |
| `mutable-action-ref` | GitHub Action pinned to a branch or tag instead of a SHA (today: skipped as a gap) | GitHub Actions |

### 3. Typosquats (offline)

- A bundled list of the top N package names per ecosystem (refreshed at release time from
  public download statistics; data file under `data/popular/`, a few MB at most).
- A dependency is flagged when its name is within Damerau-Levenshtein distance 1 (2 for
  names ≥ 10 characters) of a popular name it is not, or matches common confusions:
  separator swaps (`-`/`_`/`.`), scope removal (`@types/x` vs `types-x`), digit/letter
  homoglyphs (`l`/`1`, `o`/`0`), and pluralization.
- Known legitimate pairs are allowlisted in the data file; users can extend it.

### 4. Release age (opt-in, network)

`--signal release-age=72h`: fetch publish time for each resolved version (npm registry
`time`, PyPI JSON `upload_time`, crates.io `created_at`, RubyGems `created_at`), cached
forever per version. Flags versions younger than the threshold. The fleet view answers
"which repos pulled a version published in the last 72 hours", the question that matters
during a worm outbreak.

### 5. Fleet novelty (needs Spec 09 history)

A package name never seen in any earlier snapshot of the fleet is `new-to-fleet`. Combined
with release age or a typosquat hit, it is the strongest cheap indicator we can produce.

## Fail-closed rules

- Signals are additive warnings; their absence never implies safety, and the docs say so.
- `release-age` lookups that fail mark the package `unknown age`, never "old".

## Testing

- Historic malware fixtures: lockfiles reconstructed from public incident write-ups
  (e.g. the tj-actions and npm worm incidents) must trip the expected signals.
- Typosquat precision measured on the full dependency set of `~/fa-testbed`: target fewer
  than 1 false positive per 1,000 distinct packages before enabling by default.

## Phasing

1. Malware first-class + lockfile hygiene: S.
2. Typosquats with bundled data: M.
3. Release age: S/M.
4. Fleet novelty: S (after Spec 09).
