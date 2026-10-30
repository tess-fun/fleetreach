# Spec 07: Fix plans, verified patches and pull requests

Status: draft · Gap: #4 (mobilization) · CTEM stage: validation, mobilization · Effort: L

## Problem

The `remediation` view says exactly which bump clears which advisories across the fleet
(`RemediationItem` with `Action::Upgrade { to, breaking }` in `core/src/remediation.rs`),
then stops. The fleet owner turns one row into N manual pull requests, which is the
expensive part of remediation. Competitors open the PRs.

## What competitors do

- **Dependabot** makes the most conservative update that removes the vulnerability within
  existing version requirements; for npm transitive dependencies it bumps the parent in the
  same PR when the parent's range blocks the fix. Grouped security updates put several fixes
  in one PR, and since 2025 can group across ecosystems.
  ([transitive npm](https://github.blog/security/supply-chain-security/unlocking-security-updates-for-transitive-dependencies-with-npm/),
  [multi-ecosystem groups](https://github.blog/changelog/2025-07-01-single-pull-request-for-dependabot-multi-ecosystem-support/))
- **OSV-Scanner guided remediation** (experimental): strategies `in-place` (edit
  `package-lock.json`), `relock` (edit `package.json` and relock) and `override` (Maven
  `dependencyManagement`), headless or interactive; may run package-manager scripts; does
  not open PRs. ([guided remediation](https://google.github.io/osv-scanner/experimental/guided-remediation))
- **Renovate, Snyk, Endor, Aikido, Mend** open PRs; Endor attaches an upgrade-risk score.

What only fleetreach can do: one decision ("bump `tokio` to 1.38") fans out to every
affected repo as a **campaign**, each PR verified by re-scanning before it is opened.

## Goals

1. A machine-readable fix plan per repo from the remediation queue.
2. Apply the plan with lockfile-only package-manager operations or pure text edits, never
   running package install scripts unless explicitly allowed.
3. Verify each patch by re-scanning: the targeted advisories are gone and nothing new
   appeared. Unverified patches never become PRs.
4. Open or update PRs/MRs through `gh` / `glab`, grouped per repo, tagged with a campaign id.

Non-goals: a bot service, auto-merge, rebasing PRs on every push, fixing code that breaks
after an upgrade.

## Design

### 1. Plan

```
fleetreach fix plan -c fleet.toml [--campaign <filter>] [--allow-breaking] > fix-plan.json
```

Per repo, per remediation item, an edit with a strategy:

| Strategy | When | Example |
|----------|------|---------|
| `lock-bump` | target satisfies every existing range | `cargo update -p time@0.3.20 --precise 0.3.36` |
| `manifest-bump` | direct dependency, range excludes target | `"axios": "^0.27"` → `"^1.7.4"` + relock |
| `override` | transitive, parent's range excludes target | npm `overrides`, pnpm `pnpm.overrides`, yarn `resolutions`, Maven `dependencyManagement`, uv `override-dependencies` |
| `parent-bump` | a newer parent allows the target (phase 3) | bump `webpack-dev-server` to unlock `node-forge` |
| `blocked` | no fix, or `breaking` without `--allow-breaking`, or ecosystem unsupported | reason recorded |

Campaign id = short hash of `(ecosystem, package, to, sorted advisory ids)`, stable across
runs so re-planning updates the same branches and PRs.

### 2. Apply

```
fleetreach fix apply fix-plan.json [--repos a,b] [--max-repos 20]
```

Works on full checkouts (Spec 06 `checkout = "full"`, or local `[[repo]]` paths with a clean
work tree; a dirty tree is skipped with a reason). Creates branch
`fleetreach/<campaign-id>/<package>-<to>` from the scanned commit and runs:

| Ecosystem | Lock-only operation | Runs third-party code? |
|-----------|---------------------|------------------------|
| Cargo | `cargo update -p <pkg>@<cur> --precise <to>` | no |
| npm | `npm install --package-lock-only --ignore-scripts` (after manifest/override edit) | no |
| pnpm | `pnpm install --lockfile-only --ignore-scripts` | no |
| yarn berry | `yarn up <pkg>@<to> --mode=update-lockfile` | no |
| yarn v1 | text edit of `package.json` resolutions + `yarn install --ignore-scripts --frozen-lockfile=false` | no (scripts off) |
| uv | `uv lock --upgrade-package <pkg>==<to>` | can build sdists for metadata: sandboxed, needs `--allow-untrusted-builds` |
| poetry | `poetry update <pkg> --lock` | same as uv |
| RubyGems | `bundle lock --update <pkg> --conservative` | no |
| Composer | `composer update <pkg> --with-dependencies --no-install --no-scripts --no-plugins` | no |
| Maven | pure XML edit of the version or `dependencyManagement` (formatting-preserving) | no |
| NuGet | XML edit of `PackageReference`/`PackageVersion`; relock only if a lockfile exists | restore runs MSBuild: sandboxed + flag |
| Go | `go get <mod>@<to>` + `go mod tidy` | downloads modules, no code execution; network |
| GitHub Actions | text edit of the `uses:` tag | no |

Tools are found on `PATH`; a missing tool makes that edit `blocked` with the reason. Anything
that can execute package code goes through the existing `--build-sandbox` machinery.

### 3. Verify (CTEM validation)

Re-run the scanner on the patched work tree with the same advisory DB snapshot, then diff
against the pre-patch result with the existing `diff` engine:

- every advisory in the edit's set must be `fixed`;
- no `new` advisory or warning may appear (a bump can pull in a different vulnerable version);
- coverage must not drop (a relock that fails and leaves a partial lockfile is caught).

Fail any check: the branch is kept locally for inspection, no PR, status `unverified` in the
apply report.

### 4. Publish

```
fleetreach fix apply fix-plan.json --push --open-pr [--draft] [--labels security,dependencies]
fleetreach fix status [--campaign <id>]
```

- Push to the fleetreach-owned branch only (force-with-lease on that branch, never on the
  default branch).
- `gh pr create` / `glab mr create` (auth and enterprise hosts already configured by the
  user; no API client to maintain). Existing PR for the branch: update title/body.
- PR body generated from the plan: advisories with severity, KEV/EPSS, reachability verdict
  and witness, `breaking` flag, verification result, and the fleet line: "part of campaign
  `<id>`: the same bump across N repos (links)". Owner from Spec 08 as reviewer when set.
- `fix status` reads PR states via `gh pr list --json` / `glab mr list` for the campaign
  branch prefix and prints open/merged/closed per repo. Feeds Spec 09 history.

### Grouping

Default: one PR per repo per campaign (small, reviewable, matches the fleet view). Option
`--group repo`: one PR per repo combining all its verified edits (Dependabot-style groups).

## Safety rules

- Dry run by default: `apply` without `--push` touches only local branches.
- `--max-repos` caps blast radius per run (default 20).
- Ignored advisories, VEX `not_affected` and soundly unreachable findings are never planned.
- `breaking` edits require `--allow-breaking` and are labelled.

## Testing

- Per-ecosystem fixture repos with a known vulnerable version; plan → apply → verify must
  produce exactly the expected lockfile diff (golden files).
- Verification negative tests: a bump that introduces a different advisory; a relock failure.
- `gh`/`glab` calls behind a trait with a fake for tests; one ignored e2e against a scratch
  GitHub repo.

## Phasing

1. `fix plan` (pure, from the existing remediation data): S.
2. `apply` + verify for Cargo, npm, GitHub Actions, uv: M.
3. `--push --open-pr` + `fix status` via `gh`, then `glab`: S/M.
4. Remaining ecosystems, `override` strategy, `parent-bump`: M/L.
