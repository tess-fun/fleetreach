# Spec 02: yarn, pnpm and bun lockfiles

Status: implemented (phases 1 and 3, yarn berry and bun.lock; bun.lockb stays a reported gap) · Gap: #2 (coverage) · CTEM stage: discovery · Effort: M

## Problem

Only `package-lock.json` is read. `yarn.lock`, `pnpm-lock.yaml` and `bun.lock` are listed
in a stderr note (since 1.1.0) and otherwise ignored. In a real JavaScript fleet a large
share of repos use one of these, so they are either errored gaps or blind spots. Every
competitor reads all of them.

## What competitors do

- **OSV-Scanner, Trivy, Grype/Syft, Dependabot, Renovate, Snyk, Socket** all parse yarn v1,
  yarn berry, pnpm and (most) bun lockfiles directly, without running the package manager.
- pnpm v9 splits the file into `importers` (one per workspace package, keyed by relative
  path, `.` for the root), a canonical `packages` map keyed by `name@version`, and a
  `snapshots` map keyed by the full dependency path including peer suffixes. A file can hold
  more than one YAML document; the project graph is in the last one.
  ([pnpm lockfile](https://pnpm.io/lockfile))
- `bun.lock` is the text format (JSON with comments and trailing commas) that became Bun's
  default in 1.2; the older `bun.lockb` is binary. (To verify against Bun docs.)

## Goals

1. Full transitive coverage for yarn v1, yarn berry (v2+), pnpm (lockfile v5.4, v6, v9) and
   `bun.lock`, feeding the existing npm matcher unchanged.
2. Direct vs transitive, dependency paths and dev scope, at parity with `package-lock.json`.
3. Workspaces: one repo with N workspace packages produces one scan with correct direct sets.

Non-goals: running any package manager; `bun.lockb` (binary, reported as a gap with the fix:
`bun install --save-text-lockfile`); resolving `package.json` without a lockfile.

## Design

### Shared model

Each parser produces the existing npm intermediate (`InstalledPackage` list + dependency
edges) so matching, dedup by `(advisory, package, version)`, dependency paths, scope and the
import-graph reachability all stay in one place (`crates/npm`). New module per format:
`yarn_v1.rs`, `yarn_berry.rs`, `pnpm.rs`, `bun.rs`.

| Format | Detection | Parser | Direct set | Dev scope |
|--------|-----------|--------|------------|-----------|
| yarn v1 | `yarn.lock` with `# yarn lockfile v1` header | hand-rolled (indent-based, like the Gemfile.lock parser) | `package.json` (+ workspaces globs) | computed: dev if only reachable from `devDependencies` |
| yarn berry | `yarn.lock` with `__metadata:` | YAML | same | same |
| pnpm | `pnpm-lock.yaml` | YAML, last document | `importers.<path>.dependencies/devDependencies/optionalDependencies` | from importers |
| bun | `bun.lock` | JSONC (strip comments and trailing commas, then serde_json) | `workspaces` section | from `devDependencies` in workspaces |

### Version and name details

- yarn keys list several ranges for one resolution (`"a@^1.0.0", "a@^1.2.0":`); the resolved
  `version` field is what matters.
- npm aliases (`foo@npm:bar@1.2.3`) match the real package `bar`, but report the alias name too.
- `workspace:`, `link:`, `file:`, `portal:`, git and tarball URLs are non-registry sources:
  never matched against OSV, counted in the coverage record (Spec 00, C1) as
  `non_registry`, not errors.
- pnpm peer suffixes (`react-dom@18.2.0(react@18.2.0)`) are stripped for matching but kept
  for distinct dependency paths.

### YAML parser

The workspace has no YAML dependency today (the GitHub Actions feeder parses workflows by
hand). pnpm and yarn berry need a real parser. Candidates must be pure Rust (no vendored C):
`saphyr` / `yaml-rust2`. Selection criteria: no `unsafe` in our path, handles multi-document
streams and large files (pnpm lockfiles reach tens of MB), maintained. Parse into a generic
tree and map by hand; avoid serde magic on untrusted input.

### Reachability

The npm import graph walks `node_modules`. pnpm's layout is symlinks into
`node_modules/.pnpm/<name>@<ver>/node_modules/<name>`; yarn berry PnP has no `node_modules`
at all. Phase 1: follow pnpm symlinks (within the repo root only, no escaping); PnP repos get
the source-only one-step witness, same as no `node_modules`. Never `NotReachable` from a
layout we could not walk.

## Fail-closed rules

- Unknown `lockfileVersion` (pnpm) or unknown berry `__metadata.version`: errored gap with
  the version named, never a best-effort parse.
- A lockfile that parses but whose importer set does not cover a `package.json` under the
  repo (workspace mismatch): warn in coverage as `partial`.

## Testing and validation

Same bar as the existing npm feeder (100% recall, zero false-cleans vs the OSV export):

1. **Self-oracle corpus**: for ~300 real `package.json` files, generate lockfiles with real
   yarn 1, yarn 4, pnpm 9 and bun; compare our parsed `(name, version)` set with each tool's
   own listing (`yarn list --json`, `pnpm list --json --depth Infinity`, `bun pm ls --all`).
   Target: exact set equality.
2. **Differential**: same lockfiles through OSV-Scanner; findings must be a superset.
3. Fuzz each parser (cargo-fuzz targets exist for other parsers; add four).
4. Fixtures for aliases, workspaces, peer suffixes, git deps, multi-document pnpm files.

## Phasing

1. pnpm v9 + yarn v1 (largest share): M.
2. yarn berry + bun.lock: S each.
3. pnpm v5.4/v6 legacy formats: S.

## Open questions

- Which YAML crate (needs a quick spike against the largest real pnpm lockfiles).
- Share of each format in the user's own fleet (`~/fa-testbed`) to confirm ordering.
