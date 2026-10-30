# Spec 03: Python and .NET coverage without a native lockfile

Status: draft · Gap: #2 (coverage) · CTEM stage: discovery · Effort: M

## Problem

- **Python**: only `uv.lock`, `poetry.lock` and `Pipfile.lock` are read. Plain
  `requirements.txt` (including fully pinned `pip-compile` / `uv pip compile` output) and the
  new standard `pylock.toml` are not.
- **.NET**: only `packages.lock.json` is read, and most .NET repos never enable
  `RestorePackagesWithLockFile`. Their dependencies live in `*.csproj` `PackageReference`
  items, central package management (`Directory.Packages.props`), or legacy
  `packages.config`.

## What competitors do

- **OSV-Scanner** reads `requirements.txt` and, since v2.3.5, resolves it transitively
  through the deps.dev API (a network call that discloses package names).
  ([supported files](https://google.github.io/osv-scanner/supported-languages-and-lockfiles),
  [releases](https://github.com/google/osv-scanner/releases))
- **Semgrep Supply Chain** offers "scanning without lockfiles" (beta) for C#, Java, Kotlin,
  Python and Ruby using dynamic dependency resolution (it runs the build tool).
- **Snyk** runs `pip`/`dotnet` in the CLI to resolve.
- **pylock.toml** (PEP 751, Final) is the standard Python lockfile: `[[packages]]` with
  `name`, `version`, optional `[[packages.dependencies]]`; pip (experimental `pip lock`),
  uv (export) and pipenv write it. ([spec](https://packaging.python.org/specifications/pylock-toml/))

What we should copy: read every file a Python or .NET repo actually has. What we should not:
silently treat a manifest as a lock, run `pip`/`dotnet` (executes code), or send package
names to a third party by default.

## Goals

1. `pylock.toml` / `pylock.<name>.toml`: full coverage.
2. Fully pinned requirements files: full coverage, with direct/transitive from `# via`
   annotations when present.
3. Unpinned requirements, `.csproj` without lock: honest `direct-only` coverage, labelled
   as such, never presented as full.
4. .NET `obj/project.assets.json` (written by every `dotnet restore`) and legacy
   `packages.config`: full coverage.

## Design

All new sources report a coverage level (Spec 00, C1): `full`, `direct-only` or `partial`.

### Python

**pylock.toml**: parse with the existing `toml` crate. Packages with `version` match by
PEP 440 (existing comparator). `vcs`/`directory`/`archive` sources without `version` are
`non_registry`. Direct set: `pyproject.toml` `[project].dependencies` (and
`[dependency-groups]` for dev scope); without `pyproject.toml`, roots are packages no other
entry depends on (exact when `packages.dependencies` is present).

**requirements files**: discovery picks `requirements*.txt`, `requirements/*.txt`,
`*.requirements.txt`, and anything `-r`/`-c` references inside the repo (bounded depth,
no paths outside the repo root). Parsing per pip's format: line continuations, comments,
`--hash`, environment markers (kept, not evaluated; a marker can only hide a finding, so we
match regardless), `-e` and URLs as `non_registry`.

| Content | Coverage | Direct / transitive |
|---------|----------|---------------------|
| every requirement `name==X` (pip-compile, `pip freeze`, `uv pip compile`) | `full` | from `# via` annotations: `# via -r requirements.in` = direct; otherwise all reported transitive (conservative) |
| some lines unpinned (`>=`, `~=`, bare name) | `direct-only` for the pinned ones; unpinned names listed as `unresolved` | pinned = direct |

Unpinned requirements are never "resolved" by guessing the latest version. Optional phase 3:
`--resolve-with deps.dev` (explicit, network, privacy note in help) to compute the
transitive set like OSV-Scanner does.

`dev` scope: files named `requirements-dev*.txt`, `dev-requirements*.txt`,
`requirements/dev*.txt`, `requirements-test*.txt` are dev. Name-based, so it is a heuristic:
shown as `(dev, by filename)` and still gated by default.

### .NET

Precedence per project directory (first found wins):

1. `packages.lock.json` (existing, `full`).
2. `obj/project.assets.json`: the restore output, full transitive graph with `type:
   package` entries and `project.frameworks.*.dependencies` as the direct set. `full`, but
   checked for staleness: if any `PackageReference` in the `.csproj` is missing from the
   assets file or differs in version, downgrade to `partial` with the mismatch named.
   Usually present in CI after `dotnet restore`, rarely committed.
3. `packages.config` (legacy, non-SDK projects): lists every package including transitives.
   `full`.
4. `*.csproj` / `*.fsproj` / `*.vbproj` `PackageReference` + `Directory.Packages.props`
   (CPM `PackageVersion`, `VersionOverride`) + simple `$(Property)` substitution from
   `Directory.Build.props`: `direct-only`. Floating versions (`1.*`, ranges) are matched as
   ranges only if the advisory range fully contains them; otherwise `unresolved`.

XML parsing with a pure-Rust parser (`quick-xml` or `roxmltree`; the Maven feeder's choice
should be reused). No MSBuild evaluation beyond the simple property case: conditions,
imports of arbitrary targets and SDK props are out of scope and listed as `partial`.

## Fail-closed rules

- `direct-only` and `partial` never print as clean without the coverage note in the summary
  line and JSON. `--require-coverage full` (Spec 00) turns them into exit 2.
- An `unresolved` requirement is always listed by name.

## Testing and validation

- pylock: files produced by `uv export --format pylock.toml` and `pip lock` for a corpus of
  projects; compare against `uv.lock` for the same project (same package set).
- requirements: pip-compile outputs from the PyPI self-oracle corpus; unpinned fixtures.
- .NET: `dotnet restore` a corpus of ~100 open-source projects with and without lock files;
  `project.assets.json` package set must equal `packages.lock.json` from the same restore.
- Recall/zero-false-clean differential against the NuGet and PyPI OSV exports, as for the
  existing feeders.

## Phasing

1. pylock.toml + pinned requirements: S.
2. project.assets.json + packages.config: S.
3. csproj/CPM direct-only + unpinned requirements direct-only: S/M.
4. Optional deps.dev resolution: M (shared with Spec 04).
