---
title: PyPI (Python)
description: Scan uv, Poetry, Pipenv, pylock.toml and requirements files across a fleet with PEP 440 version rules, honest coverage labels and import-graph reachability.
sidebar:
  order: 4
---

| | |
|---|---|
| Reads | `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml`, `requirements*.txt`, `pyproject.toml` dependencies |
| Advisory data | osv.dev `PyPI` export |
| Version rules | PEP 440, names normalised per PEP 503 |
| Fix apply | `uv lock --upgrade-package <pkg>==<to> --no-build` (uv only) |
| Reachability | import graph over the virtualenv, positive only |

Advisories come from the osv.dev `PyPI` export, kept fresh in `~/.cache/fleetreach/osv/` (or read from `--osv-dir`, or `--pypi-vuln-db=file://<path>`). Fetch it ahead of time with `fleetreach db sync`.

It runs no package manager and no install or build script, so it is safe to point at any repository and needs no `--allow-untrusted-builds`. The one exception is `--resolve-python` (below), which you ask for and which still builds nothing. Without advisory data for the ecosystem, the repo is an errored gap, never clean.

## Requirements files get a coverage label

A requirements file is not always a resolved set, so fleetreach says how much it trusts it:

| Requirements file | Coverage |
|-------------------|----------|
| Every line pinned and written by a resolver (pip-compile or uv header, `# via`, or hashes) | full |
| Every line pinned, no sign a resolver wrote it (`pip freeze`) | partial |
| Any line not pinned (`>=`, `~=`, a bare name) | direct-only, unpinned names listed |

`-r` includes and `-c` constraints are followed inside the repo. Environment markers are
not evaluated (a marker could only hide a finding). Files named for development
(`requirements-dev.txt`) are dev scope. `--require-full-coverage` turns any label below full
into exit 2.

A repo with only a `pyproject.toml` is read from its PEP 621 `[project].dependencies`,
direct-only like a hand-written requirements file. Dependencies declared only under
`[tool.poetry]` with no `poetry.lock`, or marked `dynamic`, are not read: the repo is an
errored gap.

## Resolving unlocked sets with uv

`scan --resolve-python` resolves each direct-only or partial set (a requirements file that is
not complete resolver output, or a `pyproject.toml` with no lockfile) with
`uv pip compile --no-build`, so the scan sees transitive packages too. It needs uv 0.5 or
later on `PATH`, or `--uv PATH`; without it the scan stops with exit 2.

- uv contacts the package index (none with `--offline`), but `--no-build` refuses source
  distributions, so no package code is built or run.
- fleetreach writes the set to uv's standard input and runs uv in an empty scratch directory
  with `--no-config --no-sources`, so uv opens no file of the repo. `-r` and `-c` are expanded
  by fleetreach, inside the repo only. Local paths, editables, URLs and options other than
  http(s) index ones are left out, and the coverage note names them.
- The resolution is `--universal` from Python 3.12, so platform markers are kept.
- A resolved file is labelled partial: its versions are what the index allows today, not what
  is installed. Commit a lockfile for exact versions.
- A file uv cannot resolve keeps its own label, and the note says why. The usual cause is a
  package published only as a source distribution.
- Scans with `--resolve-python` are never reused by `--incremental`, since the index changes.

On 185 real repos, uv resolved 90 of 143 sets. Of the 53 it could not, 44 need a package that
has no wheel. An independent reading of uv's output agreed with fleetreach on every vulnerable
pin, and the scan found 355 more PyPI findings in 14 repos, losing none.

Matching uses both the advisory ranges and its enumerated version list: range-only matching
missed 220 of 600 real PyPI cases during validation.

## Example

The demo fleet's [`ml-service`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/ml-service) and [`data-pipeline`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/data-pipeline): a `uv.lock` and a `requirements.txt` (the second gets a coverage label, below). `ecosystems/pypi.toml` is a fleet file naming just those repos, and the output is real, generated on frozen advisory data.

<!-- run: fleetreach scan -c ecosystems/pypi.toml -f packages -->
```console
$ fleetreach scan -c ecosystems/pypi.toml -f packages
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬─────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package         │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪═════════════════╡
│ 2     ┆ 2      ┆ 0          ┆ 10         ┆ high     ┆ manifest ┆ -       ┆ urllib3 (pypi)  │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 4          ┆ medium   ┆ manifest ┆ -       ┆ requests (pypi) │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 4          ┆ critical ┆ manifest ┆ -       ┆ certifi (pypi)  │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 5          ┆ high     ┆ manifest ┆ -       ┆ jinja2 (pypi)   │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 2          ┆ high     ┆ manifest ┆ -       ┆ flask (pypi)    │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 1      ┆ 0          ┆ 2          ┆ high     ┆ manifest ┆ -       ┆ idna (pypi)     │
└───────┴────────┴────────────┴────────────┴──────────┴──────────┴─────────┴─────────────────┘
```
<!-- /run -->
