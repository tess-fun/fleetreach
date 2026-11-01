---
title: PyPI (Python)
description: Scan uv, Poetry, Pipenv, pylock.toml and requirements files across a fleet with PEP 440 version rules, honest coverage labels and import-graph reachability.
sidebar:
  order: 4
---

| | |
|---|---|
| Reads | `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml`, `requirements*.txt` |
| Advisory data | osv.dev `PyPI` export |
| Version rules | PEP 440, names normalised per PEP 503 |
| Fix apply | `uv lock --upgrade-package <pkg>==<to> --no-build` (uv only) |
| Reachability | import graph over the virtualenv, positive only |

Advisories come from the osv.dev `PyPI` export, kept fresh in `~/.cache/fleetreach/osv/` (or read from `--osv-dir`, or `--pypi-vuln-db=file://<path>`). Fetch it ahead of time with `fleetreach db sync`.

It runs no package manager and no install or build script, so it is safe to point at any repository and needs no `--allow-untrusted-builds`. Without advisory data for the ecosystem, the repo is an errored gap, never clean.

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

Matching uses both the advisory ranges and its enumerated version list: range-only matching
missed 220 of 600 real PyPI cases during validation.
