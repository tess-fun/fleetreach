---
title: Scale benchmark
description: Time and memory of fleetreach on 10,471 real repositories and 13 large monorepos, with and without incremental scanning, and how to reproduce the numbers.
sidebar:
  order: 30
---

Measured 2026-11-04 on an Apple M5 Pro (18 cores, 64 GB), native arm64 build, warm disk cache,
everything offline. Each time is the median of three runs; memory is the peak.

**Plain** is an ordinary scan. **First incremental** is `--incremental` with an empty cache,
which also stores every result. **Warm** is the next run, with nothing changed. **Same output**
says whether every incremental run printed the same bytes as the plain scan, JSON report included.

## 10,471 repositories

Mostly small Rust repos from crates.io, some polyglot. A repo counts in every row its root
lockfiles match, and a row's numbers come from a fleet of only those repos.

| Fleet | Repos | Findings | Plain | Peak memory | First incremental | Warm | Warm memory | Same output |
|---|---:|---:|---:|---:|---:|---:|---:|:---:|
| Whole fleet | 10,471 | 733 | 4.01 s | 1,248 MB | 4.80 s | 2.07 s | 350 MB | yes |
| Repos with Rust | 10,471 | 733 | 3.99 s | 1,255 MB | 4.70 s | 2.10 s | 358 MB | yes |
| Repos with npm | 11 | 211 | 0.60 s | 825 MB | 0.71 s | 0.18 s | 40 MB | yes |
| Repos with PyPI | 7 | 80 | 0.20 s | 392 MB | 0.31 s | 0.18 s | 68 MB | yes |
| Repos with Go | 3 | 25 | 0.21 s | 92 MB | 0.23 s | 0.09 s | 23 MB | yes |

## 13 large monorepos

Airflow, Deno, Discourse, Mastodon, Matomo, Meilisearch, Monica, PostHog, Plausible Analytics,
Realtime, Sentry, VS Code and Zed.

| Fleet | Repos | Findings | Plain | Peak memory | First incremental | Warm | Warm memory | Same output |
|---|---:|---:|---:|---:|---:|---:|---:|:---:|
| Whole fleet | 13 | 1,069 | 2.42 s | 1,516 MB | 3.08 s | 2.68 s | 1,289 MB | yes |
| Repos with npm | 6 | 788 | 0.77 s | 1,277 MB | 1.18 s | 0.54 s | 88 MB | yes |
| Repos with PyPI | 3 | 701 | 0.74 s | 1,133 MB | 1.14 s | 0.51 s | 111 MB | yes |
| Repos with Rust | 3 | 39 | 0.37 s | 73 MB | 0.38 s | 0.11 s | 47 MB | yes |
| Repos with RubyGems | 2 | 28 | 0.60 s | 869 MB | 0.86 s | 0.33 s | 43 MB | yes |
| Repos with Packagist | 2 | 185 | 0.60 s | 999 MB | 0.70 s | 0.18 s | 27 MB | yes |

Incremental scanning does not help this fleet: warm runs are a little slower than plain ones.
A repo with a Maven or Gradle build is never reused, so one such repo re-scans whole and its
other ecosystems' advisory data still loads, which is most of the cost here. Use it for many repos, not for a few very large ones.

## What a warm run skips

Parsing, matching, and loading the advisory data of any ecosystem with nothing to re-scan,
which is where the memory goes. It still plans every repo, hashes the files a scan would read
and assembles the report, so a warm run is about twice as fast rather than instant. Anything
that changes the advisory data for an ecosystem re-scans that ecosystem's repos, and osv.dev
updates npm and PyPI many times a day, so reuse pays most between syncs or under
`--db-snapshot`.

## Reproduce it

```sh
python3 scripts/benchmark.py ./fleetreach fleet.toml /tmp/bench \
  --offline --db ./advisory-db --osv-dir ./osv --quiet
```

It prints these tables for your own fleet, and exits 1 if any incremental run's output differed.
The 10,471-repo testbed is a local corpus, not published.
