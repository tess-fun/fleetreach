# Spec 01: OSV database sync

Status: phases 1–2 implemented (uncommitted) · Gap: #1 (onboarding) · CTEM stage: discovery · Effort: S/M

## Problem

Every non-Rust feeder needs its own `--<eco>-vuln-db file://<path>` flag pointing at a
hand-downloaded osv.dev export. A polyglot fleet needs up to ten of them, and any lockfile
whose ecosystem has no mirror turns its repo into an exit-2 gap. The first run on a real
fleet fails until the user finds, downloads and refreshes ten zips. RustSec is fetched
automatically; the other ten ecosystems are not.

`--max-db-age` only checks the RustSec DB (`cli/src/db.rs::check_db_age` takes an
`AdvisoryDb`). OSV mirrors have no freshness check at all, so a year-old `npm/all.zip`
passes silently. That is a fail-closed hole as well as a usability one.

## What competitors do

- **OSV-Scanner** queries the OSV API by default. Offline mode keeps one `all.zip` per
  ecosystem in a local cache (`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`, else the OS user
  cache dir), downloaded with `--download-offline-databases`, laid out as
  `<dir>/<Ecosystem>/all.zip`. A missing local DB is an error.
  ([offline mode](https://google.github.io/osv-scanner/usage/offline-mode))
- **Trivy / Grype** download one consolidated DB on first run, cache it, check its age and
  offer an offline flag plus a "download DB only" command for air-gapped mirrors.
- Every commercial tool hides the database entirely.

What we should copy: zero-config fetch of exactly the ecosystems the fleet uses, a single
cache directory with the bucket's own layout, a prefetch command for air-gapped use, and
freshness checks. What we keep: offline-first, fail-closed, no API calls that send
package names anywhere (we download whole ecosystem exports, so nothing about the fleet
leaves the machine).

## Goals

1. A first scan of a polyglot fleet works with no DB flags (with the `network` feature).
2. One flag (or one config key) for air-gapped use, not ten.
3. `--max-db-age` covers every advisory source, and unknown age still refuses.
4. Provenance per ecosystem in the report (source, fetch time, upstream timestamp, hash).

Non-goals: querying `api.osv.dev` per package (leaks the dependency list, rate-limited),
building our own advisory DB, mirroring the whole bucket.

## Design

### Cache layout

```
$FLEETREACH_OSV_DIR or ~/.cache/fleetreach/osv/
  npm/all.zip
  npm/all.zip.meta.json      # {etag, last_modified, fetched_at, sha256, size, url}
  PyPI/all.zip
  ...
```

Same layout as `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`
and as OSV-Scanner's offline directory, so a mirror built by either tool works for both.
Ecosystem directory names are osv.dev's: `npm`, `PyPI`, `RubyGems`, `Packagist`, `NuGet`,
`Julia`, `SwiftURL`, `Hex`, `Maven`, `GitHub Actions`, `Go`.

### Resolution order per ecosystem

1. `--<eco>-vuln-db` (unchanged, still wins: explicit beats implicit).
2. `--osv-dir <DIR>` or `[settings.osv] dir = "..."`: `<DIR>/<Ecosystem>/all.zip` or an
   unzipped `<DIR>/<Ecosystem>/` directory (the existing `core::osv::load` already accepts both).
3. The default cache, refreshed if stale (network build, not `--offline`).
4. Otherwise: errored gap, as today, with a message naming the exact command that fixes it.

### Fetch

- Only ecosystems actually discovered in this run are fetched (discovery already happens
  before matching; feed the set of needed ecosystems to the sync step).
- Conditional GET with `If-None-Match` (ETag) and `If-Modified-Since`. A 304 only updates
  `fetched_at`.
- Download to a temp file in the same directory, verify the zip's central directory opens
  and the size matches `Content-Length`, verify the GCS `x-goog-hash` (md5/crc32c) when
  present, then atomic rename. A failed download never replaces a good cache.
- Parallel across ecosystems (bounded, 4), reusing the existing `ureq` + `rustls` stack.
- Fixed host allowlist (`osv-vulnerabilities.storage.googleapis.com`), HTTPS only, no
  redirects off-host. No URL ever comes from advisory data.

### Freshness

- Upstream age = the object's `Last-Modified` (GCS sets it per export). Stored in meta.
- Auto-refresh when local `fetched_at` is older than `[settings.osv] refresh = "6h"`.
- `--max-db-age` applies to each OSV ecosystem used in the run. Age comes from the recorded
  upstream `Last-Modified`; for an export fleetreach did not fetch (a user directory or a
  `--<eco>-vuln-db` path) it falls back to the file's mtime, labelled `age_basis: "mtime"`
  in provenance. An export whose age cannot be read at all refuses with exit 2, same rule
  as RustSec. (As built: the mtime fallback replaced the proposed `--osv-age-from-mtime`
  flag, so existing `--max-db-age` users with hand-made mirrors are not broken.)

### Commands

```
fleetreach db sync [--ecosystems npm,PyPI,...|--all] [--osv-dir DIR]
fleetreach db status            # table: ecosystem, source, upstream age, size, sha256
```

`db sync --all` on a connected machine plus copying the directory is the air-gap story.

### Report

Additive `provenance.osv[]`: `{ecosystem, source: "cache"|"dir"|"flag", path, upstream_modified,
fetched_at, sha256}`. SARIF run properties get the same, so a CI log shows what data a
"clean" verdict rested on.

## Fail-closed rules

- A fetch failure with a usable cached copy within `--max-db-age`: warn and use it.
- A fetch failure with no usable copy: that ecosystem's repos are errored gaps (exit 2).
- A corrupt zip is never used and never overwrites a good one.

## Testing

- Local HTTP fixture server: 200, 304, 500, truncated body, wrong hash, redirect off-host.
- Golden test: scan the demo fleet with only `--osv-dir` set.
- `--offline` with an empty cache produces gaps naming `fleetreach db sync`.
- Age gate: meta with old `Last-Modified` plus `--max-db-age 7d` → exit 2.

## Phasing

1. `--osv-dir` + `[settings.osv] dir` + per-ecosystem freshness gate (no network): S.
2. Auto-sync into the default cache + `db sync` / `db status`: S/M.
3. Optional: point the Go module-level matcher at `Go/all.zip` instead of a vuln.go.dev
   mirror, so one directory serves all eleven OSV-backed paths.

## Open questions

- Should auto-sync be on by default in the `network` build, or require `--sync`? Proposal:
  on by default (it is the whole point), `--offline` turns it off.
- Cache path: `~/.cache/fleetreach/` vs the existing `~/.cache/fleetaudit/reach/`. Pick
  one root and migrate.
- Export sizes for the largest ecosystems (npm, Maven) need measuring before choosing the
  default refresh interval.
