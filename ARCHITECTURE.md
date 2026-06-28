# Architecture

`fleetreach` is an **orchestration + correlation layer** over the audited
[`rustsec`](https://crates.io/crates/rustsec) engine. It is deliberately *not* a
scanner or an advisory database: it never scrapes advisory sites, parses
advisory TOML, or implements version-range matching. The trust boundary is
"structured data from `rustsec` + the user's config", never raw HTML.

## Crate graph

Dependencies point strictly **inward**; nothing depends outward.

```
cli  ──►  report  ──►  (FleetReport)
 │
 ├──────►  correlate  ──►  core
 │
 └──────►  scan  ──►  core
            (only crate that touches rustsec)
```

| Crate | Responsibility | Notable constraint |
|-------|----------------|--------------------|
| `core` | Domain model + serde wire contract (`FleetReport`, `VulnFinding`, `Occurrence`, `Severity`, …). | **No I/O. No `rustsec` types in the public API.** semver re-exported so the tree links one copy. |
| `scan` | All `rustsec` interaction: load the advisory DB and lockfiles, run the engine, map engine types onto `core`. Toolchain (`Collection::Rust`) scanning lives here. | No `rustsec` type escapes its public API; engine errors are flattened to typed `ScanError` variants. |
| `correlate` | Fold per-repo, single-occurrence findings into fleet-wide findings (group by RUSTSEC id / `(kind, id)`), dedup and sort occurrences, expose the per-occurrence verdict. | Pure; the proptest target. |
| `report` | Render a `FleetReport` to JSON or a table. | **Side-effect free** — returns strings, never writes streams or picks exit codes. |
| `cli` | Config loading, the multi-repo orchestration loop, report assembly, exit codes, and the binary. | `lib` holds the testable logic; `main.rs` is a thin shell (clap, DB loading, stream routing, process exit). |

Why `core` hides `rustsec`: it is the single decision that lets v2 enrichment
(EPSS, unsafe scoring, SARIF) land as **additive fields** without breaking
`schema_version: 1` consumers.

## Data flow of one `scan`

1. **Parse args** (clap). `--explain` short-circuits: load DB, print one advisory, exit.
2. **Load + validate `fleet.toml`** — paths must exist, ignores must be justified. Failure → exit `2`.
3. **Load the advisory DB** (`--db` path · `--offline` cache · fetch), check `--max-db-age`. Unusable/stale → exit `2`. Record commit + timestamp into provenance.
4. **Scan each repo serially** (no async in v1): resolve lockfile(s) (glob if set), run `rustsec`, map to `core`. A per-repo failure degrades to `Errored` and the run continues.
5. **Correlate**: group findings, merge + dedup occurrences, compute the per-occurrence verdict.
6. **Apply ignores** (recording stale ones), filter by `--min-severity`, optionally diff a `--baseline`.
7. **Summarize, sort, render** — payload to stdout, summary to stderr.
8. **Exit** per the §8 precedence.

## The fail-closed spine

A falsely-clean report is the worst possible output, so it is treated as a
defect class with dedicated tests. The tool never exits `0` unless it completed
a trustworthy scan. These force exit `2`: invalid config · advisory DB
unloadable without cache · DB older than `--max-db-age` (or age unverifiable) ·
zero repos scanned · **any repo errored** (a gap means the fleet cannot be
called clean). Unknown-severity vulnerabilities always gate, because we cannot
prove they sit below the threshold.

Every crate has `#![forbid(unsafe_code)]`; the `unwrap`/`expect`/`panic` family
is denied workspace-wide on externally-derived values.

## Concurrency

The advisory DB is loaded **once**; repos are scanned **serially** in v1
(lockfile parsing is cheap; DB fetch dominates wall time). No async runtime —
`tokio` is not a dependency. Revisit only if a real fleet shows lockfile parsing
as the bottleneck.

## Determinism

Report assembly is deterministic: occurrences sort by a total key and the
finding list sorts by (severity desc, id). The only wall-clock input —
`generated_at` — is **injected via provenance**, so the assembly layer is a pure
function of its inputs and renders byte-identically across runs.
