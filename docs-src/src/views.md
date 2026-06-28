# Report views

The same findings can be reshaped with `-f <view>` to answer different
questions. The fleet-scale views are what single-repo tooling cannot give you.

## `impact` — which fix clears the most repos?

Ranks advisories by how many of your crates they hit.

```
Repos  Severity      Advisory            Affected                  Title
2      medium 6.2    RUSTSEC-2020-0071   payments-api, scheduler   Potential segfault in time
1      critical 9.8  RUSTSEC-2021-0003   ingest-worker             SmallVec::insert_many overflow
1      critical 9.8  RUSTSEC-2021-0097   ls-replacement            SM2 decryption buffer overflow
```

The lead row is a *medium*, not a critical: the `time` segfault is the one
advisory present in two repos, so a single bump clears both. That ordering is
the question single-repo tooling cannot answer.

## `blast` — direct vs transitive

Keeps the impact ranking but splits each advisory's reach into **direct** vs
**transitive** repos and adds a fix-path hint, because *how* you fix it depends
on the split.

```
Repos  Direct  Transitive  Fix       Severity      Advisory            Title
2      1       1           mixed     unknown       RUSTSEC-2025-0004   ssl select_next_proto UAF
1      1       0           manifest  critical 9.8  RUSTSEC-2021-0003   SmallVec::insert_many overflow
1      0       1           upstream  medium 6.2    RUSTSEC-2020-0071   Potential segfault in time
```

An advisory hitting its repos transitively can't be fixed by editing those
repos' manifests — you need an upstream bump or a dependency override
(`upstream`); a direct one can (`manifest`). A corpus study of the Go ecosystem
found ~3 in 4 vulnerable-dependency exposures are transitive, so a plain
affected-repo count hides the fix strategy.

## `packages` — your biggest fleet liability

Rolls the rows up to the *dependency*. One package often carries many advisories
across many repos, and a single bump clears them all.

```
Repos  Direct  Transitive  Advisories  Severity  Fix       Package
3      0       3           2           medium    upstream  time
2      1       1           7           unknown   mixed     openssl
1      1       0           1           critical  manifest  smallvec
```

Here a single `openssl` bump clears seven advisories — a rollup the per-advisory
views can't show. (`packages-json` emits the same data as JSON.)

## `fix-first` — what do I patch first?

Severity-dominant: actively-exploited (KEV) findings lead, then strict severity
bands, and only *within* a band does blast radius break the tie. The opposite
trade-off from `impact`, which floats a wide-but-informational warning to the
top.

## `remediation` — the fix queue

Where `fix-first` ranks *which advisory*, this prints *what to do about it*: the
concrete dependency bump. Each row is **batched**, so a single `bump tokio 1.0 →
1.38` clears every advisory that one upgrade resolves across every repo, and
breaking (semver-major) jumps are flagged so low-churn fixes go first. Advisories
with no published fix are called out honestly (`no fix: …`). With static
[reachability](./reachability.md), soundly-unreachable advisories drop to an
informational tail. (`remediation-json` emits the queue as JSON.)

## Prioritize by real-world risk

`--enrich` annotates each finding with **CISA KEV** (actively exploited) and
**FIRST EPSS** (exploit probability), re-ranks them into an action queue, and
adds a `Risk` column:

```
Severity      Risk      Advisory            Fix                       Title
critical 9.8  epss 88%  RUSTSEC-2021-0097   openssl-src → 111.16.0    SM2 decryption buffer overflow
high 7.5      epss 14%  RUSTSEC-2022-0013   regex 1.5.4 → 1.5.5       regex repetition DoS
critical 9.8  epss 2%   RUSTSEC-2021-0003   smallvec 1.6.0 → 0.6.14   SmallVec::insert_many overflow
```

The two `critical 9.8`s are tied by CVSS, but EPSS breaks the tie. Gate with
`--fail-on-kev` or `--min-epss 0.5`; both feeds can be supplied offline via
`--kev-file` / `--epss-file`.

## Provenance: `--why`

Every finding shows whether the flagged package is a direct or transitive
dependency and the chain that pulls it in. `--why <crate>` asks that across the
whole fleet at once:

```
$ fleetreach scan --why serde
cli-tools — serde 1.0.228 (direct):
  ripgrep → serde
file-finder — serde 1.0.228 (transitive):
  fd-find → globset → bstr → serde
```

## Tracking drift over time

`fleetreach diff <baseline.json> <current.json>` compares two saved reports and
splits findings into **new**, **fixed**, and **still-open** — the question a
single scan can't answer: *did this branch make the fleet better or worse?* It
is pure (no scanning or network), so it drops into CI as a cheap gate.
