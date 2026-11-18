---
title: Cut alert noise
description: Replace a CVSS sort with decisions. fleetreach ranks findings by exploitation and exposure with SSVC, proves which vulnerable functions are reached, and records what does not apply as VEX that Trivy and Grype honour.
sidebar:
  order: 2
---

**The problem.** The scanner says 211 findings and 15 of them are critical. Teams stop
reading. Most of those findings are not being exploited, are in repos nobody can reach from
the internet, or sit in code that is never called, and the tool cannot tell which.

**With fleetreach**, every finding gets a decision, and a reason for it.

## Decide by exploitation and exposure

SSVC combines what is known about exploitation (CISA KEV, EPSS, public exploit code) with
each repo's own exposure and mission impact from `fleet.toml`. Of the demo fleet's 257
decisions (one per finding in each repo), 2 are `immediate`, 25 `out-of-cycle`, and the
other 230 can wait for a scheduled release or be deferred:

<!-- run: fleetreach scan -f ssvc --enrich | head -n 11 -->
```console
$ fleetreach scan -f ssvc --enrich | head -n 11
┌──────────────┬───────────────────┬─────────────────────┬─────────────────┬────────────────────────────────────────────────────┬─────────────────┬─────────────────────────────────────┐
│ Outcome      ┆ Vector            ┆ Advisory            ┆ Repo            ┆ Package                                            ┆ Owner           ┆ Why                                 │
╞══════════════╪═══════════════════╪═════════════════════╪═════════════════╪════════════════════════════════════════════════════╪═════════════════╪═════════════════════════════════════╡
│ immediate    ┆ E:A/X:O/A:N/HI:VH ┆ GHSA-7rjr-3q55-vv33 ┆ partner-api     ┆ org.apache.logging.log4j:log4j-core 2.14.1         ┆ team-platform   ┆ in CISA KEV                         │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ immediate    ┆ E:A/X:O/A:Y/HI:VH ┆ GHSA-jfh8-c2jp-5v3q ┆ partner-api     ┆ org.apache.logging.log4j:log4j-core 2.14.1         ┆ team-platform   ┆ in CISA KEV                         │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ out-of-cycle ┆ E:N/X:O/A:Y/HI:VH ┆ GHSA-3pxv-7cmr-fjr4 ┆ partner-api     ┆ org.apache.logging.log4j:log4j-core 2.14.1         ┆ team-platform   ┆                                     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ out-of-cycle ┆ E:N/X:O/A:Y/HI:VH ┆ GHSA-3wrr-7qpf-2prh ┆ partner-api     ┆ com.fasterxml.jackson.core:jackson-databind 2.13.2 ┆ team-platform   ┆                                     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

Gate on the decision rather than the score:

```sh
fleetreach scan --enrich --fail-on-ssvc out-of-cycle   # exits 1 on a decision at or above it
fleetreach scan --enrich --fail-on-kev                 # exits 1 on anything in CISA KEV
```

## Show whether the vulnerable code is reached

`--reachability` follows imports from your own code to the vulnerable package and prints
the chain, in npm, Python, Ruby, PHP, .NET, Java, Elixir and Swift. For Rust, Java and .NET a call graph goes
further: a function no path reaches is set aside, with the proof recorded.

<!-- run: fleetreach scan -c ecosystems/rust.toml --reachability | head -n 9 -->
```console
$ fleetreach scan -c ecosystems/rust.toml --reachability | head -n 9
┌──────────────┬───────────┬───────────────────┬────────────────────────────────────────────────────────────────┬─────────────────────────────────────────────────┐
│ Severity     ┆ Reach     ┆ Advisory          ┆ Title                                                          ┆ Locations                                       │
╞══════════════╪═══════════╪═══════════════════╪════════════════════════════════════════════════════════════════╪═════════════════════════════════════════════════╡
│ critical 9.8 ┆ in source ┆ RUSTSEC-2021-0003 ┆ Buffer overflow in SmallVec::insert_many                       ┆ payments-api/smallvec@1.6.0 → 1.6.1 (direct)    │
│              ┆           ┆                   ┆ affects fn: insert_many                                        ┆                                                 │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ high 7.5     ┆ ?         ┆ RUSTSEC-2022-0013 ┆ Regexes with large repetitions on empty sub-exp…               ┆ payments-api/regex@1.5.4 → 1.5.5 (direct)       │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ medium 6.2   ┆ not found ┆ RUSTSEC-2020-0071 ┆ Potential segfault in the time crate                           ┆ payments-api/time@0.1.45 → 0.2.23 (via chrono)  │
```
<!-- /run -->

## Record what does not apply, once

A finding someone has looked at should stay decided. `fleetreach triage set` writes the
decision as a file in git, with who, why and until when. `scan -f vex` turns triage,
`[[settings.vex_assertion]]` entries and proven reachability into OpenVEX, CSAF or
CycloneDX VEX:

<!-- run: fleetreach scan -f vex --vex-author security@acme.example | jq '[.statements[].status] | group_by(.) | map({(.[0]): length}) | add' -->
```console
$ fleetreach scan -f vex --vex-author security@acme.example | jq '[.statements[].status] | group_by(.) | map({(.[0]): length}) | add'
{
  "not_affected": 2,
  "under_investigation": 257
}
```
<!-- /run -->

Trivy and Grype both honour these statements, so the same decision quiets every tool. A
statement that no longer holds is caught by `fleetreach vex check`, which fails when a
committed VEX document has drifted from a fresh scan.

See [Prioritise with KEV, EPSS and SSVC](/fleetreach/docs/guides/prioritise-with-kev-epss-and-ssvc/),
[Check reachability](/fleetreach/docs/guides/check-reachability/),
[Triage findings](/fleetreach/docs/guides/triage-findings/) and
[Suppress with OpenVEX](/fleetreach/docs/guides/suppress-with-openvex/).
