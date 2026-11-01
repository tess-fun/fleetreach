---
title: Prioritise with KEV, EPSS and SSVC
description: Rank findings by real-world exploitation (CISA KEV, FIRST EPSS) and each repo's exposure, and get an act-now or schedule-it decision from the CISA SSVC model.
sidebar:
  order: 3
---

Severity describes the vulnerability, not your system. fleetreach adds two kinds of
evidence: whether the vulnerability is being exploited (CISA KEV) or likely to be (FIRST
EPSS), and how exposed each repo is. Together they give every finding an SSVC decision:
`immediate`, `out-of-cycle`, `scheduled` or `defer`.

## 1. Add exploitation data

```sh
fleetreach scan --enrich
```

`--enrich` downloads the CISA Known Exploited Vulnerabilities catalog and EPSS scores
(network builds; offline, pass `--kev-file` and `--epss-file`). Each finding gains a `Risk`
column, and `fix-first` puts KEV findings first:

<!-- run: fleetreach scan -f fix-first --enrich | head -n 9 -->
```console
$ fleetreach scan -f fix-first --enrich | head -n 9
┌─────┬──────────────┬───────────────────┬───────┬───────────────┬─────────────────────┬──────────────────────────────────────────┐
│ #   ┆ SSVC         ┆ Severity          ┆ Repos ┆ Exploit       ┆ Advisory            ┆ Title                                    │
╞═════╪══════════════╪═══════════════════╪═══════╪═══════════════╪═════════════════════╪══════════════════════════════════════════╡
│ 1   ┆ immediate    ┆ critical 10.0 KEV ┆ 1     ┆ KEV EPSS 100% ┆ GHSA-jfh8-c2jp-5v3q ┆ Remote code injection in Log4j           │
├╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2   ┆ immediate    ┆ critical 9.0 KEV  ┆ 1     ┆ KEV EPSS 100% ┆ GHSA-7rjr-3q55-vv33 ┆ Incomplete fix for Apache Log4j vulnera… │
├╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 3   ┆ out-of-cycle ┆ high 8.6 KEV      ┆ 1     ┆ KEV EPSS 72%  ┆ GHSA-mrrh-fwg8-r2c3 ┆ tj-actions changed-files through 45.0.7… │
├╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

Gate on it with `--fail-on-kev` or `--min-epss 0.5`.

## 2. Describe each repo

```toml title="fleet.toml"
[settings.context.defaults]       # for every repo that sets nothing
exposure       = "controlled"     # small | controlled | open
mission_impact = "degraded"       # degraded | mef-support-crippled | mef-failure | mission-failure
safety_impact  = "negligible"     # negligible | marginal | critical | catastrophic

[[repo]]
id             = "payments-api"
path           = "../payments-api"
exposure       = "open"           # reachable from the internet
mission_impact = "mission-failure"
owner          = "team-payments"
```

A repo that leaves a value unset, with no default, is decided with the most urgent value and
marked `fail_closed`: missing context never lowers a priority.

## 3. Read the decisions

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

The vector reads `E` exploitation (`A`ctive, `P`oC, `N`one), `X` exposure, `A` automatable
and `HI` human impact. The decision comes from CISA's published deployer table, which
fleetreach checks row by row against CERT/CC's data. CISA's own assessments from
[Vulnrichment](https://github.com/cisagov/vulnrichment) are used where they exist.

With decisions present, `fix-first` and `remediation` sort by them first, and `impact`,
`blast` and `packages` weight each repo by its outcome.

## 4. Split the work by team

<!-- run: fleetreach scan -f owners --enrich | head -n 12 -->
```console
$ fleetreach scan -f owners --enrich | head -n 12
team-data (2 repo(s): data-pipeline, ml-service)
┌───┬───────────┬────────────────────────────────────────────────┬──────────────┬───────────────┬───────┬─────────┬─────────┬────────────────────────┐
│ # ┆ SSVC      ┆ Action                                         ┆ Severity     ┆ Resolves      ┆ Repos ┆ Reach   ┆ Exploit ┆ Bump risk              │
╞═══╪═══════════╪════════════════════════════════════════════════╪══════════════╪═══════════════╪═══════╪═════════╪═════════╪════════════════════════╡
│ 1 ┆ scheduled ┆ bump urllib3 1.26.12 → 2.8.0 (breaking)        ┆ high 8.1     ┆ 10 advisories ┆ 2     ┆ unknown ┆ EPSS 3% ┆ high                   │
│   ┆           ┆   or 1.26.19 on 1.x (2 repos, 7 left open)     ┆              ┆               ┆       ┆         ┆         ┆                        │
├╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2 ┆ scheduled ┆ bump flask 2.2.2 → 3.1.3 (breaking)            ┆ high 7.5     ┆ 2 advisories  ┆ 1     ┆ unknown ┆ EPSS 1% ┆ high                   │
│   ┆           ┆   or 2.2.5 on 2.x (1 repo, 1 left open)        ┆              ┆               ┆       ┆         ┆         ┆                        │
├╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 3 ┆ defer     ┆ bump certifi 2022.9.24 → 2026.10.18 (breaking) ┆ critical 7.5 ┆ 4 advisories  ┆ 1     ┆ unknown ┆ EPSS 1% ┆ high · 1 on 2026.10.23 │
│   ┆           ┆   or 2022.12.7 on 2022.x (1 repo, 3 left open) ┆              ┆               ┆       ┆         ┆         ┆                        │
```
<!-- /run -->

## 5. Gate on the decision

```sh
fleetreach scan --enrich --fail-on-ssvc out-of-cycle
```

Given alone, `--fail-on-ssvc` replaces the default severity gate. If no decision can be made
(no context, no KEV data), it exits 2 rather than passing.

## Your own table

SSVC expects each organisation to choose its outcomes. Copy CERT/CC's
[deployer table CSV](https://github.com/CERTCC/SSVC/blob/main/data/csv/ssvc/deployer_patch_application_priority_1_0_0.csv),
change the last column and set `[settings.ssvc] table = "ssvc-deployer.csv"`. All 72
combinations must be present; the report records the file's hash.
