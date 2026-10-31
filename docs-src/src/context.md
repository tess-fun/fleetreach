# Context and SSVC decisions

Severity, KEV and EPSS describe the vulnerability. They say nothing about the repo it sits in:
a critical CVE in an internal test tool and the same CVE in the internet-facing payments API
rank the same. Repo context fixes that. Tell fleetreach how exposed each repo is and what
breaks if it is compromised, and every finding gets an action from
[SSVC](https://certcc.github.io/SSVC/), the CISA and CERT/CC decision model:

| Outcome | Meaning |
|---------|---------|
| `immediate` | Act now, outside the normal process. |
| `out-of-cycle` | Fix ahead of the next scheduled update. |
| `scheduled` | Fix in the next scheduled update. |
| `defer` | No action for now. |

## Repo context

Values use SSVC's own names:

```toml
[settings.context.defaults]       # applied wherever a repo sets nothing
exposure       = "controlled"
mission_impact = "mef-support-crippled"
safety_impact  = "negligible"

[[repo]]
id             = "payments-api"
path           = "../payments-api"
exposure       = "open"             # small | controlled | open
mission_impact = "mission-failure"  # degraded | mef-support-crippled | mef-failure | mission-failure
safety_impact  = "negligible"       # negligible | marginal | critical | catastrophic
owner          = "team-payments"    # free text: a team, a GitHub team or an email
tags           = ["pci", "tier-1"]
```

- **`exposure`** (System Exposure): `small` for a local service or a program with few users,
  `controlled` when access is restricted (an internal network, a VPN), `open` when it is
  reachable from the internet.
- **`mission_impact`**: what happens to your organization's work if this system is
  compromised. MEF stands for *mission essential function*: `degraded`, then
  `mef-support-crippled`, then `mef-failure`, then `mission-failure`.
- **`safety_impact`**: physical, environmental or psychological harm to people, from
  `negligible` to `catastrophic`. Most software is `negligible`.

SSVC turns on when `[settings.context.defaults]` exists or any repo sets one of these three.
A repo that leaves a value unset, with no default for it, is decided with the most urgent
value (`open`, `mission-failure`, `catastrophic`), marked `fail_closed` in the report, and
named in a note. Missing context never lowers a priority.

`owner` and `tags` alone do not turn SSVC on; they feed the `owners` view.

The same fields work on a `[[source]]`, for every repo a GitHub or GitLab org, group or URL
list discovers. A `[[repo]]` with the same id keeps its own:

```toml
[[source]]
kind = "github"
org = "acme"
exposure = "controlled"
owner = "platform"
```

## How each decision is made

| Decision point | Source |
|----------------|--------|
| Exploitation | `active` if the advisory is in CISA KEV. Raised to CISA's own assessment when [Vulnrichment](#cisa-vulnrichment) has one. `public-poc` if its EPSS is at least `[settings.ssvc] poc_epss` (off by default; EPSS is a proxy, not evidence). Otherwise `none`. |
| Automatable | CISA's assessment when Vulnrichment has one. Otherwise `yes` when the advisory's CVSS vector is network, low complexity, no privileges and no user interaction (`AV:N/AC:L/PR:N/UI:N`, and `AT:N` for CVSS 4). No vector counts as `yes`. |
| System Exposure | the repo's `exposure`. |
| Human Impact | SSVC's table over `safety_impact` and `mission_impact`. |

The four points go through the published deployer table `ssvc:DT_DP:1.0.0`, which is tested
row by row against CERT/CC's data. Exploitation needs the KEV catalog, so decisions need
`--enrich` (or `--kev-file` offline). Without it fleetreach decides nothing and says so,
rather than guessing `none`.

### CISA Vulnrichment

CISA publishes its own SSVC assessment for many CVEs at
[cisagov/vulnrichment](https://github.com/cisagov/vulnrichment). Where one exists it is
better evidence than the proxies above, so fleetreach uses it: CISA's Exploitation can raise
the value (never lower it below a KEV `active`), and CISA's Automatable replaces the one read
from the CVSS vector. The reason column says when CISA's value decided.

With `--enrich` the records are fetched from GitHub (each CVE id is sent, as EPSS already
sends them to FIRST) and cached for a day under `~/.cache/fleetreach/vulnrichment/`. Offline,
point `--vulnrichment-dir` at a clone of the repository. The offline `--kev-file` path sends
nothing anywhere.

### Your own decision table

SSVC fixes the decision points and their values, and expects each organization to choose its
own outcomes. Copy CERT/CC's
[deployer table CSV](https://github.com/CERTCC/SSVC/blob/main/data/csv/ssvc/deployer_patch_application_priority_1_0_0.csv),
change the last column, and point fleetreach at it:

```toml
[settings.ssvc]
table = "ssvc-deployer.csv"       # relative to fleet.toml
```

The header must name the Exploitation, System Exposure, Automatable and Human Impact columns,
the outcome is the last column, and all 72 combinations must be listed exactly once, so no
finding can be left undecided. The report records the table as `custom:<sha256>`, so a gate
result traces back to the exact file.

A sound signal that the vulnerable code cannot run (a phantom optional dependency, or a
`NotReachable` [reachability](./reachability.md) verdict) forces `defer`. These are the same
signals that make the VEX output say `not_affected`. A heuristic or `unknown` reachability
never changes the outcome.

## Views and output

```sh
fleetreach scan -c fleet.toml --enrich -f ssvc       # every decision, most urgent first
fleetreach scan -c fleet.toml --enrich -f owners     # the fix queue, one section per owner
```

The `ssvc` view lists each repo and package with its outcome, the decision vector
(`E:A/X:O/A:Y/HI:VH` reads Exploitation active, Exposure open, Automatable yes, Human Impact
very high) and the reason. With decisions present, `fix-first` and `remediation` gain an SSVC
column and sort by it first, and `impact`, `blast` and `packages` gain the most urgent outcome
and a **weighted reach**: each affected repo counts at the weight of its outcome, 8 for
`immediate`, 4 for `out-of-cycle`, 2 for `scheduled` and 0 for `defer`, and the views rank by
it first. A dependency in two internet-facing repos then outranks one in five internal tools.
Change the weights with:

```toml
[settings.ssvc]
weights = { immediate = 10, out-of-cycle = 5, scheduled = 1, defer = 0 }
```
 SARIF results carry the outcome as a property and take their
level from it: `immediate` and `out-of-cycle` are errors, `scheduled` a warning, `defer` a
note. In JSON, `context` lists each repo's resolved context and `ssvc.decisions` every
decision.

## Gating

```sh
fleetreach scan -c fleet.toml --enrich --fail-on-ssvc out-of-cycle
```

`--fail-on-ssvc <outcome>` exits 1 when any decision is at or above the outcome. Given on its
own it replaces the default `--fail-on low`, so the decision gates instead of the raw
severity; an explicit `--fail-on` still applies alongside it, and known malware always fails.
If no decisions can be made (no context, or no KEV data) the gate exits 2 instead of passing.
