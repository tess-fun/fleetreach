---
title: fleetreach triage
description: "fleetreach triage: Decisions on findings, kept as files in git: set, list and export them. Every flag, from the binary's help."
sidebar:
  order: 12
---

Decisions on findings, kept as files in git: set, list and export them

```text
Decisions on findings, kept as files in git: set, list and export them

Usage: fleetreach triage <COMMAND>

Commands:
  set     Record a decision on a finding, appending to its log
  list    Show the decisions
  export  Publish the decisions as OpenVEX
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## fleetreach triage set

Record a decision on a finding, appending to its log

```text
Record a decision on a finding, appending to its log

Usage: fleetreach triage set [OPTIONS] --package <PACKAGE> --ecosystem <ECOSYSTEM> --state <STATE> <ADVISORY>

Arguments:
  <ADVISORY>  The advisory id, as the scan reports it

Options:
      --package <PACKAGE>              the package the decision is about
      --ecosystem <ECOSYSTEM>          its ecosystem, as in the report (npm, pypi, cargo, ...)
      --state <STATE>                  the state to record [possible values: affected, in_triage, accepted_risk, false_positive, not_affected, fixed]
      --reason <REASON>                why (required to set a finding aside)
      --assignee <ASSIGNEE>            who owns the finding
      --expires <YYYY-MM-DD>           the last day the decision holds
      --justification <JUSTIFICATION>  an OpenVEX justification label
      --alias <ALIAS>                  another id of the advisory, for export (repeatable)
      --repo <REPO>                    only this repo (repeatable; default: the whole fleet)
      --by <BY>                        who decided (default: git's user.name, else $USER)
  -c, --config <CONFIG>                fleet.toml (default: ./fleet.toml, if there)
      --dir <DIR>                      the triage directory (default: `triage/` beside fleet.toml)
  -h, --help                           Print help
```

## fleetreach triage list

Show the decisions

```text
Show the decisions

Usage: fleetreach triage list [OPTIONS]

Options:
      --state <STATE>        only this state [possible values: affected, in_triage, accepted_risk, false_positive, not_affected, fixed]
      --assignee <ASSIGNEE>  only this assignee
      --expired              only decisions that have expired
      --json                 print JSON instead of a table
  -c, --config <CONFIG>      fleet.toml (default: ./fleet.toml, if there)
      --dir <DIR>            the triage directory (default: `triage/` beside fleet.toml)
  -h, --help                 Print help
```

## fleetreach triage export

Publish the decisions as OpenVEX

```text
Publish the decisions as OpenVEX

Usage: fleetreach triage export [OPTIONS]

Options:
  -f, --format <FORMAT>  output format [default: openvex] [possible values: openvex]
      --author <AUTHOR>  OpenVEX author (default: settings.vex.author)
  -c, --config <CONFIG>  fleet.toml (default: ./fleet.toml, if there)
      --dir <DIR>        the triage directory (default: `triage/` beside fleet.toml)
  -h, --help             Print help
```
