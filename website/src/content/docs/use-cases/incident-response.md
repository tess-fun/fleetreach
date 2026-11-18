---
title: Respond to an incident
description: When a new critical advisory or a compromised package lands, find every affected repository and image, the dependency chain that pulls it in and the owner, check the fix before asking anyone to apply it, and open it everywhere.
sidebar:
  order: 5
---

**The problem.** A worm hits npm, or Log4Shell is announced. The first question is "are we
affected, where, and who owns it?", and answering it repo by repo takes days. The second is
"which version fixes it?", and the obvious answer is sometimes wrong.

**With fleetreach**, in four commands:

```sh
fleetreach db sync                       # the newest advisories
fleetreach scan --sync --why log4j-core  # every repo that has it, how, as of main today
fleetreach scan --release-age 72h        # what was pulled in during the outbreak window
fleetreach whatif --report report.json --bump axios@1.12.0   # check the fix first
```

## Where it is, and how it got there

<!-- run: fleetreach scan --why log4j-core -->
```console
$ fleetreach scan --why log4j-core
partner-api — org.apache.logging.log4j:log4j-core 2.14.1 (maven, direct):
  partner-api → org.apache.logging.log4j:log4j-core
```
<!-- /run -->

`--why` works across all 12 ecosystems and shows the chain, so you know whether to bump the
package or its parent. Repos with `owner` set give you the people to call.

## Check the fix before nine teams apply it

`whatif` re-matches a saved report with the bumps you propose, before anyone edits a file.
Here, bumping axios to 1.12.0 looks like a fix, but it clears 10 findings and adds 24:

<!-- run: fleetreach whatif --report report.json --bump axios@1.12.0 | head -n 10 -->
```console
$ fleetreach whatif --report report.json --bump axios@1.12.0 | head -n 10
what-if: 1 bump(s)
  npm axios -> 1.12.0 (2 repos): clears 10, leaves 40, new 24

open findings  critical  high medium  low unknown  total
  before         15    86    102   21      33    257
  after          15    86    116   21      33    271

per repo
  admin-dashboard: 49 -> 56 (cleared 5, new 12)
  checkout-web: 36 -> 43 (cleared 5, new 12)
```
<!-- /run -->

`fix plan` checks its own targets the same way (`--osv-dir`), so a target that carries
advisories of its own is caught before a pull request exists:

```sh
fleetreach fix plan --report report.json > plan.json
fleetreach fix apply plan.json --open-pr     # one verified PR per repo
```

- Known malware (`MAL-` advisories) is always critical, and the fix queue says to remove it
  and rotate credentials.
- `--release-age` lists dependency versions published in the last few days, the ones a worm
  would have pushed.
- `fleetreach notify` tells each owner what is new for them, in Slack, a webhook or an issue.

See [Trace why a package is there](/fleetreach/docs/guides/trace-why-a-package-is-there/)
and [Plan and apply fixes](/fleetreach/docs/guides/plan-and-apply-fixes/).
