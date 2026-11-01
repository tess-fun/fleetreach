---
title: For incident response
description: When a new critical advisory or a compromised package lands, find every affected repository, the dependency chain that pulls it in, and the owner, in one command.
sidebar:
  order: 2
---

**The problem.** A worm hits npm, or Log4Shell is announced. The first question is "are we
affected, where, and who owns it?", and answering it repo by repo takes days.

**With fleetreach.**

```sh
fleetreach db sync                       # the newest advisories
fleetreach scan --why log4j-core         # every repo that has it, and how
fleetreach scan -f impact | head -n 20   # what is most widespread right now
fleetreach scan --release-age 72h        # what was pulled in during the outbreak window
```

<!-- run: fleetreach scan --why log4j-core -->
```console
$ fleetreach scan --why log4j-core
partner-api — org.apache.logging.log4j:log4j-core 2.14.1 (maven, direct):
  partner-api → org.apache.logging.log4j:log4j-core
```
<!-- /run -->

- `--why` works across all 12 ecosystems and shows the chain, so you know whether to bump
  the package or its parent.
- `--release-age` lists dependency versions published in the last few days, the ones a
  worm would have pushed.
- Known malware (`MAL-` advisories) is always critical and the fix queue says to remove it
  and rotate credentials.
- Repos with `owner` set give you the people to call. `--sync` refreshes every checkout
  first, so the answer reflects `main` today.

Then `fix plan` and `fix apply --open-pr` open the same verified bump in every affected repo.
See [Trace why a package is there](/fleetreach/docs/guides/trace-why-a-package-is-there/).
