---
title: For consultancies and audits
description: "Assess a client's whole codebase in a day: a dependency risk inventory across every repository and language, without installing anything in their environment or running their code."
sidebar:
  order: 5
---

**The problem.** A due-diligence review, a pentest scoping or a security assessment needs a
picture of a client's dependency risk across all their code, quickly, without building their
software or installing agents.

**With fleetreach**, point it at their checkouts (or their org, with a read token):

```sh
fleetreach scan -c client.toml --enrich -f fix-first > findings.txt
fleetreach scan -c client.toml --enrich --history-dir history/ -f json > report.json
fleetreach sbom -c client.toml -o boms/
fleetreach licenses -c client.toml -f json > licenses.json
fleetreach report html --history-dir history/ -c client.toml -o assessment.html
```

- **Safe on their code**: lockfiles are read, nothing is built and no package scripts run.
- **Works offline** on a disconnected laptop with synced advisory data.
- **Honest about coverage**: anything that could not be read is named, so the report states
  its own limits.
- **Reproducible**: the report records the advisory data versions and commit of each repo,
  and SBOMs are byte-identical with `SOURCE_DATE_EPOCH`.

The JSON report and SBOMs are inputs to your own tooling; the HTML report is ready to hand
over.
