---
title: Audit a client's code
description: "Assess a client's whole codebase in a day: a dependency risk inventory across every repository, image and language, without installing anything in their environment, building their software or running their code."
sidebar:
  order: 7
---

**The problem.** A due-diligence review, a pentest scoping or a security assessment needs a
picture of a client's dependency risk across all their code, quickly, without building
their software or installing agents, and a report whose limits are stated.

**With fleetreach**, point it at their checkouts, their org with a read token, or their
images:

```sh
fleetreach scan -c client.toml --enrich -f fix-first > findings.txt
fleetreach scan -c client.toml --enrich --history-dir history/ -f json > report.json
fleetreach sbom -c client.toml -o boms/
fleetreach licenses -c client.toml -f json > licenses.json
fleetreach report html --history-dir history/ -c client.toml -o assessment.html
```

## Honest about coverage

Anything that could not be fully read is named, with the reason. With
`--require-full-coverage`, a partial read is a failed run (exit 2), so a report never
claims more than was checked:

<!-- run: fleetreach scan -c ecosystems/pypi.toml --require-full-coverage >/dev/null; echo "exit $?" -->
```console
$ fleetreach scan -c ecosystems/pypi.toml --require-full-coverage >/dev/null; echo "exit $?"
note: 1 source(s) scanned with incomplete coverage (findings outside what was read were never matched):
  data-pipeline: requirements.txt [partial] every requirement is pinned, but nothing shows the file lists the full transitive set (no pip-compile or uv header, `# via` annotations or hashes); dependencies of these packages may be missing
Scanned 2 repo(s) (0 errored): 27 vulns, 0 warning(s); max severity critical. Incomplete coverage: 1 source(s) in 1 repo(s).
error: incomplete coverage under --require-full-coverage (see note above)
exit 2
```
<!-- /run -->

## Safe on their code, and on a laptop with no network

- **Nothing runs**: lockfiles and images are read as data, nothing is built and no package
  scripts run.
- **Offline**: take the advisory data with you as one bundle, checked by its hash on import:

```sh
fleetreach db bundle --osv-dir ./data -o data.tar        # at the office: prints the sha256
fleetreach db import --bundle data.tar --sha256 <hash> --osv-dir ./data
fleetreach scan -c client.toml --offline --osv-dir ./data
```

- **Reproducible**: the report records the advisory data version and each repo's commit,
  `--db-snapshot` pins a rerun to exactly the same data, and SBOMs are byte-identical with
  `SOURCE_DATE_EPOCH`.

The JSON report and SBOMs are inputs to your own tooling; the HTML report is ready to hand
over.

See [Run offline or air-gapped](/fleetreach/docs/guides/run-offline-or-air-gapped/) and
[Coverage and fail-closed](/fleetreach/docs/concepts/coverage-and-fail-closed/).
