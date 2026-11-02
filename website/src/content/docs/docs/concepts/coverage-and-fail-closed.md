---
title: Coverage and failing closed
description: fleetreach never reports a repo clean unless it read it in full. How errored repos, partial and direct-only coverage, exit code 2 and --require-full-coverage work.
sidebar:
  order: 3
---

A security tool's worst output is a false clean: a repo reported safe because it was not
really read. fleetreach is built so that cannot happen silently.

**Exit codes.** `0` means every repo was read and nothing tripped the gate. `1` means
findings tripped it. `2` means something could not be read, or the run failed, even if
other repos had findings.

**Errored repos.** A repo with no readable source, a missing advisory database for its
ecosystem, or a failed clone is an errored gap, listed in the report, never counted clean.

**Coverage labels.** A source that was read, but not completely, is labelled:

| Coverage | Example |
|----------|---------|
| full | a lockfile with the whole resolved tree |
| partial | `pip freeze` output, a `pom.xml` with an unresolved parent, `bun.lockb`, an SPDX SBOM |
| direct-only | a requirements file with ranges, `.csproj` files without `project.assets.json` |

What was read is still matched; the gap is named in the report with the reason. Pass
`--require-full-coverage` to turn any label below full into exit 2. On the demo fleet's
[`data-pipeline`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/data-pipeline), a pinned `requirements.txt` with no sign a resolver
wrote it:

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

**Unknowns count.** A finding without a severity counts as at least the gate's level. A
finding without KEV data gets no SSVC decision, and `--fail-on-ssvc` then exits 2.
Reachability only marks something not reachable on a sound proof.

**History.** A run that exited 2, an errored repo or a partly read source never marks a
finding fixed: absent data is not a fix.
