---
title: Exit codes
description: "fleetreach's exit codes, the CI contract: 0 clean, 1 findings tripped the gate, 2 something could not be read or the run failed."
sidebar:
  order: 2
---

| Code | `scan` | Meaning |
|------|--------|---------|
| `0` | every repo read, nothing tripped the gate | safe to pass |
| `1` | a finding (or, with `--fail-on-warnings`, a warning) tripped the gate, or a triage decision on an open finding expired | fix, ignore or decide again |
| `2` | a repo, source or database could not be read, or the run failed | never a pass |

`2` wins over `1`: a run with findings and an unreadable repo exits 2, so a partial scan is
never mistaken for a complete one.

On the demo fleet's [`notifications-gateway`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/notifications-gateway), whose worst finding is
medium, the gate's level decides:

<!-- run: fleetreach scan -c ecosystems/swift.toml --fail-on high >/dev/null; echo "exit $?" -->
```console
$ fleetreach scan -c ecosystems/swift.toml --fail-on high >/dev/null; echo "exit $?"
Scanned 1 repo(s) (0 errored): 2 vulns, 0 warning(s); max severity medium.
exit 0
```
<!-- /run -->

<!-- run: fleetreach scan -c ecosystems/swift.toml --fail-on medium >/dev/null; echo "exit $?" -->
```console
$ fleetreach scan -c ecosystems/swift.toml --fail-on medium >/dev/null; echo "exit $?"
Scanned 1 repo(s) (0 errored): 2 vulns, 0 warning(s); max severity medium.
exit 1
```
<!-- /run -->

[`data-pipeline`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/data-pipeline)'s `requirements.txt` is pinned but shows no sign a
resolver wrote it, so it is partial coverage, and `--require-full-coverage` makes that a 2
whatever the findings:

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

| Command | `1` | `2` |
|---------|-----|-----|
| `diff` | a new finding trips the gate | a report could not be read |
| `licenses` | a license is denied | a source could not be read |
| `history sla` | a finding is past its deadline | no `[settings.sla]` |
| `vex check` | the document has drifted | |
| `sbom` | | a source could not be fully read (its SBOM is still written, marked incomplete) |
| `--why` | | the package is in no repo |

`--exit-zero` on `diff` makes it report only.
