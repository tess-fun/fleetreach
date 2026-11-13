---
title: Detect supply-chain signals
description: Flag install scripts, git and URL dependencies, unexpected registries, missing checksums, tag-pinned GitHub Actions, typosquats, brand-new releases and packages new to the fleet.
sidebar:
  order: 16
---

`--signals` adds supply-chain warnings from the lockfiles already read, with no network.
They are warnings, never vulnerabilities, and gate only with `--fail-on-warnings`.

<!-- run: fleetreach scan --signals | tail -n 7 -->
```console
$ fleetreach scan --signals | tail -n 7
┌─────────┬───────────────────────────────┬───────────────────────────────────────────────────────┐
│ Kind    ┆ Advisory                      ┆ Locations                                             │
╞═════════╪═══════════════════════════════╪═══════════════════════════════════════════════════════╡
│ unsound ┆ RUSTSEC-2023-0072             ┆ payments-api/openssl@0.10.38 → 0.10.60 (direct)       │
├╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ notice  ┆ fleetreach:mutable-action-ref ┆ checkout-web/tj-actions/changed-files@44.0.0 (direct) │
└─────────┴───────────────────────────────┴───────────────────────────────────────────────────────┘
```
<!-- /run -->

It flags:

- packages that run an install script;
- packages fetched from git, a URL or a path;
- packages from a registry outside the public ones (add yours with
  `[settings.signals] registries = ["npm.example.com"]`; lookalike hosts are caught);
- registry packages with no checksum;
- third-party GitHub Actions pinned to a tag or branch their owner can move, instead of a
  commit SHA (the `tj-actions/changed-files` attack);
- possible typosquats: npm, PyPI and Cargo names one edit from a popular package they are
  not. The popular names are bundled, so nothing is sent anywhere.

## Brand-new releases

```sh
fleetreach scan --release-age 72h
```

flags dependency versions published less than 72 hours ago, which is what you want to know
during a worm outbreak. Publish times come from deps.dev (each package's name and version is
sent; answers are cached). A version deps.dev cannot date is listed, never assumed old.

## What registries say

`--health` asks each package's registry what a lockfile cannot show:

| Warning | Registry |
|---------|----------|
| `deprecated` | npm, NuGet, Go (`// Deprecated:` in the newest `go.mod`) |
| `yanked` | PyPI, RubyGems, crates.io, NuGet (unlisted) |
| `abandoned`, with its replacement | Packagist |
| `retracted` | Go |
| `retired` | Hex |
| `relocated`, with the new coordinates | Maven |
| `archived` | GitHub repos, with `GITHUB_TOKEN` or `GH_TOKEN` set |
| `low-scorecard` | repos scoring under `[settings.health] min_scorecard` on OpenSSF Scorecard |

```text
fleetreach:deprecated:npm/request  npm package request is deprecated: request has been deprecated, ...
fleetreach:retracted:go/lukechampine.com/blake3@v1.4.0  go module lukechampine.com/blake3 v1.4.0 was retracted: ...
```

Ids name the package, and the version for what is said of one version, so
`[[settings.ignore]]` can take one out. Warnings on dev packages keep `scope: dev`.

`--health` sends the name and version of each package from a public registry to that registry.
Git, path and other-registry packages are not sent. With `min_scorecard` or a GitHub token
those names also go to deps.dev, to find the source repo, and with a token the repo names go to
GitHub. Package answers are cached for a week.

A package with no answer, because the run was offline, the registry failed or it does not know
the package, is a coverage gap, never clean: it shows in the report and fails
`--require-full-coverage`. `--offline` reads the cache however old it is. Without a token,
archived repos are not checked, and a note says so. Julia's registry records none of this, and
PyPI's project status (PEP 792) is not read yet.

## New to the fleet

With `--history-dir`, `--signals` also flags packages whose name no earlier recorded run has
read. The first recorded run is the baseline and flags nothing.

## What package code can do

`--capabilities` reads the code of each npm and PyPI package the lockfiles pin by hash. It
warns above all on what a version **adds** over the release before it:

```text
fleetreach:adds-install-network:npm/pad@1.0.1  npm package pad 1.0.1 adds network access to install-time code (1.0.0 had none): i.js
```

| Capability | Read as |
|------------|---------|
| `network` | `http`, `https`, `net`, `dns`, `fetch(`, `WebSocket`; Python `socket`, `urllib.request`, `requests`, `httpx`; `curl` or `wget` in an install script or through `child_process` |
| `shell` | `child_process`; Python `subprocess`, `os.system`, `os.popen` |
| `filesystem` | `fs`; Python `open(`, `shutil` |
| `env` | `process.env`; Python `os.environ`, `os.getenv` |
| `eval` | `eval(`, `new Function(`, `vm`; Python `eval(`, `exec(`, `marshal.loads` |
| `obfuscated` | `_0x` names or dense `\x` escapes; Python `exec` of decoded data, PyArmor |
| `high-entropy` | a long base64 or hex string that looks random, not a `data:` URI |
| `native-code` | an ELF, Mach-O or PE file, or a `.node` addon |
| `install-script` | npm `preinstall`, `install`, `postinstall`; a `.pth` file that imports |

Code is placed by when it runs:
- **Install-time:** npm install scripts, the files they start with `node` and what those
  require, and a wheel's `.pth` files.
- **Build-time:** a source distribution's `setup.py`.
- **Runtime:** everything else.

The id says which: `adds-install-network`, `adds-build-shell`, `adds-env`. A few warnings
stand without a previous release:
- network, shell, eval, obfuscation and high-entropy strings in install-time code;
- network, obfuscation and high-entropy strings in `setup.py`;
- obfuscated code anywhere.

A compiler call or an `exec` of a version file in `setup.py` is normal, so it shows only when
a version adds it. Tests, docs and examples are not read.

Each archive and its previous release come from the public registry. Each must match its hash:
the lockfile's for the version in use, the registry's for the one before. Archives are read in
memory as bytes, never unpacked and never run. Profiles are cached by hash, so a version is
read once, and `--offline` reads only the cache. A package with no SHA-512 (npm) or SHA-256
(PyPI) hash in its lockfile is not read, and a note says how many.

None of this is a verdict: a capability is what code can reach. On the latest releases of the
top 1,000 npm and top 1,000 PyPI packages (2026-11-12), 6 and 13 in 1,000 had any warning,
and 2 and 3 in 1,000 had one that stands on its own. On 13 open-source monorepos (11,038
package versions), 11.5 in 1,000 had a warning and 3 in 1,000 one that stands on its own,
all of them packages that fetch or build a binary when installed (esbuild, swc, sentry-cli).
A first run downloads each archive once; the same fleet then took 23 seconds from the cache.

## Malware

Known malware (OSV `MAL-` records) needs no flag: it is always critical, never hidden by
`--min-severity`, and the fix queue says to remove the package and rotate credentials.
