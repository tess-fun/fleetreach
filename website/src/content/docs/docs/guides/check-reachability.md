---
title: Check reachability
description: Find out whether vulnerable code is actually reached, with import witness chains for eight ecosystems, a sound MIR call-graph analysis for Rust, and JVM call graphs over container images.
sidebar:
  order: 12
---

An advisory says a package contains vulnerable code; reachability asks whether your code
gets to it. fleetreach has two tiers, both opt-in, and only ever suppresses a finding on a
verdict it can stand behind.

## Heuristic and import graphs (no build)

```sh
fleetreach scan --reachability
```

- **npm** builds a module import graph from every `require` and `import` (and from
  `node_modules` when present) and reports a reached package with a witness chain. Tools run
  from `package.json` scripts or workflow steps count as entry points.
  `--npm-prune-unreachable` also marks unreached packages `NotReachable`; that negative is
  best-effort (a dynamic `require(expr)` can defeat it), so it is a separate opt-in.
- **Python** does the same over a repo's virtualenv, mapping modules to distributions
  through their `RECORD` files, so `import yaml` is PyYAML. It is positive-only: an
  unreached distribution stays `unknown`.
- **npm and Python, function level**: when the advisory has a sink record, a call graph over
  your source (and the installed dependency source in `node_modules` or a virtualenv) looks
  for a chain of calls to the vulnerable function. A chain found replaces the import chain
  as the witness, each step with its file and line. Calls the graph cannot resolve by name
  (callbacks, framework dispatch, `getattr`) are not followed, so this is positive-only too.
- **Ruby, PHP, .NET, Java and Kotlin, Elixir and Swift** read the import lines of your own
  source and follow the lockfile from there. The chain starts at a file and line, and every
  later hop is a dependency the lockfile records. This is positive-only too.
- **Other ecosystems** grep your source for imports of each direct dependency, and for Rust
  for the advisory's affected function names. Those six fall back to the same grep. A match
  raises a finding to reachable; no match never lowers it.

The table's `Reach` column shows the chain, for example
`imported via fastapi → starlette → python-multipart`, or with the line where one is known,
`imported at app/models/user.rb:3 via loofah → nokogiri`. In SARIF the chain is a `codeFlow`
that starts at that line, so a code scanning alert links to the import.

| Language | Lines read | How an import becomes a package |
|----------|------------|---------------------------------|
| Ruby | `require`, `Bundler.require` | the longest gem named by the path; `Bundler.require` loads the `Gemfile`'s gems, less `require: false` |
| PHP | `use` | the PSR-4 and PSR-0 prefixes in `composer.lock` |
| C#, F#, VB | `using`, `open`, `Imports` | assemblies in `project.assets.json` when present, then package ids |
| Java, Kotlin, Scala, Groovy | `import` | classes in jars under `~/.m2` and the Gradle cache, then group and artifact when only one fits |
| Elixir | `alias`, `import`, `require`, `use` | the longest package named by the module |
| Swift | `import` | `.product` in `Package.swift`, then the repository's name |

An import that resolves to no locked package is dropped rather than guessed, and imports of the
repo's own namespaces never count.

The demo fleet's [`admin-dashboard`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/admin-dashboard) has one Express server,
`src/server.js`, that requires express, axios, jsonwebtoken and lodash. The packages it
imports are reached; what express pulls in stays `?` without `node_modules` to follow:

<!-- run: fleetreach scan -c ecosystems/npm.toml --reachability | head -n 11 -->
```console
$ fleetreach scan -c ecosystems/npm.toml --reachability | head -n 11
┌──────────┬───────────────────────────┬─────────────────────┬──────────────────────────────────────────────────┬─────────────────────────────────────────────────────────────┐
│ Severity ┆ Reach                     ┆ Advisory            ┆ Title                                            ┆ Locations                                                   │
╞══════════╪═══════════════════════════╪═════════════════════╪══════════════════════════════════════════════════╪═════════════════════════════════════════════════════════════╡
│ high     ┆ ?                         ┆ GHSA-27r3-jxmh-p828 ┆ body-parser vulnerable to Denial of Service via… ┆ admin-dashboard/body-parser@1.19.0 → 1.20.9 (via express)   │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ high     ┆ imported via lodash       ┆ GHSA-35jh-r3h4-6jhm ┆ Command Injection in lodash                      ┆ admin-dashboard/lodash@4.17.15 → 4.17.21 (direct)           │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ high     ┆ ?                         ┆ GHSA-37ch-88jc-xwx2 ┆ path-to-regexp vulnerable to Regular Expression… ┆ admin-dashboard/path-to-regexp@0.1.7 → 0.1.13 (via express) │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ high     ┆ imported via axios        ┆ GHSA-3g43-6gmg-66jw ┆ axios Vulnerable to Credential Theft and Respon… ┆ admin-dashboard/axios@0.21.0 → 0.31.1 (direct)              │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

For Rust, [`payments-api`](https://github.com/tess-fun/fleetreach/tree/main/website/demo/repos/payments-api) calls `SmallVec::insert_many`, the function
RUSTSEC-2021-0003 names, and never calls `time`'s local-offset functions:

<!-- run: fleetreach scan -c ecosystems/rust.toml --reachability | head -n 9 -->
```console
$ fleetreach scan -c ecosystems/rust.toml --reachability | head -n 9
┌──────────────┬───────────┬───────────────────┬────────────────────────────────────────────────────────────────┬─────────────────────────────────────────────────┐
│ Severity     ┆ Reach     ┆ Advisory          ┆ Title                                                          ┆ Locations                                       │
╞══════════════╪═══════════╪═══════════════════╪════════════════════════════════════════════════════════════════╪═════════════════════════════════════════════════╡
│ critical 9.8 ┆ in source ┆ RUSTSEC-2021-0003 ┆ Buffer overflow in SmallVec::insert_many                       ┆ payments-api/smallvec@1.6.0 → 1.6.1 (direct)    │
│              ┆           ┆                   ┆ affects fn: insert_many                                        ┆                                                 │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ high 7.5     ┆ ?         ┆ RUSTSEC-2022-0013 ┆ Regexes with large repetitions on empty sub-exp…               ┆ payments-api/regex@1.5.4 → 1.5.5 (direct)       │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ medium 6.2   ┆ not found ┆ RUSTSEC-2020-0071 ┆ Potential segfault in the time crate                           ┆ payments-api/time@0.1.45 → 0.2.23 (via chrono)  │
```
<!-- /run -->

`in source` raises the finding; `not found` is shown but never lowers it, because a grep can
miss a call.

## Sound static analysis for Rust

```sh
fleetreach scan --reachability=static --allow-untrusted-builds --reach-driver <path>
```

A MIR call-graph analysis over the compiled crate closure proves whether a vulnerable
function is callable, with a witness chain. `NotReachable` is returned only when there is no
path in an over-approximating call graph, so it is trusted enough to suppress: such a
finding drops to the end of the fix queue, becomes `not_affected` in VEX and SARIF, and is
`defer` in SSVC.

:::caution[It compiles the repos]
Building Rust runs each repo's build scripts and procedural macros, which is arbitrary code
with your privileges. It needs `--allow-untrusted-builds` and the separately built
`fleetreach-reach-driver`. Only point it at repositories you trust, or run it in a sandbox.
:::

## JVM call graphs for container images

```sh
fleetreach scan --image app.tar --reachability=jvm --jvm-app com.example
```

fleetreach reads every Java archive in the image as data (nothing is loaded or run) and builds
one call graph from the service's entry points. Those are the non-private methods of the
classes in the `jvm_app` packages, or a Spring Boot fat jar's or a war's own classes, plus what
frameworks start by name: annotations, `web.xml`, `spring.factories`, service files and the
other resources that name classes. Each Maven finding with a reviewed sink record is then
judged:

- **reachable**, with a chain from an entry point to a method the fix changes;
- **not reachable**, when no image it occurs in reaches a sink. This suppresses like the Rust
  verdict: `not_affected` in VEX and SARIF, the end of the fix queue, `defer` in SSVC;
- **unknown**, with the reason, in every other case: the record's sinks are loaded by name (a
  JDBC driver, a JCA provider), the record is still `proposed`, the installed jars do not hold
  the sinks, an archive or class could not be read, the occurrence is not in an image, or no
  entry point was found.

Findings with no record keep their package-level verdict. The records are curated data built
into fleetreach: each was read against its fix and the published jars by a person.

:::note[What the graph cannot see]
Class names built at run time, reflective calls by method name, template expressions
(`#numbers`) and code started outside the image's archives (a `-javaagent` on the command
line) are not followed. A class defined twice, by two versions of a library, counts as both.
Records whose sinks are typically loaded by name never say "not reachable". Measured on 79
CVE reproducers, 86 of the 87 vulnerable methods that ran were in the graph; the one missed is
such a by-name case.
:::

## .NET call graphs for container images

```sh
fleetreach scan --image app.tar --reachability=dotnet
```

The same, over the image's .NET assemblies: every `.dll` outside the runtime's shared
frameworks is read as data, and each folder holding a `*.deps.json` (what `dotnet publish`
writes) is a service whose own assemblies are the entry points. NuGet findings with a curated
sink record get the same three verdicts as Java ones.

The graph follows what reflection makes: types named by `typeof`, by generic arguments
(dependency injection, serializers), by strings, by attributes and by `appsettings.json` or
`*.config`. Methods the runtime calls on its own (`ToString`, `Dispose`, async state machines,
ASP.NET Core interfaces) are reached on every type something makes. Reflection by method name
is counted, not followed. Checked against the runtime's own JIT events on 11 apps built from
real NuGet packages, every method that ran in their assemblies was in the graph.

:::note[No NuGet records yet]
fleetreach ships no NuGet sink records yet, so .NET findings keep their package-level verdict
until records are added.
:::

## Go

With `govulncheck` on `PATH` (and `--allow-untrusted-builds`, since it compiles the module),
Go findings that are called are marked reachable. Without it, Go is matched at module level
from the osv.dev export, compiling nothing.
