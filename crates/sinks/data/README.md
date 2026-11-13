# Curated sink records

One JSON file per advisory, `<ecosystem>/<id>.json`, in the format of
`fleetreach_sinks::record` (`schema = "fleetreach-sinks/1"`). A record says which methods
hold the advisory's flaw (`verdict = "sinks"`), which gadget classes a deserialization deny
list adds (`"deny-list"`), or that no method holds it (`"no-method-sink"`, with a note).

Spec 16 (rows 12 and 13, experiments E2 and E2b) explains why these are reviewed by a
person: neither jar diffs nor fix-commit diffs find sinks precisely enough to act on
unreviewed. JVM reachability may use a `proposed` record only to say a sink is reached, never
that it is not.

Records for PyPI (`pypi/`, `module.Class.name`) and npm (`npm/`, `repo/path.js.Class.name`)
have no descriptors or deny lists. The 284 PyPI and 289 npm records are `sinkpropose` output,
all `proposed`: `scan --reachability` uses them only for call-chain witnesses, and skips a
proposed record with more than 10 sinks as too broad.

Records for NuGet (`nuget/`) name types as .NET reflection does (`Namespace.Outer+Inner`) and
methods by their metadata name (`.ctor`, `ReadFrame`). The 97 records started as
`nugetpropose` output (`crates/clr/examples`): for each high or critical NuGet advisory with a
GitHub fix commit, the IL of the last vulnerable and the first fixed release inside the fixed
range, narrowed to the types of the source files the fix changed, with generated code charged
to the method that owns it. `docs/differential/nuget-sinks/propose.py` fetches the packages
and commit file lists and runs it. All 97 are `reviewed`: 71 name sinks, 26 are
`no-method-sink` (mostly flaws in a bundled native library or a single platform). `scan --reachability=dotnet` looks for a record's sinks only in the
assemblies the image's deps files list for its packages, so name the package that ships the
class. The .NET runtime's Brotli record
(`GHSA-p3jp-9v83-76w9`) names sinks in the runtime itself, judged only where a service ships
the runtime. Where a class moved between
release lines the record names each spelling; `docs/differential/nuget-sinks/span.py` checks
that every affected line holds at least one of a record's sinks, or none (then the verdict is
unknown). Packages with no library assemblies (native code, tools) have no record, unless the
advisory names managed entry points of the runtime, as Brotli's does.

## Status of the seed data

The 100 records cover a seeded sample of high and critical Maven advisories that have SAP
project-kb fix commits:

- 40 are `reviewed`: the E2b pilot's labels, each decided by a person against the fix
  diff and the published jars. 19 of them changed in review;
- 60 are `proposed`: `sinkpropose` output as it came out.

Of the 34 reviewed `sinks` records, 27 are `reached_by_name`, so 7 can support "not reached".

## Reviewing a record

1. Read the advisory and the fix commits in `evidence.commits`.
2. Check each sink: it exists in the vulnerable version, holds the flawed behaviour, and is
   reached only when the vulnerable feature is used. Code that only passes a new flag
   along, refactors, logging and generic setup code are not sinks.
   `evidence.excluded` lists the candidates the proposer left out, with the reason.
3. Check the names against published jars, not just the fix commit. `packages` must name
   the artifact that holds the class, which is often not the one the advisory names, and
   may be a POM. A fix commit shows one release line: a method can have another name or
   package on the others, or exist only after the advisory's range.
4. Set `"reached_by_name": true` when applications reach the sinks through a name, not a
   call (JCA, plugin systems, framework dispatch), and say how in `note`. No sink reached
   then proves nothing, and the record can only say "reached". Say in `note` too when
   reaching a sink is not the whole story, such as a setting a code scan cannot see.
5. Edit `sinks`, `gadgets`, `verdict` or `note` as needed, add a `descriptor` where only
   one overload is meant, then set `"status": "reviewed"` and
   `"review": {"by": "<you>", "date": "YYYY-MM-DD"}`.
6. `cargo test -p fleetreach-sinks` checks every record; any invalid record fails it.

## Proposing a new record

```bash
cargo run -p fleetreach-sinks --example sinkpropose -- --id GHSA-... --alias CVE-... \
  --package group:artifact --text advisory.txt --git path/to/clone --commit <sha>
```

Only `git` runs, to read objects from the clone. Nothing from the repository is built or
executed.
