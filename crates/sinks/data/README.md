# Curated sink records

One JSON file per advisory, `<ecosystem>/<id>.json`, in the format of
`fleetreach_sinks::record` (`schema = "fleetreach-sinks/1"`). A record says which methods
hold the advisory's flaw (`verdict = "sinks"`), which gadget classes a deserialization deny
list adds (`"deny-list"`), or that no method holds it (`"no-method-sink"`, with a note).

Spec 16 (rows 12 and 13, experiments E2 and E2b) explains why these are reviewed by a
person: neither jar diffs nor fix-commit diffs find sinks precisely enough to act on
unreviewed. JVM reachability may use a `proposed` record only to say a sink is reached, never
that it is not.

## Status of the seed data

The 100 records cover a seeded sample of high and critical Maven advisories that have SAP
project-kb fix commits:

- 40 are `reviewed`: the E2b pilot's labels, each decided by a person against the fix
  diff and the published jars. 19 of them changed in review;
- 60 are `proposed`: `sinkpropose` output as it came out.

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
4. Say in `note` when reaching a sink is not the whole story: a class reached by name
   (JCA, plugin systems, framework dispatch), so no sink reached proves nothing, or a
   setting a code scan cannot see.
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
