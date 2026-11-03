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

All 100 records are `proposed`. They cover a seeded sample of high and critical Maven
advisories that have SAP project-kb fix commits:

- 40 carry the E2b pilot's labels, made with model assistance from each advisory's text
  and fix diff;
- 60 are `sinkpropose` output as it came out.

## Reviewing a record

1. Read the advisory and the fix commits in `evidence.commits`.
2. Check each sink: it exists in the vulnerable version, holds the flawed behaviour, and is
   reached only when the vulnerable feature is used. Code that only passes a new flag
   along, refactors, logging and generic setup code are not sinks.
   `evidence.excluded` lists the candidates the proposer left out, with the reason.
3. Edit `sinks`, `gadgets`, `verdict` or `note` as needed, add a `descriptor` where only
   one overload is meant, then set `"status": "reviewed"` and
   `"review": {"by": "<you>", "date": "YYYY-MM-DD"}`.
4. `cargo test -p fleetreach-sinks` checks every record; any invalid record fails it.

## Proposing a new record

```bash
cargo run -p fleetreach-sinks --example sinkpropose -- --id GHSA-... --alias CVE-... \
  --package group:artifact --text advisory.txt --git path/to/clone --commit <sha>
```

Only `git` runs, to read objects from the clone. Nothing from the repository is built or
executed.
