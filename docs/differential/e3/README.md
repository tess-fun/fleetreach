# E3: JVM suppression yield

`corpus.txt` lists each service image and the class prefixes that are the service's own code.
`run.py` pulls an image, scans it, judges the sink records over its jars with the `jvmreach`
example, and deletes it. `run2.py` adds which jars the graph touches. `run3.py` judges the
records again into `out3`, reusing the scans in `out`. `agg.py` (pass `out3` for the rerun)
and `agg2.py` print the tables in `docs/specs/16-a-plus.md`.

Set `FLEETREACH_TARGET_PARENT` to the folder holding `base-target`, and work under
`~/fa-testbed/e3`. Jars are parsed, never run. Docker Hub rate limits an anonymous run of the
whole list, so `run2.py` can need a second pass.
