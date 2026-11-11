# vul4j: JVM graph soundness corpus

This checks whether the `crates/jvm` call graph reaches the code a known-reachable CVE
reproducer runs. Each of vul4j's proof-of-vulnerability (PoV) tests is built and run in a
throwaway container under JaCoCo. Then the graph, rooted at the test class alone, must reach
every method that ran, and above all the methods the human fix changes. Results:
"Soundness corpus" in `docs/specs/16-a-plus.md`.

This is the one harness that runs the code it judges. It runs in Docker only, in containers
that are deleted after each entry.

- `build.sh` builds `vul4j:oracle`.
  - vul4j is GPL-3, so its Dockerfile is not copied here: the script clones vul4j at
    `bca934d` and edits that clone's Dockerfile, dropping the warmup steps and moving the
    virtualenv out of the source tree.
  - `Dockerfile` then adds JaCoCo 0.8.12 on top.
- `run_all.sh` runs every entry without a result, two at a time, through `one.sh`.
  - The containers share a Maven repository volume (`vul4j-m2`) and `settings.xml`, which
    mirrors Central through Google, since Central rate-limits fresh containers.
- `oracle.py` runs in the container and writes `out/ID`:
  - the class path;
  - `sinks.txt`, the methods the patch changes, from `sinks.py`;
  - `covered.txt`, the methods the PoV run executed, from `report.py`.
  
  The agent goes only into surefire's forked JVM, through the `jvm/bin/java` wrapper.
- `resink.sh` reruns `sinks.py` over finished entries.
- `judge.py` runs on the host with `JVMREACH` set to the `jvmreach` example binary:
  `ls -d out/VUL4J-* | JVMREACH=... xargs python3 -I judge.py > judge.jsonl`.
  It prints one JSON line per entry, with `missed_sinks`, `missed` and `elsewhere`.

Set `VUL4J_WORK` to the work folder (default `~/fa-testbed/vul4j`). The full run takes about
three hours on an Apple silicon Mac through amd64 emulation.

Traps:
- **macOS mounts are case-insensitive.** A class directory holding both `Queue.class` and
  `queue/` (Jenkins) is copied out as a jar.
- **vul4j overwrites `MAVEN_OPTS` with `MVN_ARGS`.** So flags go in `MVN_ARGS`: `-Djacoco.skip=true`
  turns off a build's own agent, which cannot run beside this one.
- **Surefire 2.21+ wants the `jvm` path to end in `bin/java`.** The commons parent overrides
  `jvm` with `commons.surefire.java`, so both are set.
- **The judge roots every test class and JUnit runner the run executed.** A TestNG suite runs
  all its tests for one PoV method, and ApacheDS's `@RunWith` runner starts the server.
