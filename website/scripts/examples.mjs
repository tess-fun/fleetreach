// Fill every example on the site with real fleetreach output.
//
// A page marks a command, and this script runs it on the demo fleet (website/demo) and
// writes what it printed between the markers:
//
//   <!-- run: fleetreach scan -f impact | head -n 12 -->
//   ```console
//   (replaced)
//   ```
//   <!-- /run -->
//
// MDX has no HTML comments, so .mdx pages write the markers as `{/* run: ... */}` and
// `{/* /run */}` instead.
//
// The command runs in website/demo, offline, against the advisory data frozen in
// website/demo/data, so the output only changes when fleetreach does. What the page shows is
// the command as a reader would type it; the flags that point it at the frozen data are added
// here (see `actual`). Supported after the command: `| head -n N`, `| tail -n N`,
// `| jq '<filter>'`, `2>&1` and `>/dev/null` (only what goes to stderr is shown), and at the
// very end `; echo "exit $?"`, which prints the exit status the way a shell would.
// The repository's README.md is filled the same way.
//
// Before the examples run, two scans are recorded as if made on 1 September and 15 October
// 2026, so the drift, history, notify, VEX and report examples have something to read:
//
//   before.json   the first scan: billing on its older rack (demo/before), no partner-api yet
//   report.json   the second scan, of the fleet as it is
//   history/      both runs, as `scan --history-dir` records them
//
// Every example then runs as of 1 November 2026 (SOURCE_DATE_EPOCH), and all of it is
// removed at the end.
//
//   node scripts/examples.mjs          rewrite the pages
//   node scripts/examples.mjs --check  exit 1 if any page is out of date (CI)
//
// FLEETREACH names the binary (default: ../target/release/fleetreach).

import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const site = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const demo = join(site, "demo");
const content = join(site, "src", "content", "docs");
const binary = process.env.FLEETREACH ?? resolve(site, "..", "target", "release", "fleetreach");
const check = process.argv.includes("--check");

const MARKER = /(<!--|\{\/\*) run: (.+?) (?:-->|\*\/\})\n[\s\S]*?(?:<!--|\{\/\*) \/run (?:-->|\*\/\})/g;

/** The argv actually run for a shown command: the same, pointed at the frozen data. */
function actual(argv) {
  const out = [];
  for (const arg of argv) {
    if (arg === "--enrich") out.push("--kev-file", "data/kev.json", "--epss-file", "data/epss.csv");
    else out.push(arg);
  }
  if (argv[0] === "scan") out.push("--offline", "--db", "data/advisory-db");
  // The frozen advisory-db is not a git clone, so it has no commit time to date VEX by.
  if (argv[0] === "scan" && argv.includes("vex")) out.push("--vex-timestamp", "2026-11-01T09:00:00Z");
  if (argv[0] === "fix" && argv[1] === "apply") out.push("--", "--offline", "--db", "data/advisory-db");
  return out;
}

/** Split a line on ` | `, except inside single quotes (a jq filter has pipes of its own). */
function pipeline(line) {
  const parts = [""];
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === "'") quoted = !quoted;
    if (!quoted && line.startsWith(" | ", i)) {
      parts.push("");
      i += 2;
    } else parts[parts.length - 1] += line[i];
  }
  return parts;
}

/** Split `fleetreach scan -f x | head -n 5 2>&1` into argv and the post-processing. */
function parse(line) {
  const EXIT = '; echo "exit $?"';
  const exit = line.endsWith(EXIT);
  if (exit) line = line.slice(0, -EXIT.length);
  const [command, ...pipes] = pipeline(line);
  let words = command.trim().split(/\s+/);
  const merge = words.at(-1) === "2>&1";
  if (merge) words = words.slice(0, -1);
  const discard = words.at(-1) === ">/dev/null";
  if (discard) words = words.slice(0, -1);
  if (words[0] !== "fleetreach") throw new Error(`not a fleetreach command: ${line}`);
  const filters = pipes.map((pipe) => {
    const lines = pipe.trim().match(/^(head|tail) -n (\d+)$/);
    if (lines) return { kind: lines[1], n: Number(lines[2]) };
    const jq = pipe.trim().match(/^jq '([^']+)'$/);
    if (jq) return { kind: "jq", filter: jq[1] };
    throw new Error(`unsupported pipe in: ${line}`);
  });
  return { argv: words.slice(1), merge, discard, filters, exit };
}

// A fixed `rustc` first on PATH: scan reads the toolchain version for the Rust toolchain's own
// advisories, which would otherwise make the output depend on the machine (and, with the empty
// HOME below, wait on rustup).
const bin = mkdtempSync(join(tmpdir(), "fleetreach-examples-bin-"));
writeFileSync(join(bin, "rustc"), '#!/bin/sh\necho "rustc 1.89.0 (29483883e 2025-08-04)"\n');
chmodSync(join(bin, "rustc"), 0o755);

// The first run, the second run, and "now" for every example.
const RUN_1 = "1788253200"; // 2026-09-01T09:00:00Z
const RUN_2 = "1792054800"; // 2026-10-15T09:00:00Z
const NOW = "1793523600"; // 2026-11-01T09:00:00Z

function run(line, at = NOW) {
  const { argv, merge, discard, filters, exit } = parse(line);
  const home = mkdtempSync(join(tmpdir(), "fleetreach-examples-"));
  mkdirSync(join(home, ".m2"));
  const result = spawnSync(binary, actual(argv), {
    cwd: demo,
    encoding: "utf8",
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      HOME: home,
      XDG_CACHE_HOME: home,
      FLEETREACH_OSV_SYNC: "off",
      MAVEN_REPO_LOCAL: join(demo, "data", "m2"),
      COLUMNS: "120",
      SOURCE_DATE_EPOCH: at,
      NO_COLOR: "1",
    },
  });
  rmSync(home, { recursive: true, force: true });
  if (result.error) throw result.error;
  let text = discard ? result.stderr : merge ? result.stderr + result.stdout : result.stdout;
  let lines = text.replace(/\s+$/, "").split("\n");
  for (const { kind, n, filter } of filters) {
    if (kind === "head") lines = lines.slice(0, n);
    else if (kind === "tail") lines = lines.slice(-n);
    else {
      const jq = spawnSync("jq", [filter], { input: lines.join("\n"), encoding: "utf8" });
      if (jq.status !== 0) throw new Error(`jq ${filter}: ${jq.stderr}`);
      lines = jq.stdout.replace(/\s+$/, "").split("\n");
    }
  }
  // A pipeline's status is its last command's, so only a bare command shows fleetreach's.
  if (exit) lines.push(`exit ${filters.length ? 0 : result.status}`);
  const body = lines.join("\n").replaceAll(demo, "~/acme");
  return { body, raw: result.stdout, status: result.status };
}

function pages(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return pages(path);
    return /\.mdx?$/.test(name) ? [path] : [];
  });
}

execFileSync(binary, ["--version"]);
const before = join(demo, "fleet-before.toml");
writeFileSync(
  before,
  readFileSync(join(demo, "fleet.toml"), "utf8")
    .replace('path  = "repos/billing"', 'path  = "before/billing"')
    .replace(/\n\[\[repo\]\]\nid {13}= "partner-api"[\s\S]*$/, "\n"),
);
const scratch = ["before.json", "report.json", "fleet-before.toml", "history", "boms", "fleet-report.html"].map((f) => join(demo, f));
rmSync(join(demo, "history"), { recursive: true, force: true });
const record = (args, at) => run(`fleetreach scan ${args} --history-dir history/ --enrich -f json`, at).raw;
writeFileSync(join(demo, "before.json"), record("-c fleet-before.toml", RUN_1));
writeFileSync(join(demo, "report.json"), record("", RUN_2));
let stale = 0;
let count = 0;
const cache = new Map();
for (const page of [...pages(content), resolve(site, "..", "README.md")]) {
  const before = readFileSync(page, "utf8");
  const after = before.replace(MARKER, (_, open, line) => {
    const [start, end] = open === "<!--" ? ["<!--", "-->"] : ["{/*", "*/}"];
    count += 1;
    if (!cache.has(line)) cache.set(line, run(line));
    const { body } = cache.get(line);
    const fence = body.includes("```") ? "````" : "```";
    return `${start} run: ${line} ${end}\n${fence}console\n$ ${line}\n${body}\n${fence}\n${start} /run ${end}`;
  });
  if (after === before) continue;
  stale += 1;
  if (check) console.error(`out of date: ${relative(site, page)}`);
  else writeFileSync(page, after);
}
rmSync(bin, { recursive: true, force: true });
// The HTML report example's page is published as a sample at /demo/fleet-report.html. It is
// rewritten here but not compared under --check: it names the history's run ids, which hash
// the report, and the report records the operating system it was made on.
const sample = join(site, "public", "demo", "fleet-report.html");
if (!check && existsSync(join(demo, "fleet-report.html"))) {
  mkdirSync(dirname(sample), { recursive: true });
  copyFileSync(join(demo, "fleet-report.html"), sample);
}
for (const path of scratch) rmSync(path, { recursive: true, force: true });
console.error(`${count} examples in ${cache.size} commands; ${stale} page(s) ${check ? "out of date" : "updated"}`);
if (check && stale > 0) {
  console.error("run `npm run examples` in website/ and commit the result");
  process.exit(1);
}
