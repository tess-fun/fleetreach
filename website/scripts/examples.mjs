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
// here (see `actual`). Supported after the command: `| head -n N`, `| tail -n N` and `2>&1`.
// A saved scan of the demo fleet is at report.json while the examples run. The repository's
// README.md is filled the same way.
//
//   node scripts/examples.mjs          rewrite the pages
//   node scripts/examples.mjs --check  exit 1 if any page is out of date (CI)
//
// FLEETREACH names the binary (default: ../target/release/fleetreach).

import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
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
  if (argv[0] === "fix" && argv[1] === "apply") out.push("--", "--offline", "--db", "data/advisory-db");
  return out;
}

/** Split `fleetreach scan -f x | head -n 5 2>&1` into argv and the post-processing. */
function parse(line) {
  const [command, ...pipes] = line.split(" | ");
  let words = command.trim().split(/\s+/);
  const merge = words.at(-1) === "2>&1";
  if (merge) words = words.slice(0, -1);
  if (words[0] !== "fleetreach") throw new Error(`not a fleetreach command: ${line}`);
  const filters = pipes.map((pipe) => {
    const m = pipe.trim().match(/^(head|tail) -n (\d+)$/);
    if (!m) throw new Error(`unsupported pipe in: ${line}`);
    return { kind: m[1], n: Number(m[2]) };
  });
  return { argv: words.slice(1), merge, filters };
}

// A fixed `rustc` first on PATH: scan reads the toolchain version for the Rust toolchain's own
// advisories, which would otherwise make the output depend on the machine (and, with the empty
// HOME below, wait on rustup).
const bin = mkdtempSync(join(tmpdir(), "fleetreach-examples-bin-"));
writeFileSync(join(bin, "rustc"), '#!/bin/sh\necho "rustc 1.89.0 (29483883e 2025-08-04)"\n');
chmodSync(join(bin, "rustc"), 0o755);

function run(line) {
  const { argv, merge, filters } = parse(line);
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
      NO_COLOR: "1",
    },
  });
  rmSync(home, { recursive: true, force: true });
  if (result.error) throw result.error;
  let text = merge ? result.stderr + result.stdout : result.stdout;
  let lines = text.replace(/\s+$/, "").split("\n");
  for (const { kind, n } of filters) lines = kind === "head" ? lines.slice(0, n) : lines.slice(-n);
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
// A saved report in the demo folder, for the examples that read one (`fix plan --report
// report.json`, `sbom --report report.json`). Removed again at the end.
const report = join(demo, "report.json");
writeFileSync(report, run("fleetreach scan -f json").raw);
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
rmSync(report, { force: true });
rmSync(join(demo, "boms"), { recursive: true, force: true });
console.error(`${count} examples in ${cache.size} commands; ${stale} page(s) ${check ? "out of date" : "updated"}`);
if (check && stale > 0) {
  console.error("run `npm run examples` in website/ and commit the result");
  process.exit(1);
}
