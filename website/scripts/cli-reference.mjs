// Write the CLI reference pages (src/content/docs/docs/reference/cli/) from the binary's own
// `--help`, so they cannot drift from what fleetreach accepts. One page per command, with its
// subcommands on the same page.
//
//   node scripts/cli-reference.mjs          rewrite the pages
//   node scripts/cli-reference.mjs --check  exit 1 if any page is out of date (CI)
//
// FLEETREACH names the binary (default: ../target/release/fleetreach).

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const site = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(site, "src", "content", "docs", "docs", "reference", "cli");
const binary = process.env.FLEETREACH ?? resolve(site, "..", "target", "release", "fleetreach");
const check = process.argv.includes("--check");

function help(args) {
  return execFileSync(binary, [...args, "--help"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, COLUMNS: "100", NO_COLOR: "1" },
  }).replace(/\s+$/, "");
}

/** `name  description` lines under `Commands:`, without `help`. */
function subcommands(text) {
  const block = text.split("\nCommands:\n")[1]?.split("\n\n")[0] ?? "";
  return block
    .split("\n")
    .map((line) => line.trim().match(/^(\S+)\s+(.*)$/))
    .filter((m) => m && m[1] !== "help")
    .map((m) => ({ name: m[1], about: m[2] }));
}

const yaml = (s) => JSON.stringify(s);
const fence = (text) => "```text\n" + text + "\n```";

const top = help([]);
const commands = subcommands(top);
let stale = 0;
const write = (file, body) => {
  const path = join(out, file);
  let before = "";
  try {
    before = readFileSync(path, "utf8");
  } catch {}
  if (before === body) return;
  stale += 1;
  if (check) console.error(`out of date: ${file}`);
  else writeFileSync(path, body);
};

mkdirSync(out, { recursive: true });
write(
  "index.md",
  `---
title: CLI reference
description: Every fleetreach command and flag, generated from the binary's own help text.
sidebar:
  order: 0
---

Generated from \`fleetreach --help\`; each command's page has its full help.

| Command | What it does |
|---------|--------------|
${commands.map((c) => `| [\`${c.name}\`](/fleetreach/docs/reference/cli/${c.name}/) | ${c.about.replaceAll("|", "\\|")} |`).join("\n")}

${fence(top)}
`,
);
commands.forEach((c, i) => {
  const text = help([c.name]);
  const subs = subcommands(text);
  const sections = subs
    .map((s) => `## fleetreach ${c.name} ${s.name}\n\n${s.about}\n\n${fence(help([c.name, s.name]))}\n`)
    .join("\n");
  write(
    `${c.name}.md`,
    `---
title: fleetreach ${c.name}
description: ${yaml(`fleetreach ${c.name}: ${c.about.replace(/\.$/, "")}. Every flag, from the binary's help.`)}
sidebar:
  order: ${i + 1}
---

${c.about}

${fence(text)}
${sections ? "\n" + sections : ""}`,
  );
});
console.error(`${commands.length} commands; ${stale} page(s) ${check ? "out of date" : "written"}`);
if (check && stale > 0) {
  console.error("run `npm run cli-reference` in website/ and commit the result");
  process.exit(1);
}
