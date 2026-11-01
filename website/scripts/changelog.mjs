// Write the changelog page from the repository's CHANGELOG.md, so there is one source.
// The page is generated before every build and dev run, and not committed.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const site = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = readFileSync(join(site, "..", "CHANGELOG.md"), "utf8");
// Drop the file's own title and intro; the page has its own.
const body = source.slice(source.indexOf("\n## ") + 1);
writeFileSync(
  join(site, "src", "content", "docs", "docs", "changelog.md"),
  `---
title: Changelog
description: Every fleetreach release and what changed in it, following Keep a Changelog and Semantic Versioning.
editUrl: https://github.com/tess-fun/fleetreach/edit/main/CHANGELOG.md
---

All notable changes, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

${body}`,
);
