---
title: Publish a fleet report
description: Write one self-contained HTML page from the scan history, with trends, SLA breaches, a queue per owner, fix campaigns and time to fix, for any static host.
sidebar:
  order: 8
---

`fleetreach report html` writes one self-contained HTML file from the scan history: no
external resources, nothing fetched, so it works offline and on any static host such as
GitHub Pages or an internal bucket.

```sh
fleetreach report html --history-dir history/ -c fleet.toml -o fleet-report.html
```

The page shows:

- summary tiles: open findings, past SLA, new and fixed in the newest run, median days to fix;
- open findings per run, stacked by severity, with gap runs marked, and a table view;
- every finding past its SLA, most overdue first;
- a queue per owner, past due first;
- fix campaigns from a saved `fix status` (`--fix-status`), with links to the requests;
- time to fix by severity.

```sh
fleetreach fix status -c fleet.toml > fix-status.json
fleetreach report html --history-dir history/ -c fleet.toml --fix-status fix-status.json -o site/index.html
```

`--title` names the page, `--since 90d` shortens the trend and `-o -` writes to stdout. The
page is byte-identical for the same history and `SOURCE_DATE_EPOCH`, so it diffs cleanly
when committed, and follows the viewer's light or dark setting.
