# fleetreach logo

The mark is a small dependency graph. The orange line is a reach path: from a repo, through
the hub, to the vulnerable package. It is also drawn thicker than the dark edges, so it
stays distinct in the one-colour versions.

| File | Use |
|------|-----|
| `fleetreach-logo.svg` | Symbol + wordmark on light backgrounds |
| `fleetreach-logo-inverse.svg` | Symbol + wordmark on dark backgrounds |
| `fleetreach-logo-black.svg`, `fleetreach-logo-white.svg` | One colour, where orange is unreliable |
| `fleetreach-symbol*.svg` | Symbol only (avatar, compact header), same four variants |
| `favicon.svg` | Browser tab; heavier strokes for 16 to 32 px, switches to white in dark mode |
| `social-preview.png` | 1200x630 card for link previews and the GitHub repo setting |

Colours: ink `#0B0D10`, white `#FFFFFF`, orange `#FF7A45` (the site's `--accent`).

The wordmark is Inter Bold (SIL Open Font License), converted to outlines, so it renders the
same everywhere without the font installed. Write it lowercase: `fleetreach`.

Rules: keep the proportions, no shadows or outlines, keep clear space of at least one hub
diameter around the mark, and use the symbol, not the full logo, below 32 px.

## Regenerating

`gen-logo.py` builds every file from the node coordinates at its top.

```bash
python3 -m venv /tmp/fr-logo && /tmp/fr-logo/bin/pip install fonttools
curl -fsSLO https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip && unzip -q Inter-4.1.zip -d inter
/tmp/fr-logo/bin/python assets/brand/gen-logo.py assets/brand inter/extras/otf/Inter-Bold.otf
```

It also writes `_favicon-light.svg` and `_favicon-dark.svg` (fixed-colour favicons for
rasterising); they are not part of the set.
