"""Generate the fleetreach logo suite as clean SVGs (geometry + outlined Inter wordmark)."""
import sys
from pathlib import Path
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

OUT = Path(sys.argv[1])
FONT = sys.argv[2]
OUT.mkdir(parents=True, exist_ok=True)

INK = "#0B0D10"
WHITE = "#FFFFFF"
ORANGE = "#FF7A45"

# Symbol on a 64 x 64 grid. One hub, six outer nodes, a tree (no cycles).
# The reach path (a -> hub -> b) is orange AND thicker, so it survives in monochrome.
HUB = (32, 32)
N = {
    "a": (9, 53),    # path start: a repo
    "b": (55, 11),   # path end: the vulnerable package
    "c": (12, 12),   # a direct dependency
    "e": (53, 48),   # a dependency...
    "f": (30, 58),   # ...and its own dependency (transitive depth)
}
PATH = [("a", "hub"), ("hub", "b")]
EDGES = [("c", "hub"), ("hub", "e"), ("e", "f")]
R_NODE, R_HUB = 5.6, 8.6
W_EDGE, W_PATH = 4.4, 5.6


def pt(k):
    return HUB if k == "hub" else N[k]


def symbol(ink, accent, nodes=N, path=PATH, edges=EDGES, r=R_NODE, rh=R_HUB, we=W_EDGE, wp=W_PATH):
    on_path = {k for e in path for k in e}
    s = [f'<g fill="none" stroke-linecap="round">']
    for u, v in edges:
        (x1, y1), (x2, y2) = pt(u), pt(v)
        s.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{ink}" stroke-width="{we}"/>')
    for u, v in path:
        (x1, y1), (x2, y2) = pt(u), pt(v)
        s.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{accent}" stroke-width="{wp}"/>')
    s.append("</g>")
    for k, (x, y) in nodes.items():
        s.append(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{accent if k in on_path else ink}"/>')
    s.append(f'<circle cx="{HUB[0]}" cy="{HUB[1]}" r="{rh}" fill="{accent}"/>')
    return "\n  ".join(s)


def svg(w, h, body, title, vb=None):
    vb = vb or f"0 0 {w} {h}"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb}" width="{w}" height="{h}" '
            f'role="img" aria-label="{title}">\n  <title>{title}</title>\n  {body}\n</svg>\n')


# Wordmark: Inter Bold outlined, slight negative tracking, no kerning table needed for these glyphs.
font = TTFont(FONT)
gs = font.getGlyphSet()
cmap = font.getBestCmap()
hmtx = font["hmtx"]
upm = font["head"].unitsPerEm
cap = font["OS/2"].sCapHeight
xh = font["OS/2"].sxHeight


def wordmark(text, size, tracking=-0.025):
    """Return (path_d, width, ascender_height) at font size `size`, baseline at y=0."""
    scale = size / upm
    x = 0.0
    d = []
    for ch in text:
        g = cmap[ord(ch)]
        pen = SVGPathPen(gs)
        gs[g].draw(TransformPen(pen, (scale, 0, 0, -scale, x, 0)))
        d.append(pen.getCommands())
        x += hmtx[g][0] * scale + tracking * size
    return " ".join(d), x - tracking * size


def lockup(ink, accent, title):
    # Symbol 64 units tall; wordmark x-height optically matched to the hub-to-node spread.
    size = 54
    d, tw = wordmark("fleetreach", size)
    asc = 0.73 * size  # ascender of l/f/h in Inter ~0.73em
    gap = 16
    sx = 64 + gap
    baseline = 32 + asc / 2 + 1  # center the ascender height on the hub row
    w = round(sx + tw + 2)
    body = f'{symbol(ink, accent)}\n  <path transform="translate({sx} {baseline:.2f})" fill="{ink}" d="{d}"/>'
    return svg(w * 4, 64 * 4, body, title, vb=f"0 0 {w} 64")


def write(name, text):
    (OUT / name).write_text(text)


# Full symbol variants (rendered at 256 px by default, scale via CSS).
write("fleetreach-symbol.svg", svg(256, 256, symbol(INK, ORANGE), "fleetreach", vb="0 0 64 64"))
write("fleetreach-symbol-inverse.svg", svg(256, 256, symbol(WHITE, ORANGE), "fleetreach", vb="0 0 64 64"))
write("fleetreach-symbol-black.svg", svg(256, 256, symbol(INK, INK), "fleetreach", vb="0 0 64 64"))
write("fleetreach-symbol-white.svg", svg(256, 256, symbol(WHITE, WHITE), "fleetreach", vb="0 0 64 64"))

# Lockups.
write("fleetreach-logo.svg", lockup(INK, ORANGE, "fleetreach"))
write("fleetreach-logo-inverse.svg", lockup(WHITE, ORANGE, "fleetreach"))
write("fleetreach-logo-black.svg", lockup(INK, INK, "fleetreach"))
write("fleetreach-logo-white.svg", lockup(WHITE, WHITE, "fleetreach"))

# Favicon: small-size optical variant. Hub + reach path + one spoke, fat strokes, big nodes.
FAV = {"a": (10, 53), "b": (54, 11), "c": (11, 11), "e": (53, 45), "f": (29, 56)}
saved = dict(N)
N.clear(); N.update(FAV)
def fav_symbol(ink):
    return symbol(ink, ORANGE, nodes=FAV, path=PATH, edges=[("c", "hub"), ("hub", "e"), ("e", "f")],
                  r=6.6, rh=9.8, we=5.8, wp=7.0)
fav_light = fav_symbol(INK)
N.clear(); N.update(saved)
# Browser tabs: ink nodes flip to white in a dark UI.
fav = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">\n'
       f'  <style>@media (prefers-color-scheme:dark){{.ink{{fill:{WHITE};stroke:{WHITE}}}}}</style>\n'
       f'  {fav_light}\n</svg>\n').replace(f'stroke="{INK}"', f'class="ink" stroke="{INK}"').replace(
       f'fill="{INK}"', f'class="ink" fill="{INK}"')
write("favicon.svg", fav)
write("_favicon-light.svg", svg(64, 64, fav_light, "fleetreach"))
write("_favicon-dark.svg", svg(64, 64, fav_light.replace(INK, WHITE), "fleetreach"))
print("ok", sorted(p.name for p in OUT.iterdir()))
