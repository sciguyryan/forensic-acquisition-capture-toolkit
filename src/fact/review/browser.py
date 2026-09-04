"""Generate the minimal static web shell used to present review layers.

The shell deliberately contains no third-party JavaScript and does not alter
source media.  It is presentation plumbing only: an immutable image is loaded
as an ordinary resource and SVG overlays are derived from structured review
JSON at display time.
"""

from __future__ import annotations

import json
from pathlib import Path

_BROWSER_CSS = """\
:root { color-scheme: light dark; font-family: system-ui, sans-serif; }
body { margin: 0; }
header { padding: 0.75rem 1rem; border-bottom: 1px solid currentColor; }
.controls { display: flex; gap: 1rem; flex-wrap: wrap; }
.viewer { padding: 1rem; overflow: auto; }
.frame { position: relative; display: inline-block; max-width: 100%; }
.frame img { display: block; max-width: 100%; height: auto; }
.overlay { position: absolute; inset: 0; width: 100%; height: 100%; pointer-events: none; }
.annotation { fill: none; stroke: currentColor; vector-effect: non-scaling-stroke; stroke-width: 2; }
.highlight { fill: rgba(255, 255, 0, 0.25); stroke: currentColor; vector-effect: non-scaling-stroke; }
.redaction { fill: rgba(0, 0, 0, 0.82); stroke: white; vector-effect: non-scaling-stroke; }
.hidden { display: none; }
"""

_BROWSER_JS = """\
'use strict';
const state = { data: null };
const ns = 'http://www.w3.org/2000/svg';
function svg(name, attrs) {
  const node = document.createElementNS(ns, name);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}
function pxX(value) { return value * state.data.original_width; }
function pxY(value) { return value * state.data.original_height; }
function renderBox(layer, box, cls, title) {
  const node = svg('rect', {
    x: pxX(box.x), y: pxY(box.y), width: pxX(box.width), height: pxY(box.height), class: cls
  });
  if (title) { const t = svg('title', {}); t.textContent = title; node.appendChild(t); }
  layer.appendChild(node);
}
function addArrowDefinition(layer) {
  const defs = svg('defs', {});
  const marker = svg('marker', {id:'arrowhead', markerWidth:'10', markerHeight:'7', refX:'9', refY:'3.5', orient:'auto'});
  marker.appendChild(svg('polygon', {points:'0 0, 10 3.5, 0 7'}));
  defs.appendChild(marker); layer.appendChild(defs);
}
function render() {
  const annotations = document.getElementById('annotations');
  const redactions = document.getElementById('redactions');
  annotations.replaceChildren(); redactions.replaceChildren();
  addArrowDefinition(annotations);
  for (const item of state.data.annotations || []) {
    const g = item.geometry || {};
    if (['rectangle', 'ellipse', 'highlight'].includes(item.kind) && g.box) {
      if (item.kind === 'ellipse') {
        const b = g.box;
        annotations.appendChild(svg('ellipse', {
          cx: pxX(b.x + b.width / 2), cy: pxY(b.y + b.height / 2),
          rx: pxX(b.width / 2), ry: pxY(b.height / 2), class: 'annotation'
        }));
      } else renderBox(annotations, g.box, item.kind === 'highlight' ? 'highlight' : 'annotation', item.note || '');
    } else if (['line', 'arrow'].includes(item.kind) && g.start && g.end) {
      const line = svg('line', {x1:pxX(g.start.x), y1:pxY(g.start.y), x2:pxX(g.end.x), y2:pxY(g.end.y), class:'annotation'});
      if (item.kind === 'arrow') line.setAttribute('marker-end', 'url(#arrowhead)');
      annotations.appendChild(line);
    }
  }
  for (const item of state.data.proposed_redactions || []) renderBox(redactions, item.box, 'redaction', item.reason);
}
async function start() {
  const config = JSON.parse(document.getElementById('fact-config').textContent);
  state.data = config.review_data;
  const image = document.getElementById('original'); image.src = config.image;
  const viewBox = `0 0 ${state.data.original_width} ${state.data.original_height}`;
  document.querySelectorAll('.overlay').forEach(layer => layer.setAttribute('viewBox', viewBox));
  document.getElementById('toggle-annotations').addEventListener('change', e => document.getElementById('annotations').classList.toggle('hidden', !e.target.checked));
  document.getElementById('toggle-redactions').addEventListener('change', e => document.getElementById('redactions').classList.toggle('hidden', !e.target.checked));
  render();
}
start().catch(error => { document.getElementById('status').textContent = error.message; });
"""

_BROWSER_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FACT image review</title>
<link rel="stylesheet" href="assets/fact-review.css">
</head>
<body>
<header>
  <strong>FACT image review</strong>
  <div class="controls">
    <label><input id="toggle-annotations" type="checkbox" checked> Annotations</label>
    <label><input id="toggle-redactions" type="checkbox" checked> Proposed redactions</label>
    <span id="status"></span>
  </div>
</header>
<main class="viewer">
  <div class="frame">
    <img id="original" alt="Immutable original evidence">
    <svg id="annotations" class="overlay" aria-label="Annotation layer"></svg>
    <svg id="redactions" class="overlay" aria-label="Proposed redaction layer"></svg>
  </div>
</main>
<script id="fact-config" type="application/json">__FACT_CONFIG__</script>
<script src="assets/fact-review.js"></script>
</body>
</html>
"""


def write_image_review_shell(
    output: Path, *, image: str, review_data: dict[str, object]
) -> Path:
    """Write a self-contained static shell around caller-supplied local media.

    The generated files reference relative project resources but make no network
    requests beyond those local resources.  The shell is therefore suitable as
    a building block for the later closed-project media browser.
    """

    assets = output / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    (assets / "fact-review.css").write_text(_BROWSER_CSS, encoding="utf-8")
    (assets / "fact-review.js").write_text(_BROWSER_JS, encoding="utf-8")
    # Embed a presentation copy of the structured layer data so the browser
    # works when opened directly from ``file://``. The canonical review JSON
    # remains a separate project artefact; this embedded copy is generated UI.
    config = json.dumps(
        {"image": image, "review_data": review_data},
        ensure_ascii=False,
    ).replace("<", "\\u003c")
    index = output / "index.html"
    index.write_text(_BROWSER_HTML.replace("__FACT_CONFIG__", config), encoding="utf-8")
    return index
