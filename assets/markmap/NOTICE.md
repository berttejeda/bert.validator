# Vendored assets

These browser bundles are vendored (not built from source in this repo) so
that `--visualize` works from a single self-contained `validator` binary,
with no Node.js toolchain required at build or run time.

| File | Source | License |
|---|---|---|
| `d3.min.js` | [d3](https://d3js.org/) v7.9.0 | ISC |
| `markmap-view.js` | [markmap-view](https://github.com/markmap/markmap) browser build | MIT |
| `markmap-toolbar.js` / `markmap-toolbar.css` | [markmap-toolbar](https://github.com/markmap/markmap) browser build | MIT |
| `markmap-lib.js` | [markmap-lib](https://github.com/berttejeda/markmap) browser build, `feature-mermaid` branch (adds a built-in Mermaid diagram plugin on top of upstream [markmap](https://github.com/markmap/markmap)) | MIT |

`mermaid.min.js` itself is intentionally NOT vendored (it's ~3.5MB); it is
loaded from a public CDN (jsdelivr) at runtime only when a generated
visualization actually contains a Mermaid diagram. If the machine viewing the
HTML is offline, the mindmap still renders fully — only the Mermaid diagram
falls back to showing its source text.

To refresh these files after the upstream fork changes, rebuild
`berttejeda/markmap` (`pnpm build` at the repo root) and copy:
- `packages/markmap-view/dist/browser/index.js` → `markmap-view.js`
- `packages/markmap-lib/dist/browser/index.iife.js` → `markmap-lib.js`
- `packages/markmap-toolbar/dist/index.js` → `markmap-toolbar.js`
- `packages/markmap-toolbar/dist/style.css` → `markmap-toolbar.css`
- `node_modules/d3/dist/d3.min.js` → `d3.min.js` (only if the d3 version pin changes)
