package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

/* =========================
   --visualize: HTML mindmap of the validation summary
   ========================= */

// Vendored, self-contained browser assets (see assets/markmap/NOTICE.md).
// Embedding these keeps `validator` a single static binary: rendering the
// mindmap needs no Node.js toolchain and no network access. Only the
// optional Mermaid diagram (the outcomes pie chart) is fetched from a CDN
// at runtime, and gracefully degrades to plain text if unavailable.
var (
	//go:embed assets/markmap/d3.min.js
	vendoredD3JS []byte

	//go:embed assets/markmap/markmap-view.js
	vendoredMarkmapViewJS []byte

	//go:embed assets/markmap/markmap-lib.js
	vendoredMarkmapLibJS []byte

	//go:embed assets/markmap/markmap-toolbar.js
	vendoredMarkmapToolbarJS []byte

	//go:embed assets/markmap/markmap-toolbar.css
	vendoredMarkmapToolbarCSS []byte
)

// visualizeFlag implements flag.Value with an optional value, so both
// `--visualize` (ephemeral temp file) and `--visualize=path.html` work.
type visualizeFlag struct {
	enabled bool
	path    string
}

func (v *visualizeFlag) String() string { return v.path }

func (v *visualizeFlag) Set(s string) error {
	switch s {
	case "false":
		v.enabled = false
		v.path = ""
	case "true", "":
		v.enabled = true
	default:
		v.enabled = true
		v.path = s
	}
	return nil
}

// IsBoolFlag tells the flag package this flag doesn't require an explicit
// value, matching how --extra-var-style flags differ from boolean ones.
func (v *visualizeFlag) IsBoolFlag() bool { return true }

var visualizeOpt visualizeFlag

// mindmapTextEscaper neutralizes Markdown syntax and HTML metacharacters in
// dynamic content (validation names, notes, manifest paths) before it's
// embedded in the generated Markdown. Manifests can come from untrusted
// remote URLs, and the underlying markdown-it renderer runs with `html:
// true`, so unescaped `<`/`&` would let a hostile validation name inject
// live HTML/JS into the generated page.
var mindmapTextEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	"\\", "\\\\",
	"*", "\\*",
	"_", "\\_",
	"`", "\\`",
	"[", "\\[",
	"]", "\\]",
	"|", "\\|",
	"\r", " ",
	"\n", " ",
)

func escapeMindmapText(s string) string {
	return mindmapTextEscaper.Replace(s)
}

// buildVisualizationMarkdown renders the validation summary as a Markmap
// outline: a Mermaid pie chart overview, followed by one top-level branch
// per outcome (PASS/FAIL/WARN/SKIP) listing its validations.
func buildVisualizationMarkdown(results []summaryResult) string {
	order := []string{"PASS", "FAIL", "WARN", "SKIP"}
	icons := map[string]string{"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "SKIP": "⏭️"}

	grouped := make(map[string][]summaryResult)
	counts := make(map[string]int)
	for _, r := range results {
		grouped[r.Status] = append(grouped[r.Status], r)
		counts[r.Status]++
	}

	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("markmap:\n")
	b.WriteString("  colorFreezeLevel: 2\n")
	b.WriteString("  mermaid:\n")
	b.WriteString("    theme: base\n")
	b.WriteString("    themeVariables:\n")
	b.WriteString("      primaryColor: '#4a90d9'\n")
	b.WriteString("      primaryTextColor: '#fff'\n")
	b.WriteString("      primaryBorderColor: '#2d6cb4'\n")
	b.WriteString("      lineColor: '#888'\n")
	b.WriteString("---\n\n")
	b.WriteString("# bert.validator — Validation Summary\n\n")

	if len(results) == 0 {
		b.WriteString("_No validation results were recorded for this run._\n")
		return b.String()
	}

	b.WriteString("## Overview\n\n")
	b.WriteString("```mermaid\n")
	b.WriteString("pie showData title Validation Outcomes\n")
	for _, status := range order {
		if n := counts[status]; n > 0 {
			fmt.Fprintf(&b, "    %q : %d\n", status, n)
		}
	}
	b.WriteString("```\n\n")

	for _, status := range order {
		items := grouped[status]
		if len(items) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s %s (%d)\n\n", icons[status], status, len(items))
		for _, r := range items {
			fmt.Fprintf(&b, "- **%s** `#%s` `%s` — _%s_\n",
				escapeMindmapText(r.Name), escapeMindmapText(r.ExecDisplay), r.ValidationID, escapeMindmapText(r.Manifest))
			for _, note := range r.Notes {
				fmt.Fprintf(&b, "  - %s\n", escapeMindmapText(note))
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

const visualizationBaseCSS = `* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}
html, body {
  width: 100%;
  height: 100%;
}
body {
  font-family: ui-sans-serif, system-ui, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji';
}
#mindmap {
  display: block;
  width: 100vw;
  height: 100vh;
}
.markmap-dark {
  background: #27272a;
  color: white;
}
.bv-header {
  position: fixed;
  top: 0.75rem;
  left: 0.75rem;
  z-index: 10;
  padding: 0.5rem 0.75rem;
  border-radius: 0.5rem;
  background: rgba(255, 255, 255, 0.85);
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.2);
  font-size: 0.85rem;
  pointer-events: none;
}
.markmap-dark .bv-header {
  background: rgba(39, 39, 42, 0.85);
  color: white;
}
.bv-header strong {
  font-size: 0.95rem;
}
`

const visualizationBootstrapJS = `(function () {
  var markdownSource = __MARKDOWN_JSON__;
  var transformer = new markmap.Transformer();
  var result = transformer.transform(markdownSource);
  var root = result.root;
  var features = result.features;
  var frontmatter = result.frontmatter || {};
  var jsonOptions = frontmatter.markmap || {};
  if (jsonOptions.mermaid) {
    window.__mermaidConfig = jsonOptions.mermaid;
  }
  var assets = transformer.getUsedAssets(features);

  function renderMindmap() {
    var mm = markmap.Markmap.create('svg#mindmap', markmap.deriveOptions(jsonOptions), root);
    window.mm = mm;
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      document.documentElement.classList.add('markmap-dark');
    }
    var toolbar = markmap.Toolbar.create(mm);
    toolbar.setBrand(false);
    toolbar.el.style.position = 'fixed';
    toolbar.el.style.bottom = '1rem';
    toolbar.el.style.right = '1rem';
    document.body.appendChild(toolbar.el);
  }

  var pending = [];
  if (assets && assets.styles && assets.styles.length) {
    pending.push(markmap.loadCSS(assets.styles));
  }
  if (assets && assets.scripts && assets.scripts.length) {
    pending.push(markmap.loadJS(assets.scripts));
  }
  Promise.all(pending).then(renderMindmap, function (err) {
    console.warn('bert.validator: diagram assets failed to load (offline?)', err);
    renderMindmap();
  });
})();
`

// buildVisualizationHTML assembles a single self-contained HTML file: the
// vendored markmap/d3 bundles inlined as <script> tags, plus a small
// bootstrap script that transforms the embedded Markdown into a mindmap
// client-side (see assets/markmap/NOTICE.md for what's vendored and why).
func buildVisualizationHTML(markdown string) (string, error) {
	mdJSON, err := json.Marshal(markdown)
	if err != nil {
		return "", err
	}
	bootstrap := strings.Replace(visualizationBootstrapJS, "__MARKDOWN_JSON__", string(mdJSON), 1)

	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
	b.WriteString("<title>bert.validator — Validation Summary</title>\n")
	b.WriteString("<style>\n")
	b.WriteString(visualizationBaseCSS)
	b.Write(vendoredMarkmapToolbarCSS)
	b.WriteString("\n</style>\n</head>\n<body>\n")
	b.WriteString("<div class=\"bv-header\"><strong>bert.validator</strong><br>Validation Summary</div>\n")
	b.WriteString("<svg id=\"mindmap\"></svg>\n")
	b.WriteString("<script>")
	b.Write(vendoredD3JS)
	b.WriteString("</script>\n<script>")
	b.Write(vendoredMarkmapViewJS)
	b.WriteString("</script>\n<script>")
	b.Write(vendoredMarkmapLibJS)
	b.WriteString("</script>\n<script>")
	b.Write(vendoredMarkmapToolbarJS)
	b.WriteString("</script>\n<script>\n")
	b.WriteString(bootstrap)
	b.WriteString("\n</script>\n</body>\n</html>\n")
	return b.String(), nil
}

// generateVisualization writes the HTML mindmap to outPath, or to a fresh
// temp file when outPath is empty, returning the file's final path.
func generateVisualization(results []summaryResult, outPath string) (string, error) {
	html, err := buildVisualizationHTML(buildVisualizationMarkdown(results))
	if err != nil {
		return "", err
	}

	if outPath == "" {
		f, err := os.CreateTemp("", "bert-validator-visualize-*.html")
		if err != nil {
			return "", err
		}
		defer f.Close()
		if _, err := f.WriteString(html); err != nil {
			os.Remove(f.Name())
			return "", err
		}
		return f.Name(), nil
	}

	if dir := filepath.Dir(outPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(outPath, []byte(html), 0o644); err != nil {
		return "", err
	}
	return outPath, nil
}

// openInBrowser opens path with the OS's default handler for HTML files.
func openInBrowser(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	return cmd.Start()
}
