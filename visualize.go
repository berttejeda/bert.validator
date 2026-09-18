package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// optionalPathFlag implements flag.Value for a flag that's a plain on/off
// switch by default but can also take an explicit path, so both bare
// `--visualize` (ephemeral temp file) and `--visualize=path.html` work; the
// same type backs `--export-as-mop`.
type optionalPathFlag struct {
	enabled bool
	path    string
}

func (v *optionalPathFlag) String() string { return v.path }

func (v *optionalPathFlag) Set(s string) error {
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
func (v *optionalPathFlag) IsBoolFlag() bool { return true }

var visualizeOpt optionalPathFlag

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

// safeLinkURLPattern restricts markdown-link targets to schemes that are
// inert to click (http/https/mailto), rejecting things like javascript: or
// data: URIs that a hostile validation name/note could otherwise smuggle in.
var safeLinkURLPattern = regexp.MustCompile(`(?i)^\s*(https?://|mailto:)`)

var urlHTMLEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
)

// escapeMindmapRich is like escapeMindmapText, but preserves the single
// `[text](url)` Markdown-link form that validation names/notes already
// support elsewhere in the tool (see linkify/mdPattern in main.go), instead
// of escaping their brackets into literal text. Everything outside of a
// recognized link, and the link's own label, still goes through the same
// full escaping; only http(s)/mailto targets are honored as real links.
func escapeMindmapRich(s string) string {
	matches := mdPattern.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return escapeMindmapText(s)
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		fullStart, fullEnd := m[0], m[1]
		textStart, textEnd := m[2], m[3]
		urlStart, urlEnd := m[4], m[5]
		b.WriteString(escapeMindmapText(s[last:fullStart]))
		url := s[urlStart:urlEnd]
		if safeLinkURLPattern.MatchString(url) {
			b.WriteByte('[')
			b.WriteString(escapeMindmapText(s[textStart:textEnd]))
			b.WriteString("](")
			b.WriteString(urlHTMLEscaper.Replace(strings.TrimSpace(url)))
			b.WriteByte(')')
		} else {
			b.WriteString(escapeMindmapText(s[fullStart:fullEnd]))
		}
		last = fullEnd
	}
	b.WriteString(escapeMindmapText(s[last:]))
	return b.String()
}

// outputBlockEscaper is like mindmapTextEscaper, but for multi-line captured
// stdout/stderr rather than a single-line note: it neutralizes the same
// Markdown/HTML metacharacters, but turns newlines into literal `<br>` tags
// instead of collapsing them to a space, since the block renders inside a
// <pre>. A raw newline can't be used here even though <pre> would normally
// preserve it: this text sits inline inside a single Markdown list item, and
// an unindented newline there would be parsed as ending the list item.
var outputBlockEscaper = strings.NewReplacer(
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
	"\r", "",
	"\n", "<br>",
)

// maxOutputChars caps how much of a single stdout/stderr stream is embedded
// per validation, so one chatty script can't bloat the visualization file.
const maxOutputChars = 20000

func truncateOutput(s string) string {
	if len(s) <= maxOutputChars {
		return s
	}
	return s[:maxOutputChars] + "\n… (truncated)"
}

// buildOutputDetails renders a validation's captured stdout/stderr as a
// collapsed <details> block so it's available without cluttering the
// mindmap by default. Returns "" when there's nothing to show.
func buildOutputDetails(stdout, stderr string) string {
	stdout, stderr = strings.TrimSpace(stdout), strings.TrimSpace(stderr)
	if stdout == "" && stderr == "" {
		return ""
	}
	var body strings.Builder
	if stdout != "" {
		body.WriteString("<strong>stdout</strong><br>")
		body.WriteString(outputBlockEscaper.Replace(truncateOutput(stdout)))
	}
	if stderr != "" {
		if body.Len() > 0 {
			body.WriteString("<br><br>")
		}
		body.WriteString("<strong>stderr</strong><br>")
		body.WriteString(outputBlockEscaper.Replace(truncateOutput(stderr)))
	}
	return fmt.Sprintf(` <details class="bv-output"><summary>Output</summary><pre>%s</pre></details>`, body.String())
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
			fmt.Fprintf(&b, "- **%s** `#%s` `%s` — _%s_%s\n",
				escapeMindmapRich(r.Name), escapeMindmapText(r.ExecDisplay), r.ValidationID, escapeMindmapText(r.Manifest),
				buildOutputDetails(r.Stdout, r.Stderr))
			for _, note := range r.Notes {
				fmt.Fprintf(&b, "  - %s\n", escapeMindmapRich(note))
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
/* Mermaid pie legend text inherits primaryTextColor (white, for contrast
   against colored slices) which disappears against a white/light page
   background. Outline it so it stays legible on any background. */
.mermaid .legend text {
  fill: #fff;
  paint-order: stroke fill;
  stroke: #000;
  stroke-width: 3px;
  stroke-linejoin: round;
}
.mermaid .legend rect {
  stroke: #000;
  stroke-width: 1px;
}
.bv-output {
  display: inline-block;
  margin-left: 0.4rem;
  vertical-align: middle;
}
.bv-output summary {
  cursor: pointer;
  color: #0097e6;
  font-size: 0.85em;
}
.bv-output pre {
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 16rem;
  overflow: auto;
  margin-top: 0.25rem;
  padding: 0.5rem;
  border-radius: 0.35rem;
  background: #f0f0f0;
  color: #333;
  font-size: 0.8em;
}
.markmap-dark .bv-output pre {
  background: #1f1f22;
  color: #ddd;
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
