package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"text/template"
	"time"

	sprig "github.com/Masterminds/sprig/v3"
	"github.com/savioxavier/termlink"
	"gopkg.in/yaml.v3"
)

/* =========================
   Version (override via -ldflags)
   ========================= */

var (
	Version   = "1.6.0"
	GitCommit = "dev"
	BuildDate = "2026-08-11"
)

/* =========================
   Logging
   ========================= */

type logLevel int

const (
	DEBUG logLevel = iota
	INFO
	WARN
	ERROR
)

type logRecord struct {
	Time    string `json:"time" yaml:"time"`
	Level   string `json:"level" yaml:"level"`
	Message string `json:"message" yaml:"message"`
}

var (
	level            = INFO
	showOutputFlag   bool
	dumpScript       bool
	showVersion      bool
	strictMode       bool
	noSummary        bool
	listValidations  bool
	showFilter       string
	colorMode        string // auto|always|never
	useColor         bool   // resolved runtime decision
	outputMode       string // detailed|compact
	compactMode      bool   // resolved from outputMode
	enableAnsiVars   bool
	manifest         string
	levelArg         string
	logFile          string
	logFileFormat    string
	logRecords       []logRecord
	defaultUnixShell = "/usr/bin/bash"
	defaultWinShell  = "powershell.exe"

	nameRegex  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	varPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	// Integers or floats (with optional leading dot / scientific notation)
	numPattern = regexp.MustCompile(`^\s*-?(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+\-]?\d+)?\s*$`)

	// duplicate key tracking
	dupKeyCount int

	// ANSI pattern (used to strip when --color=never)
	ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

	// Markdown and plain HTTP(S) URL patterns for terminal hyperlinking
	mdPattern   = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	urlPattern  = regexp.MustCompile(`https?://\S+`)
	linkPattern = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)|https?://\S+`)
)

func logAt(l logLevel, format string, a ...any) {
	if l < level {
		return
	}
	prefix := map[logLevel]string{
		DEBUG: "[DEBUG] ",
		INFO:  "[INFO]  ",
		WARN:  "[WARN]  ",
		ERROR: "[ERROR] ",
	}[l]
	levelName := map[logLevel]string{
		DEBUG: "DEBUG",
		INFO:  "INFO",
		WARN:  "WARN",
		ERROR: "ERROR",
	}[l]
	ts := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, a...)

	// Guard against ANSI bleed:
	// - If colors are enabled, reset before timestamp,
	//   dim timestamp, reset, colorize the level prefix, reset before the message, then reset after.
	if useColor {
		fmt.Fprint(os.Stdout, reset+colorize(ts, dim)+" "+colorForLevel(l)+prefix+reset+msg+reset+"\n")
	} else {
		fmt.Fprintf(os.Stdout, ts+" "+prefix+"%s\n", msg)
	}

	if logFile != "" {
		logRecords = append(logRecords, logRecord{Time: ts, Level: levelName, Message: stripANSI(msg)})
	}
}

func detectLogFormat(path, explicit string) string {
	if explicit != "" {
		return strings.ToLower(strings.TrimSpace(explicit))
	}
	ext := strings.TrimPrefix(filepath.Ext(strings.ToLower(path)), ".")
	switch ext {
	case "json":
		return "json"
	case "yaml", "yml":
		return "yaml"
	case "md", "markdown":
		return "markdown"
	}
	return "json"
}

type logFileReport struct {
	Logs    []logRecord     `json:"logs" yaml:"logs"`
	Results []summaryResult `json:"results" yaml:"results"`
}

func writeLogFile(path, format string, results []summaryResult) error {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = detectLogFormat(path, "")
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	switch format {
	case "json":
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(logFileReport{Logs: logRecords, Results: results})
	case "yaml":
		enc := yaml.NewEncoder(f)
		defer enc.Close()
		return enc.Encode(logFileReport{Logs: logRecords, Results: results})
	case "markdown":
		return writeMarkdownLog(f, results)
	default:
		return fmt.Errorf("unknown log file format: %s", format)
	}
}

func writeMarkdownLog(w io.Writer, results []summaryResult) error {
	fmt.Fprintln(w, "# Validation Log")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "## Messages")
	fmt.Fprintln(w)
	for _, r := range logRecords {
		fmt.Fprintf(w, "* **%s [%s]** %s\n", r.Time, r.Level, r.Message)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "## Results")
	fmt.Fprintln(w)
	if len(results) == 0 {
		fmt.Fprintln(w, "*No results.*")
		return nil
	}
	grouped := make(map[string][]summaryResult)
	var order []string
	for _, res := range results {
		if _, ok := grouped[res.Manifest]; !ok {
			grouped[res.Manifest] = []summaryResult{}
			order = append(order, res.Manifest)
		}
		grouped[res.Manifest] = append(grouped[res.Manifest], res)
	}
	for _, m := range order {
		fmt.Fprintf(w, "### %s\n\n", m)
		fmt.Fprintln(w, "| # | ID | Name | Status |")
		fmt.Fprintln(w, "|---|---|---|---|")
		for _, res := range grouped[m] {
			fmt.Fprintf(w, "| %s | %s | %s | %s |\n", res.ExecDisplay, res.ValidationID, strings.ReplaceAll(res.Name, "|", "\\|"), res.Status)
		}
		fmt.Fprintln(w)
	}
	return nil
}

func maybeWriteLogFile(format string, results []summaryResult) {
	if logFile == "" {
		return
	}
	format = detectLogFormat(logFile, format)
	if err := writeLogFile(logFile, format, results); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing log file %s: %v\n", logFile, err)
	}
}

func setLevel(s string) {
	switch strings.ToUpper(s) {
	case "DEBUG":
		level = DEBUG
	case "INFO":
		level = INFO
	case "WARN", "WARNING":
		level = WARN
	case "ERROR":
		level = ERROR
	default:
		level = INFO
	}
}

/* =========================
   Color / TTY helpers
   (Windows impl lives in ansi_windows.go; non-Windows in ansi_unix.go)
   ========================= */

func builtinAnsiVars() []kv {
	return []kv{
		// reset
		{Key: "nc", Value: "\x1b[0m"},

		// regular colors
		{Key: "black", Value: "\x1b[0;30m"},
		{Key: "red", Value: "\x1b[0;31m"},
		{Key: "green", Value: "\x1b[0;32m"},
		{Key: "yellow", Value: "\x1b[0;33m"},
		{Key: "blue", Value: "\x1b[0;34m"},
		{Key: "purple", Value: "\x1b[0;35m"},
		{Key: "cyan", Value: "\x1b[0;36m"},
		{Key: "white", Value: "\x1b[0;37m"},

		// bold
		{Key: "bold_black", Value: "\x1b[1;30m"},
		{Key: "bold_red", Value: "\x1b[1;31m"},
		{Key: "bold_green", Value: "\x1b[1;32m"},
		{Key: "bold_yellow", Value: "\x1b[1;33m"},
		{Key: "bold_blue", Value: "\x1b[1;34m"},
		{Key: "bold_purple", Value: "\x1b[1;35m"},
		{Key: "bold_cyan", Value: "\x1b[1;36m"},
		{Key: "bold_white", Value: "\x1b[1;37m"},

		// underline
		{Key: "underline_black", Value: "\x1b[4;30m"},
		{Key: "underline_red", Value: "\x1b[4;31m"},
		{Key: "underline_green", Value: "\x1b[4;32m"},
		{Key: "underline_yellow", Value: "\x1b[4;33m"},
		{Key: "underline_blue", Value: "\x1b[4;34m"},
		{Key: "underline_purple", Value: "\x1b[4;35m"},
		{Key: "underline_cyan", Value: "\x1b[4;36m"},
		{Key: "underline_white", Value: "\x1b[4;37m"},

		// background
		{Key: "background_black", Value: "\x1b[40m"},
		{Key: "background_red", Value: "\x1b[41m"},
		{Key: "background_green", Value: "\x1b[42m"},
		{Key: "background_yellow", Value: "\x1b[43m"},
		{Key: "background_blue", Value: "\x1b[44m"},
		{Key: "background_purple", Value: "\x1b[45m"},
		{Key: "background_cyan", Value: "\x1b[46m"},
		{Key: "background_white", Value: "\x1b[47m"},

		// high intensity
		{Key: "intense_black", Value: "\x1b[0;90m"},
		{Key: "intense_red", Value: "\x1b[0;91m"},
		{Key: "intense_green", Value: "\x1b[0;92m"},
		{Key: "intense_yellow", Value: "\x1b[0;93m"},
		{Key: "intense_blue", Value: "\x1b[0;94m"},
		{Key: "intense_purple", Value: "\x1b[0;95m"},
		{Key: "intense_cyan", Value: "\x1b[0;96m"},
		{Key: "intense_white", Value: "\x1b[0;97m"},

		// bold high intensity
		{Key: "bold_intense_black", Value: "\x1b[1;90m"},
		{Key: "bold_intense_red", Value: "\x1b[1;91m"},
		{Key: "bold_intense_green", Value: "\x1b[1;92m"},
		{Key: "bold_intense_yellow", Value: "\x1b[1;93m"},
		{Key: "bold_intense_blue", Value: "\x1b[1;94m"},
		{Key: "bold_intense_purple", Value: "\x1b[1;95m"},
		{Key: "bold_intense_cyan", Value: "\x1b[1;96m"},
		{Key: "bold_intense_white", Value: "\x1b[1;97m"},

		// high intensity backgrounds
		{Key: "background_intense_black", Value: "\x1b[0;100m"},
		{Key: "background_intense_red", Value: "\x1b[0;101m"},
		{Key: "background_intense_green", Value: "\x1b[0;102m"},
		{Key: "background_intense_yellow", Value: "\x1b[0;103m"},
		{Key: "background_intense_blue", Value: "\x1b[0;104m"},
		{Key: "background_intense_purple", Value: "\x1b[0;105m"},
		{Key: "background_intense_cyan", Value: "\x1b[0;106m"},
		{Key: "background_intense_white", Value: "\x1b[0;107m"},
	}
}

func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func stripANSI(s string) string {
	return ansiRE.ReplaceAllString(s, "")
}

func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
		case r == 0xFE0E || r == 0xFE0F:
			// emoji variation selectors have no display width
		case r >= 0x2000:
			w += 2
		default:
			w++
		}
	}
	return w
}

// ANSI color helpers (no-op when colors are disabled).
const (
	reset     = "\x1b[0m"
	green     = "\x1b[0;32m"
	red       = "\x1b[0;31m"
	yellow    = "\x1b[0;33m"
	blue      = "\x1b[0;34m"
	magenta   = "\x1b[0;35m"
	cyan      = "\x1b[0;36m"
	boldWhite = "\x1b[1;37m"
	boldCyan  = "\x1b[1;36m"
	dim       = "\x1b[2;37m"
)

func colorize(s, code string) string {
	if !useColor || code == "" {
		return s
	}
	return code + s + reset
}

func colorForLevel(l logLevel) string {
	switch l {
	case DEBUG:
		return dim
	case INFO:
		return cyan
	case WARN:
		return yellow
	case ERROR:
		return red
	}
	return ""
}

func indent(depth int) string {
	if depth <= 0 {
		return ""
	}
	return colorize(strings.Repeat("  ", depth), dim)
}

func taskSeparator(depth, width int) string {
	return colorize(strings.Repeat("  ", depth)+strings.Repeat("─", width), dim)
}

func printTaskSeparator(depth int) {
	if compactMode {
		return
	}
	fmt.Println(taskSeparator(depth, 60))
}

func linkify(s string) string {
	if !useColor || !termlink.SupportsHyperlinks() {
		return s
	}
	return linkPattern.ReplaceAllStringFunc(s, func(match string) string {
		if md := mdPattern.FindStringSubmatch(match); md != nil {
			return termlink.Link(md[1], md[2])
		}
		trimmed := strings.TrimRightFunc(match, func(r rune) bool {
			return r == '.' || r == ',' || r == ')' || r == ']' || r == '}' || r == ';' || r == '>'
		})
		link := termlink.Link(trimmed, trimmed)
		if len(trimmed) < len(match) {
			link += match[len(trimmed):]
		}
		return link
	})
}

/* =========================
   Interpreter detection
   ========================= */

type interpreterKind int

const (
	interpOther      interpreterKind = iota
	interpShell                      // bash/sh/zsh/dash/ksh
	interpPowerShell                 // powershell.exe / pwsh
	interpCmd                        // cmd.exe
)

func detectInterpreterKind(path string) interpreterKind {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(base, "bash") ||
		base == "sh" || strings.Contains(base, "zsh") ||
		strings.Contains(base, "dash") || strings.Contains(base, "ksh"):
		return interpShell
	case base == "powershell" || base == "powershell.exe" || base == "pwsh":
		return interpPowerShell
	case base == "cmd" || base == "cmd.exe":
		return interpCmd
	default:
		return interpOther
	}
}

func findExecutable(candidates []string) string {
	for _, cand := range candidates {
		if strings.Contains(cand, "/") || strings.Contains(cand, `\`) {
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				return cand
			}
			continue
		}
		if p, err := exec.LookPath(cand); err == nil {
			return p
		}
	}
	return ""
}

// activateVenv prepends a local .venv/Scripts (Windows) or .venv/bin
// directory to PATH so that any python/python3 call resolves to the venv.
func activateVenv() {
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	venvDir := filepath.Join(cwd, ".venv")
	st, err := os.Stat(venvDir)
	if err != nil || !st.IsDir() {
		return
	}

	binDir := "bin"
	if runtime.GOOS == "windows" {
		binDir = "Scripts"
	}
	venvBin := filepath.Join(venvDir, binDir)
	st, err = os.Stat(venvBin)
	if err != nil || !st.IsDir() {
		return
	}

	path := os.Getenv("PATH")
	if path != "" {
		path = venvBin + string(os.PathListSeparator) + path
	} else {
		path = venvBin
	}
	os.Setenv("PATH", path)
	if p, err := exec.LookPath("python"); err == nil {
		logAt(INFO, "Detected .venv in %s; using python: %s", cwd, p)
	} else if p, err := exec.LookPath("python3"); err == nil {
		logAt(INFO, "Detected .venv in %s; using python3: %s", cwd, p)
	} else {
		logAt(INFO, "Detected .venv in %s; prepended %s to PATH", cwd, venvBin)
	}
}

func autoDetectDefaultInterpreter() (string, interpreterKind) {
	switch runtime.GOOS {
	case "windows":
		winCandidates := []string{
			"pwsh.exe", "pwsh",
			"powershell.exe", "powershell",
		}
		if comspec := os.Getenv("ComSpec"); strings.TrimSpace(comspec) != "" {
			winCandidates = append(winCandidates, comspec)
		}
		winCandidates = append(winCandidates, "cmd.exe", "cmd")
		if p := findExecutable(winCandidates); p != "" {
			return p, detectInterpreterKind(p)
		}
		return defaultWinShell, detectInterpreterKind(defaultWinShell)
	case "darwin":
		macCandidates := []string{
			"/opt/homebrew/bin/bash",
			"/usr/local/bin/bash",
			"bash", "/bin/bash",
			"zsh", "/bin/zsh",
			"sh", "/bin/sh",
			"python3",
			"python",
		}
		if p := findExecutable(macCandidates); p != "" {
			return p, detectInterpreterKind(p)
		}
		return defaultUnixShell, detectInterpreterKind(defaultUnixShell)
	default: // linux/unix
		linuxCandidates := []string{
			"/usr/bin/bash", "/bin/bash", "bash",
			"zsh", "/usr/bin/zsh", "/bin/zsh",
			"sh", "/bin/sh", "/usr/bin/sh",
			"python3",
			"python",
		}
		if p := findExecutable(linuxCandidates); p != "" {
			return p, detectInterpreterKind(p)
		}
		return defaultUnixShell, detectInterpreterKind(defaultUnixShell)
	}
}

/* =========================
   YAML helpers (preserve order) + dup warnings
   ========================= */

type kv struct {
	Key   string
	Value string
}

type manifestData struct {
	TemplateVars map[string]any
	Content      string
}

func getMapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(m.Content); i += 2 {
		k := m.Content[i]
		v := m.Content[i+1]
		if k.Value == key {
			return v
		}
	}
	return nil
}

func warnDuplicateKeys(m *yaml.Node, context string) {
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	seen := map[string]int{}
	for i := 0; i < len(m.Content); i += 2 {
		k := m.Content[i]
		seen[k.Value]++
	}
	for k, n := range seen {
		if n > 1 {
			logAt(WARN, "Duplicate key %q in %s; the first occurrence will be used.", k, context)
			dupKeyCount++
		}
	}
}

func toString(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	_ = enc.Encode(n)
	_ = enc.Close()
	return strings.TrimSpace(buf.String())
}

func orderedVars(mapNode *yaml.Node, context string) ([]kv, error) {
	out := []kv{}
	if mapNode == nil {
		return out, nil
	}
	if mapNode.Kind != yaml.MappingNode {
		return nil, errors.New("vars must be a mapping")
	}
	warnDuplicateKeys(mapNode, context+" vars")
	seen := map[string]bool{}
	for i := 0; i < len(mapNode.Content); i += 2 {
		k := mapNode.Content[i]
		v := mapNode.Content[i+1]
		key := k.Value
		if seen[key] {
			continue // first wins
		}
		if !nameRegex.MatchString(key) {
			return nil, fmt.Errorf("invalid variable name for shell: %q", key)
		}
		out = append(out, kv{Key: key, Value: toString(v)})
		seen[key] = true
	}
	return out, nil
}

// Merge: globals first (in order), then locals override (moved to end)
func mergeVars(globals, locals []kv) (mergedList []kv, mergedMap map[string]string) {
	mergedMap = make(map[string]string)
	for _, p := range globals {
		mergedMap[p.Key] = p.Value
		mergedList = append(mergedList, kv{p.Key, p.Value})
	}
	for _, p := range locals {
		mergedMap[p.Key] = p.Value
		tmp := mergedList[:0]
		for _, e := range mergedList {
			if e.Key != p.Key {
				tmp = append(tmp, e)
			}
		}
		mergedList = tmp
		mergedList = append(mergedList, kv{p.Key, p.Value})
	}
	return mergedList, mergedMap
}

/* =========================
   Quoters / headers per interpreter
   ========================= */

// numeric literals unquoted for bash arithmetic; everything else quoted
func bashFormatValue(s string) string {
	if numPattern.MatchString(s) {
		return strings.TrimSpace(s)
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func psQuote(s string) string {
	s = strings.ReplaceAll(s, "`", "``")
	s = strings.ReplaceAll(s, `"`, "`\"")
	return `"` + s + `"`
}

func cmdQuoteValue(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
	s = strings.ReplaceAll(s, `"`, `""`)
	return s
}

func buildHeader(kind interpreterKind, pairs []kv) string {
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('\n')
		}
		switch kind {
		case interpShell:
			b.WriteString(p.Key)
			b.WriteByte('=') // <-- byte, not string
			b.WriteString(bashFormatValue(p.Value))
		case interpPowerShell:
			b.WriteString(`$env:`)
			b.WriteString(p.Key)
			b.WriteByte('=') // optional: also fine to keep as WriteString("=")
			b.WriteString(psQuote(p.Value))
		case interpCmd:
			b.WriteString(`set "`)
			b.WriteString(p.Key)
			b.WriteByte('=') // optional: also fine to keep as WriteString("=")
			b.WriteString(cmdQuoteValue(p.Value))
			b.WriteString(`"`)
		default:
			b.WriteString("# no-op for non-shell interpreter")
		}
	}
	return b.String()
}

/* =========================
   Message templating
   ========================= */

func renderMsg(msg string, vars map[string]string) string {
	if msg == "" {
		return ""
	}
	return varPattern.ReplaceAllStringFunc(msg, func(m string) string {
		sub := varPattern.FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		key := sub[1]
		if v, ok := vars[key]; ok {
			return v
		}
		if ev := os.Getenv(key); ev != "" {
			return ev
		}
		return m
	})
}

// Collect OS environment into a map[string]string
func envMap() map[string]string {
	m := make(map[string]string)
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k := kv[:i]
			v := kv[i+1:]
			m[k] = v
		}
	}
	return m
}

// Extract top-level `templates` (mapping of string->string) from the parsed YAML root.
func extractTemplates(root *yaml.Node) map[string]string {
	out := make(map[string]string)
	if root == nil || len(root.Content) == 0 {
		return out
	}
	top := root.Content[0]
	if top == nil || top.Kind != yaml.MappingNode {
		return out
	}
	tplNode := getMapValue(top, "templateVars")
	if tplNode == nil || tplNode.Kind != yaml.MappingNode {
		return out
	}
	// Preserve only first occurrence per key (matching your duplicate-key rule)
	seen := map[string]bool{}
	for i := 0; i < len(tplNode.Content); i += 2 {
		k := tplNode.Content[i]
		v := tplNode.Content[i+1]
		key := k.Value
		if seen[key] {
			continue
		}
		out[key] = toString(v)
		seen[key] = true
	}
	return out
}

// buildTemplateContext flattens everything into a single namespace for templating,
// plus a nested .Env. `templates` can contain strings, arrays, or maps.
func buildTemplateContext(
	mergedVars map[string]string,
	templates map[string]any,
	env map[string]string,
) map[string]any {
	ctx := make(map[string]any, len(env)+len(templates)+len(mergedVars)+1)

	// lowest precedence → highest precedence
	for k, v := range env {
		ctx[k] = v
	}
	for k, v := range templates {
		ctx[k] = v
	}
	for k, v := range mergedVars {
		ctx[k] = v
	}

	// always provide .Env
	ctx["Env"] = env
	return ctx
}

// Render a Go template string using Sprig functions and the provided context.
// We keep missing keys as empty (no hard error), but you can switch to Option("missingkey=error") if desired.
func renderTemplate(name, text string, ctx any) (string, error) {
	if strings.TrimSpace(text) == "" {
		return text, nil
	}
	tpl, err := template.New(name).
		Funcs(sprig.FuncMap()).
		Option("missingkey=default").
		Parse(text)
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	if err := tpl.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}

/* =========================
   Manifest model + parsing (defaults + per-validation show_output)
   ========================= */

type manifestDefaults struct {
	InterpreterPath  string
	InterpreterFlags []string
	EnvOnly          bool
	ShowOutput       bool
	ShowOutputSet    bool
}

type functionDef struct {
	Name   string `yaml:"name"`
	Source string `yaml:"source"`
}

type functionsMap map[string][]functionDef

type includeBlock struct {
	Name          string
	Path          string
	Vars          map[string]any
	PropagateTags bool
}

type loopItem struct {
	Name  string
	Vars  map[string]any
	Tags  []string
	Notes []string
}

type outcome struct {
	Message   string `yaml:"message"`
	ExitCodes []int  `yaml:"exit_codes"`
}

type condition struct {
	Eval string `yaml:"eval"`
}

type initEntry struct {
	Name      string
	SkipError bool
	Script    string
}

type validation struct {
	ExecNumber       int
	ValidationID     string
	Name             string
	Tags             []string `yaml:"tags"`
	Conditions       []condition
	Script           string
	Pass             outcome
	Fail             outcome
	Warn             outcome
	InterpreterPath  string
	InterpreterFlags []string
	LocalVarsOrdered []kv
	LocalVarsMap     map[string]string
	EnvOnly          bool
	EnvOnlySet       bool // explicitly set in manifest
	ShowOutput       bool // per-validation override of --show-output
	ShowOutputSet    bool
	Includes         []includeBlock
	Loop             []loopItem
	Notes            []string
}

func computeValidationID(execNumber int, name string) string {
	h := fnv.New32a()
	fmt.Fprintf(h, "%d:%s", execNumber, name)
	return fmt.Sprintf("%08x", h.Sum32())
}

// parseManifestTemplateSection reads the top-level `templates:` mapping and returns it
// as map[string]any so values can be strings, arrays, or nested maps.
func parseManifestTemplateSection(r io.Reader) (map[string]any, error) {
	var doc yaml.Node
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("invalid yaml: missing document")
	}

	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("invalid yaml: root is not a mapping")
	}

	// Find the "templates" key at the top level.
	var templatesNode *yaml.Node
	for i := 0; i < len(root.Content); i += 2 {
		k := root.Content[i]
		v := root.Content[i+1]
		if k.Kind == yaml.ScalarNode && k.Value == "templateVars" {
			templatesNode = v
			break
		}
	}

	if templatesNode == nil {
		return map[string]any{}, nil
	}
	if templatesNode.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("invalid yaml: templates is not a mapping")
	}

	out := make(map[string]any)
	if err := templatesNode.Decode(&out); err != nil {
		return nil, fmt.Errorf("decode templates: %w", err)
	}
	return out, nil
}

func fetchURL(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "validator/"+Version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Read a small body snippet for error context
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTP %d fetching %s: %s", resp.StatusCode, url, strings.TrimSpace(string(snippet)))
	}

	return io.ReadAll(resp.Body)
}

// Read manifest from local path or URL
func readManifestSource(src string) ([]byte, error) {
	s := strings.TrimSpace(src)
	if s == "-" {
		return io.ReadAll(os.Stdin)
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return fetchURL(s)
	}
	s = strings.TrimPrefix(s, "file://")
	return os.ReadFile(s)
}

func loadManifest(path string) (*manifestData, error) {
	f, err := readManifestSource(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	tmplVars, err := parseManifestTemplateSection(bytes.NewReader(f))
	if err != nil {
		return nil, fmt.Errorf("Templating error %s: %w", path, err)
	}
	return &manifestData{
		TemplateVars: tmplVars,
		Content:      string(f),
	}, nil

}

func parseManifest(root *yaml.Node) (globals []kv, defs manifestDefaults, funcs functionsMap, inits []initEntry, vals []validation, err error) {
	dupKeyCount = 0 // reset for each parse

	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, manifestDefaults{}, nil, nil, nil, errors.New("invalid YAML document")
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, manifestDefaults{}, nil, nil, nil, errors.New("top-level YAML must be a mapping")
	}

	// warn duplicates at top level
	warnDuplicateKeys(top, "top-level")

	// defaults (optional)
	if d := getMapValue(top, "defaults"); d != nil && d.Kind == yaml.MappingNode {
		warnDuplicateKeys(d, "defaults")
		if eo := getMapValue(d, "env_only"); eo != nil {
			defs.EnvOnly = strings.EqualFold(strings.TrimSpace(toString(eo)), "true")
		}
		if so := getMapValue(d, "show_output"); so != nil {
			defs.ShowOutput = strings.EqualFold(strings.TrimSpace(toString(so)), "true")
			defs.ShowOutputSet = true
		}
		if di := getMapValue(d, "interpreters"); di != nil && di.Kind == yaml.MappingNode {
			warnDuplicateKeys(di, "defaults.interpreters")
			if s := getMapValue(di, "script"); s != nil && strings.TrimSpace(toString(s)) != "" {
				defs.InterpreterPath = strings.TrimSpace(toString(s))
			}
			if f := getMapValue(di, "flags"); f != nil && f.Kind == yaml.SequenceNode {
				for _, n := range f.Content {
					defs.InterpreterFlags = append(defs.InterpreterFlags, toString(n))
				}
			}
		}
	}

	// top-level init (optional)
	if iNode := getMapValue(top, "init"); iNode != nil && iNode.Kind == yaml.SequenceNode {
		for _, item := range iNode.Content {
			if item.Kind != yaml.MappingNode {
				return nil, manifestDefaults{}, nil, nil, nil, errors.New("each init entry must be a mapping")
			}
			warnDuplicateKeys(item, "init")
			var name string
			if n := getMapValue(item, "name"); n != nil {
				name = toString(n)
			} else if len(item.Content) >= 2 && item.Content[0].Kind == yaml.ScalarNode {
				name = item.Content[0].Value
			}
			if name == "" {
				return nil, manifestDefaults{}, nil, nil, nil, errors.New("init entry missing a name")
			}
			ie := initEntry{Name: name}
			if se := getMapValue(item, "skip_error"); se != nil {
				ie.SkipError = strings.EqualFold(strings.TrimSpace(toString(se)), "true")
			}
			if s := getMapValue(item, "script"); s != nil {
				ie.Script = toString(s)
			}
			inits = append(inits, ie)
		}
	}

	// top-level functions (optional)
	funcs = make(functionsMap)
	if fNode := getMapValue(top, "functions"); fNode != nil && fNode.Kind == yaml.MappingNode {
		warnDuplicateKeys(fNode, "functions")
		for i := 0; i < len(fNode.Content); i += 2 {
			k := fNode.Content[i] // interpreter key (e.g. bash, powershell)
			v := fNode.Content[i+1]
			key := k.Value
			if v.Kind == yaml.SequenceNode {
				var list []functionDef
				if err := v.Decode(&list); err == nil {
					funcs[key] = list
				} else {
					logAt(WARN, "Failed to decode functions list for %q: %v", key, err)
				}
			}
		}
	}

	// top-level vars
	if gv := getMapValue(top, "vars"); gv != nil {
		gl, err2 := orderedVars(gv, "top-level")
		if err2 != nil {
			return nil, manifestDefaults{}, nil, nil, nil, fmt.Errorf("top-level vars: %w", err2)
		}
		globals = gl
	}

	// validations
	vNode := getMapValue(top, "validations")
	if vNode == nil || vNode.Kind != yaml.SequenceNode {
		return nil, manifestDefaults{}, nil, nil, nil, errors.New("`validations` must be a sequence")
	}

	for valIdx, item := range vNode.Content {
		if item.Kind != yaml.MappingNode {
			return nil, manifestDefaults{}, nil, nil, nil, errors.New("each validation must be a mapping")
		}

		warnDuplicateKeys(item, "validation")

		var name string
		var body *yaml.Node

		if getMapValue(item, "name") != nil {
			nNode := getMapValue(item, "name")
			name = toString(nNode)
			body = &yaml.Node{Kind: yaml.MappingNode}
			for i := 0; i < len(item.Content); i += 2 {
				k := item.Content[i]
				v := item.Content[i+1]
				if k.Value == "name" {
					continue
				}
				body.Content = append(body.Content, k, v)
			}
		} else if len(item.Content) == 2 {
			name = item.Content[0].Value
			body = item.Content[1]
		} else {
			return nil, manifestDefaults{}, nil, nil, nil, errors.New("validation missing a name")
		}

		if body == nil || body.Kind != yaml.MappingNode {
			return nil, manifestDefaults{}, nil, nil, nil, fmt.Errorf("validation %q body must be a mapping", name)
		}

		warnDuplicateKeys(body, fmt.Sprintf("validation %q", name))

		script := toString(getMapValue(body, "script"))

		var pass, fail, warn outcome
		if outcomes := getMapValue(body, "outcomes"); outcomes != nil && outcomes.Kind == yaml.MappingNode {
			warnDuplicateKeys(outcomes, fmt.Sprintf("validation %q outcomes", name))
			if pNode := getMapValue(outcomes, "pass"); pNode != nil {
				if msg := getMapValue(pNode, "message"); msg != nil {
					pass.Message = toString(msg)
				}
				if ecs := getMapValue(pNode, "exit_codes"); ecs != nil && ecs.Kind == yaml.SequenceNode {
					for _, n := range ecs.Content {
						if val, err := json.Number(toString(n)).Int64(); err == nil {
							pass.ExitCodes = append(pass.ExitCodes, int(val))
						}
					}
				}
			}
			if fNode := getMapValue(outcomes, "fail"); fNode != nil {
				if msg := getMapValue(fNode, "message"); msg != nil {
					fail.Message = toString(msg)
				}
				if ecs := getMapValue(fNode, "exit_codes"); ecs != nil && ecs.Kind == yaml.SequenceNode {
					for _, n := range ecs.Content {
						if val, err := json.Number(toString(n)).Int64(); err == nil {
							fail.ExitCodes = append(fail.ExitCodes, int(val))
						}
					}
				}
			}
			if wNode := getMapValue(outcomes, "warn"); wNode != nil {
				if msg := getMapValue(wNode, "message"); msg != nil {
					warn.Message = toString(msg)
				}
				if ecs := getMapValue(wNode, "exit_codes"); ecs != nil && ecs.Kind == yaml.SequenceNode {
					for _, n := range ecs.Content {
						if val, err := json.Number(toString(n)).Int64(); err == nil {
							warn.ExitCodes = append(warn.ExitCodes, int(val))
						}
					}
				}
			}
		}
		if pass.Message == "" {
			pass.Message = "PASS"
		}
		if fail.Message == "" {
			fail.Message = "FAIL"
		}
		if warn.Message == "" {
			warn.Message = "WARN"
		}

		interp := ""
		var flags []string
		if interps := getMapValue(body, "interpreters"); interps != nil && interps.Kind == yaml.MappingNode {
			warnDuplicateKeys(interps, fmt.Sprintf("validation %q interpreters", name))
			if s := getMapValue(interps, "script"); s != nil && strings.TrimSpace(toString(s)) != "" {
				interp = strings.TrimSpace(toString(s))
			}
			if f := getMapValue(interps, "flags"); f != nil && f.Kind == yaml.SequenceNode {
				for _, n := range f.Content {
					flags = append(flags, toString(n))
				}
			}
		}

		envOnly := false
		envOnlySet := false
		if eo := getMapValue(body, "env_only"); eo != nil {
			envOnly = strings.EqualFold(strings.TrimSpace(toString(eo)), "true")
			envOnlySet = true
		}

		showOutputVal := false
		showOutputSet := false
		if so := getMapValue(body, "show_output"); so != nil {
			showOutputVal = strings.EqualFold(strings.TrimSpace(toString(so)), "true")
			showOutputSet = true
		}

		var tags []string
		if t := getMapValue(body, "tags"); t != nil && t.Kind == yaml.SequenceNode {
			for _, n := range t.Content {
				tags = append(tags, toString(n))
			}
		}

		var notes []string
		if nNode := getMapValue(body, "notes"); nNode != nil && nNode.Kind == yaml.SequenceNode {
			for _, n := range nNode.Content {
				notes = append(notes, toString(n))
			}
		}

		var conditions []condition
		if cNode := getMapValue(body, "conditions"); cNode != nil && cNode.Kind == yaml.SequenceNode {
			for _, n := range cNode.Content {
				if n.Kind == yaml.MappingNode {
					var c condition
					if evalNode := getMapValue(n, "eval"); evalNode != nil {
						c.Eval = toString(evalNode)
					}
					conditions = append(conditions, c)
				}
			}
		}

		var includes []includeBlock
		if incNode := getMapValue(body, "includes"); incNode != nil && incNode.Kind == yaml.SequenceNode {
			for _, n := range incNode.Content {
				if n.Kind == yaml.MappingNode {
					ib := includeBlock{Vars: make(map[string]any), PropagateTags: true}
					if nameNode := getMapValue(n, "name"); nameNode != nil {
						ib.Name = toString(nameNode)
					}
					if pathNode := getMapValue(n, "path"); pathNode != nil {
						ib.Path = toString(pathNode)
					}
					if propNode := getMapValue(n, "propagate_tags"); propNode != nil {
						ib.PropagateTags = strings.EqualFold(strings.TrimSpace(toString(propNode)), "true")
					}
					if varsNode := getMapValue(n, "vars"); varsNode != nil && varsNode.Kind == yaml.MappingNode {
						for i := 0; i < len(varsNode.Content); i += 2 {
							k := varsNode.Content[i].Value
							var vAny any
							if err := varsNode.Content[i+1].Decode(&vAny); err == nil {
								ib.Vars[k] = vAny
							} else {
								ib.Vars[k] = toString(varsNode.Content[i+1])
							}
						}
					}
					includes = append(includes, ib)
				}
			}
		}

		var loop []loopItem
		if loopNode := getMapValue(body, "loop"); loopNode != nil && loopNode.Kind == yaml.SequenceNode {
			for _, n := range loopNode.Content {
				if n.Kind == yaml.MappingNode {
					li := loopItem{Vars: make(map[string]any)}
					if nameNode := getMapValue(n, "name"); nameNode != nil {
						li.Name = toString(nameNode)
					}
					if varsNode := getMapValue(n, "vars"); varsNode != nil && varsNode.Kind == yaml.MappingNode {
						for i := 0; i < len(varsNode.Content); i += 2 {
							k := varsNode.Content[i].Value
							var vAny any
							if err := varsNode.Content[i+1].Decode(&vAny); err == nil {
								li.Vars[k] = vAny
							} else {
								li.Vars[k] = toString(varsNode.Content[i+1])
							}
						}
					}
					if tagsNode := getMapValue(n, "tags"); tagsNode != nil && tagsNode.Kind == yaml.SequenceNode {
						for _, tn := range tagsNode.Content {
							li.Tags = append(li.Tags, toString(tn))
						}
					}
					if notesNode := getMapValue(n, "notes"); notesNode != nil && notesNode.Kind == yaml.SequenceNode {
						for _, nn := range notesNode.Content {
							li.Notes = append(li.Notes, toString(nn))
						}
					}

					loop = append(loop, li)
				}
			}
		}

		var localOrdered []kv
		if lv := getMapValue(body, "vars"); lv != nil {
			lo, err2 := orderedVars(lv, fmt.Sprintf("validation %q", name))
			if err2 != nil {
				return nil, manifestDefaults{}, nil, nil, nil, fmt.Errorf("validation %q vars: %w", name, err2)
			}
			localOrdered = lo
		}
		localMap := map[string]string{}
		for _, p := range localOrdered {
			localMap[p.Key] = p.Value
		}

		execNum := valIdx + 1
		vid := computeValidationID(execNum, name)

		vals = append(vals, validation{
			ExecNumber:       execNum,
			ValidationID:     vid,
			Name:             name,
			Tags:             tags,
			Conditions:       conditions,
			Script:           script,
			Pass:             pass,
			Fail:             fail,
			Warn:             warn,
			InterpreterPath:  interp,
			InterpreterFlags: flags,
			LocalVarsOrdered: localOrdered,
			LocalVarsMap:     localMap,
			EnvOnly:          envOnly,
			EnvOnlySet:       envOnlySet,
			ShowOutput:       showOutputVal,
			ShowOutputSet:    showOutputSet,
			Includes:         includes,
			Loop:             loop,
			Notes:            notes,
		})
	}

	// If strict mode is on and we saw duplicates, fail parsing.
	if strictMode && dupKeyCount > 0 {
		return nil, manifestDefaults{}, nil, nil, nil, fmt.Errorf("manifest contains %d duplicate key(s); re-run without --strict to see WARN logs", dupKeyCount)
	}

	return globals, defs, funcs, inits, vals, nil
}

/* =========================
   Process exec (buffered and live-stream variants) + progress indicator
   ========================= */

func writeTemp(content, suffix string) (string, error) {
	f, err := os.CreateTemp("", "validator-*"+suffix)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.WriteString(f, content); err != nil {
		return "", err
	}
	_ = f.Chmod(0o700)
	return f.Name(), nil
}

type runResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// Buffered runner (kept for non-streaming path)
func runWithInterpreter(interpreter string, flags []string, script string, extraEnv map[string]string, kind interpreterKind) (*runResult, error) {
	suffix := ".tmp"
	switch kind {
	case interpShell:
		suffix = ".sh"
	case interpPowerShell:
		suffix = ".ps1"
	case interpCmd:
		suffix = ".cmd"
	}

	path, err := writeTemp(script, suffix)
	if err != nil {
		return nil, err
	}
	defer os.Remove(path)

	var args []string
	switch kind {
	case interpPowerShell:
		if len(flags) == 0 {
			args = []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path}
		} else {
			args = append(flags, path)
		}
	case interpCmd:
		if len(flags) > 0 {
			args = append(flags, "/C", path)
		} else {
			args = []string{"/C", path}
		}
	default:
		if len(flags) > 0 {
			args = append(flags, path)
		} else {
			args = []string{path}
		}
	}

	cmd := exec.Command(interpreter, args...)

	env := os.Environ()
	if len(extraEnv) > 0 {
		for k, v := range extraEnv {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd.Env = env

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	start := time.Now()
	err = cmd.Run()
	dur := time.Since(start)

	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			exit = 1
		}
	}

	return &runResult{
		Stdout:   outBuf.String(),
		Stderr:   errBuf.String(),
		ExitCode: exit,
		Duration: dur,
	}, nil
}

// Live-stream runner: prints lines as they arrive (with prefixes) and also buffers.
// Live-stream runner: prints lines as they arrive (with prefixes) and also buffers.
// Now prints STDOUT/STDERR headers lazily, only when the first line arrives.
func runWithInterpreterLive(
	interpreter string,
	flags []string,
	script string,
	extraEnv map[string]string,
	kind interpreterKind,
	logName string, // validation name for headers
	stripColor bool,
) (*runResult, error) {

	suffix := ".tmp"
	switch kind {
	case interpShell:
		suffix = ".sh"
	case interpPowerShell:
		suffix = ".ps1"
	case interpCmd:
		suffix = ".cmd"
	}

	path, err := writeTemp(script, suffix)
	if err != nil {
		return nil, err
	}
	defer os.Remove(path)

	var args []string
	switch kind {
	case interpPowerShell:
		if len(flags) == 0 {
			args = []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path}
		} else {
			args = append(flags, path)
		}
	case interpCmd:
		if len(flags) > 0 {
			args = append(flags, "/C", path)
		} else {
			args = []string{"/C", path}
		}
	default:
		if len(flags) > 0 {
			args = append(flags, path)
		} else {
			args = []string{path}
		}
	}

	cmd := exec.Command(interpreter, args...)

	env := os.Environ()
	if len(extraEnv) > 0 {
		for k, v := range extraEnv {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd.Env = env

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	var outBuf, errBuf bytes.Buffer
	var wg sync.WaitGroup

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Print headers lazily when first line arrives
	var stdoutHeaderOnce sync.Once
	var stderrHeaderOnce sync.Once

	wg.Add(2)

	scan := func(r io.Reader, isStdout bool) {
		defer wg.Done()
		scanner := bufio.NewScanner(r)
		// Support long lines
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 10*1024*1024)

		for scanner.Scan() {
			lineRaw := scanner.Text()

			if isStdout {
				stdoutHeaderOnce.Do(func() {
					logAt(INFO, "[%s] STDOUT:", logName)
				})
			} else {
				stderrHeaderOnce.Do(func() {
					logAt(INFO, "[%s] STDERR:", logName)
				})
			}

			// Log line (strip ANSI if requested)
			lineToLog := lineRaw
			if stripColor {
				lineToLog = stripANSI(lineToLog)
			}
			logAt(INFO, "%s", lineToLog)

			// Buffer raw (unstripped) to mirror non-streaming path
			if isStdout {
				outBuf.WriteString(lineRaw)
				outBuf.WriteByte('\n')
			} else {
				errBuf.WriteString(lineRaw)
				errBuf.WriteByte('\n')
			}
		}
		if err := scanner.Err(); err != nil {
			// Surface scanner errors in the error buffer
			if isStdout {
				errBuf.WriteString(fmt.Sprintf("[stream error reading STDOUT: %v]\n", err))
			} else {
				errBuf.WriteString(fmt.Sprintf("[stream error reading STDERR: %v]\n", err))
			}
		}
	}

	go scan(stdoutPipe, true)
	go scan(stderrPipe, false)

	wg.Wait()
	runErr := cmd.Wait()
	dur := time.Since(start)

	exit := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			exit = 1
		}
	}

	return &runResult{
		Stdout:   strings.TrimRight(outBuf.String(), "\n"),
		Stderr:   strings.TrimRight(errBuf.String(), "\n"),
		ExitCode: exit,
		Duration: dur,
	}, nil
}

/* =========================
   Progress indicator for non-streaming runs
   ========================= */

func startProgress(name string) (stop func()) {
	// In compact mode, don't emit any progress lines.
	if compactMode {
		return func() {}
	}

	// If DEBUG, just print start/finish lines (no spinner).
	if level == DEBUG {
		start := time.Now()
		logAt(INFO, "[%s] Running...", name)
		return func() {
			elapsed := time.Since(start).Round(time.Millisecond)
			logAt(INFO, "[%s] Finished in %s", name, elapsed)
		}
	}

	start := time.Now()
	isTTY := stdoutIsTTY()
	if !isTTY {
		// Non-TTY: simple start/finish lines with timing.
		logAt(INFO, "[%s] Running...", name)
		return func() {
			elapsed := time.Since(start).Round(time.Millisecond)
			logAt(INFO, "[%s] Finished in %s", name, elapsed)
		}
	}

	// TTY spinner with completion handshake.
	frames := []string{"-", "\\", "|", "/"}
	done := make(chan struct{})
	finished := make(chan struct{}) // signal when spinner has fully cleaned up

	go func() {
		i := 0
		ticker := time.NewTicker(120 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				// Clear spinner line and emit a terminating newline BEFORE we signal finished.
				// Also reset in case child left the terminal in a colored state.
				fmt.Fprintf(os.Stdout, "\r%s%s\r\n", reset, strings.Repeat(" ", 80))
				close(finished)
				return
			case <-ticker.C:
				elapsed := time.Since(start).Round(time.Millisecond)
				// Start each redraw with a reset to protect the prefix from bleed.
				fmt.Fprintf(os.Stdout, "\r%s[INFO]  [%s] Running %s %s", reset, name, frames[i%len(frames)], elapsed)
				i++
			}
		}
	}()

	return func() {
		close(done)
		<-finished
	}

}

/* =========================
   main
   ========================= */

// repeatedStringFlag allows -e to be specified multiple times
type repeatedStringFlag []string

func (i *repeatedStringFlag) String() string {
	return strings.Join(*i, ", ")
}

func (i *repeatedStringFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var extraVarFlags repeatedStringFlag

func main() {
	flag.StringVar(&manifest, "manifest", "", "Path to YAML manifest")
	flag.StringVar(&levelArg, "log-level", "INFO", "Log level: DEBUG, INFO, WARN, ERROR")
	flag.BoolVar(&showOutputFlag, "show-output", false, "Show child STDOUT/STDERR (overridden by per-validation show_output and defaults.show_output)")
	flag.BoolVar(&dumpScript, "dump-script", false, "Dump final assembled scripts at DEBUG")
	flag.BoolVar(&showVersion, "version", false, "Print version information and exit")
	flag.BoolVar(&strictMode, "strict", false, "Fail with non-zero exit if duplicate keys are found in the manifest")
	flag.BoolVar(&noSummary, "no-summary", false, "Skip printing the summary of Pass/Fail steps at the end")
	flag.BoolVar(&listValidations, "list", false, "List all validations with their Execution Number and Validation ID, then exit")
	flag.StringVar(&showFilter, "show", "", "Show rendered script for validations matching the given Validation ID or name pattern, then exit")
	flag.BoolVar(&enableAnsiVars, "ansi-vars", true, "Expose built-in ANSI color variables to scripts (can be overridden by manifest)")
	flag.StringVar(&colorMode, "color", "auto", "Color output: auto|always|never (affects child output pass-through)")
	flag.StringVar(&outputMode, "output", "detailed", "Output mode: detailed|compact")
	flag.Var(&extraVarFlags, "extra-var", "Specify extra variables for config template as key=value pairs (can be specified multiple times)")
	flag.Var(&extraVarFlags, "e", "Alias for --extra-var")

	flag.StringVar(&logFile, "log-file", "", "Write captured output to a file")
	flag.StringVar(&logFileFormat, "log-file-format", "", "Log file format: json|yaml|markdown (auto-detected from --log-file extension by default)")

	var filterNameRegex string
	flag.StringVar(&filterNameRegex, "name", "", "Regex pattern to filter validations by name")
	flag.StringVar(&filterNameRegex, "n", "", "Alias for --name")

	var filterTags repeatedStringFlag
	flag.Var(&filterTags, "tag", "Filter validations by tag (can be specified multiple times)")
	flag.Var(&filterTags, "t", "Alias for --tag")

	flag.Parse()

	if showVersion {
		fmt.Printf("validator %s (commit %s, built %s)\n", Version, GitCommit, BuildDate)
		os.Exit(0)
	}

	// Resolve color mode (and enable Windows VT if necessary)
	switch strings.ToLower(strings.TrimSpace(colorMode)) {
	case "always":
		useColor = true
	case "never":
		useColor = false
	default: // auto
		useColor = stdoutIsTTY()
	}
	if useColor {
		// Provided by ansi_windows.go (real) or ansi_unix.go (no-op)
		enableWindowsANSI()
	}

	// Resolve output mode
	compactMode = strings.ToLower(strings.TrimSpace(outputMode)) == "compact"

	if manifest == "" && flag.NArg() > 0 {
		manifest = flag.Arg(0)
	}
	if manifest == "" {
		fmt.Fprintln(os.Stderr, "Usage: validator --manifest <path> [--log-level DEBUG] [--show-output] [--dump-script] [--version] [--strict] [--color auto|always|never] [--output detailed|compact]")
		os.Exit(2)
	}
	setLevel(levelArg)
	activateVenv()

	// Automatically disable ANSI vars when in DEBUG mode
	if strings.ToUpper(levelArg) == "DEBUG" {
		enableAnsiVars = false
		logAt(DEBUG, "Disabling built-in ANSI color variables because log level is DEBUG")
	}

	// Compile name regex if provided
	var nameRe *regexp.Regexp
	if filterNameRegex != "" {
		var err error
		nameRe, err = regexp.Compile(filterNameRegex)
		if err != nil {
			logAt(ERROR, "Invalid name regex: %v", err)
			maybeWriteLogFile(logFileFormat, nil)
			os.Exit(2)
		}
	}

	globalExtraVars := make(map[string]any)
	for _, kv := range extraVarFlags {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			logAt(WARN, "Ignoring malformed extra-var: %q (expected key=value)", kv)
			continue
		}
		key := parts[0]
		valStr := parts[1]
		var valAny any
		if err := json.Unmarshal([]byte(valStr), &valAny); err == nil {
			globalExtraVars[key] = valAny
		} else {
			globalExtraVars[key] = valStr
		}
	}

	ctx := &runContext{
		NameRe:          nameRe,
		FilterTags:      filterTags,
		GlobalExtraVars: globalExtraVars,
		ShowFilter:      showFilter,
	}

	if listValidations {
		listManifestValidations(manifest, nil, 0)
		maybeWriteLogFile(logFileFormat, nil)
		os.Exit(0)
	}

	overallRC := executeManifest(manifest, nil, 0, ctx)

	if dumpScript || showFilter != "" {
		maybeWriteLogFile(logFileFormat, ctx.Results)
		os.Exit(0)
	}

	if !noSummary && len(ctx.Results) > 0 {
		fmt.Printf("\n%s\n", colorize("--- Validation Summary ---", boldCyan))
		statusColor := map[string]string{
			"PASS": green,
			"FAIL": red,
			"WARN": yellow,
			"SKIP": blue,
		}
		statusIcon := map[string]string{
			"PASS": "✅",
			"FAIL": "❌",
			"WARN": "⚠️",
			"SKIP": "⏭️",
		}

		grouped := make(map[string][]summaryResult)
		var manifestOrder []string
		for _, res := range ctx.Results {
			if _, ok := grouped[res.Manifest]; !ok {
				grouped[res.Manifest] = []summaryResult{}
				manifestOrder = append(manifestOrder, res.Manifest)
			}
			grouped[res.Manifest] = append(grouped[res.Manifest], res)
		}

		totalPass, totalFail, totalWarn, totalSkip := 0, 0, 0, 0

		maxPrefix := 0
		for _, res := range ctx.Results {
			plain := fmt.Sprintf("%s Validation #%-4s [%s] %s", statusIcon[res.Status], res.ExecDisplay, res.ValidationID, res.Name)
			if w := displayWidth(plain); w > maxPrefix {
				maxPrefix = w
			}
		}

		for _, m := range manifestOrder {
			results := grouped[m]
			p, f, w, s := 0, 0, 0, 0
			fmt.Printf("\n%s %s\n", colorize("Manifest:", boldWhite), colorize(m, cyan))
			for _, res := range results {
				switch res.Status {
				case "PASS":
					p++
					totalPass++
				case "FAIL":
					f++
					totalFail++
				case "WARN":
					w++
					totalWarn++
				case "SKIP":
					s++
					totalSkip++
				}
				plain := fmt.Sprintf("%s Validation #%-4s [%s] %s", statusIcon[res.Status], res.ExecDisplay, res.ValidationID, res.Name)
				prefix := fmt.Sprintf("%s Validation #%-4s [%s] %s", statusIcon[res.Status], res.ExecDisplay, res.ValidationID, linkify(res.Name))
				pad := maxPrefix - displayWidth(plain)
				if pad < 0 {
					pad = 0
				}
				fmt.Printf("%s %s[%s]\n", prefix, strings.Repeat(" ", pad), colorize(res.Status, statusColor[res.Status]))
				if len(res.Notes) > 0 {
					fmt.Println(colorize("   Notes:", dim))
					for _, note := range res.Notes {
						fmt.Printf("%s %s\n", colorize("   -", dim), linkify(note))
					}
				}
			}
			fmt.Printf("  %s: %d (Pass: %s, Fail: %s, Warn: %s, Skip: %s)\n",
				colorize("Subtotal", dim),
				len(results),
				colorize(fmt.Sprintf("%d", p), green),
				colorize(fmt.Sprintf("%d", f), red),
				colorize(fmt.Sprintf("%d", w), yellow),
				colorize(fmt.Sprintf("%d", s), blue))
		}
		fmt.Printf("\n%s: %d (Pass: %s, Fail: %s, Warn: %s, Skip: %s)\n",
			colorize("Total", boldWhite),
			len(ctx.Results),
			colorize(fmt.Sprintf("%d", totalPass), green),
			colorize(fmt.Sprintf("%d", totalFail), red),
			colorize(fmt.Sprintf("%d", totalWarn), yellow),
			colorize(fmt.Sprintf("%d", totalSkip), blue))
	}

	if overallRC == 0 {
		logAt(INFO, "%s", colorize("All validations PASSED ✅", green))
	} else {
		logAt(ERROR, "%s", colorize("One or more validations FAILED ❌", red))
	}
	maybeWriteLogFile(logFileFormat, ctx.Results)
	os.Exit(overallRC)
}
