package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	sprig "github.com/Masterminds/sprig/v3"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"text/template"
	"time"
)

/* =========================
   Version (override via -ldflags)
   ========================= */

var (
	Version   = "0.1.0"
	GitCommit = "dev"
	BuildDate = "unknown"
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

var (
	level            = INFO
	showOutputFlag   bool
	dumpScript       bool
	showVersion      bool
	strictMode       bool
	colorMode        string // auto|always|never
	useColor         bool   // resolved runtime decision
	enableAnsiVars   bool
	manifest         string
	levelArg         string
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

	// Guard against ANSI bleed:
	// - If colors are enabled, reset BEFORE prefix,
	//   print the message, then reset AFTER.
	if useColor {
		const reset = "\x1b[0m"
		msg := fmt.Sprintf(format, a...)
		// Prepend reset (protect prefix) and append reset (protect next line).
		fmt.Fprint(os.Stdout, reset)
		fmt.Fprint(os.Stdout, prefix)
		fmt.Fprint(os.Stdout, msg)
		fmt.Fprint(os.Stdout, reset)
		fmt.Fprint(os.Stdout, "\n")
		return
	}

	// No color: normal print
	fmt.Fprintf(os.Stdout, prefix+format+"\n", a...)
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

// logMultiline prints each line with a level prefix (kept for any buffered printing paths).
func logMultiline(l logLevel, text string) {
	if l < level || text == "" {
		return
	}
	lines := strings.Split(text, "\n")
	for _, ln := range lines {
		logAt(l, "%s", ln)
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
	tplNode := getMapValue(top, "templates")
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

// Build the context for Go templating (single flat namespace), plus a nested .Env map.
// Precedence: locals > globals > templates > env (flattened). .Env always has all env vars.
func buildTemplateContext(mergedVars map[string]string, templates map[string]string, env map[string]string) map[string]any {
	ctx := make(map[string]any, len(env)+len(templates)+len(mergedVars)+1)

	// Lowest precedence first, so later assignments override.
	for k, v := range env {
		ctx[k] = v
	}
	for k, v := range templates {
		ctx[k] = v
	}
	for k, v := range mergedVars {
		ctx[k] = v
	}

	// Always provide a dedicated Env map
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

type validation struct {
	Name             string
	Script           string
	PassMessage      string
	FailMessage      string
	InterpreterPath  string
	InterpreterFlags []string
	LocalVarsOrdered []kv
	LocalVarsMap     map[string]string
	EnvOnly          bool
	EnvOnlySet       bool // explicitly set in manifest
	ShowOutput       bool // per-validation override of --show-output
	ShowOutputSet    bool
}

func parseManifestTemplateSection(r io.Reader) (map[string]string, error) {
	var doc yaml.Node
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true) // catch unknown struct fields if you later add typed nodes

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
		key := root.Content[i]
		val := root.Content[i+1]
		if key.Kind == yaml.ScalarNode && key.Value == "templates" {
			templatesNode = val
			break
		}
	}

	if templatesNode == nil {
		// No templates key found; return empty map (or you could return an error if you prefer).
		return map[string]string{}, nil
	}
	if templatesNode.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("invalid yaml: templates is not a mapping")
	}

	// Unmarshal the templates node directly into a string map.
	out := make(map[string]string)
	if err := templatesNode.Decode(&out); err != nil {
		return nil, fmt.Errorf("decode templates: %w", err)
	}

	return out, nil
}

func loadManifest(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	return parseManifestTemplateSection(f)
}

func parseManifest(root *yaml.Node) (globals []kv, defs manifestDefaults, vals []validation, err error) {
	dupKeyCount = 0 // reset for each parse

	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, manifestDefaults{}, nil, errors.New("invalid YAML document")
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, manifestDefaults{}, nil, errors.New("top-level YAML must be a mapping")
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

	// top-level vars
	if gv := getMapValue(top, "vars"); gv != nil {
		gl, err2 := orderedVars(gv, "top-level")
		if err2 != nil {
			return nil, manifestDefaults{}, nil, fmt.Errorf("top-level vars: %w", err2)
		}
		globals = gl
	}

	// validations
	vNode := getMapValue(top, "validations")
	if vNode == nil || vNode.Kind != yaml.SequenceNode {
		return nil, manifestDefaults{}, nil, errors.New("`validations` must be a sequence")
	}

	for _, item := range vNode.Content {
		if item.Kind != yaml.MappingNode {
			return nil, manifestDefaults{}, nil, errors.New("each validation must be a mapping")
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
			return nil, manifestDefaults{}, nil, errors.New("validation missing a name")
		}

		if body == nil || body.Kind != yaml.MappingNode {
			return nil, manifestDefaults{}, nil, fmt.Errorf("validation %q body must be a mapping", name)
		}

		warnDuplicateKeys(body, fmt.Sprintf("validation %q", name))

		script := toString(getMapValue(body, "script"))

		var passMsg, failMsg string
		if outcomes := getMapValue(body, "outcomes"); outcomes != nil && outcomes.Kind == yaml.MappingNode {
			warnDuplicateKeys(outcomes, fmt.Sprintf("validation %q outcomes", name))
			if pass := getMapValue(outcomes, "pass"); pass != nil {
				passMsg = toString(getMapValue(pass, "message"))
			}
			if fail := getMapValue(outcomes, "fail"); fail != nil {
				failMsg = toString(getMapValue(fail, "message"))
			}
		}
		if passMsg == "" {
			passMsg = "PASS"
		}
		if failMsg == "" {
			failMsg = "FAIL"
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

		var localOrdered []kv
		if lv := getMapValue(body, "vars"); lv != nil {
			lo, err2 := orderedVars(lv, fmt.Sprintf("validation %q", name))
			if err2 != nil {
				return nil, manifestDefaults{}, nil, fmt.Errorf("validation %q vars: %w", name, err2)
			}
			localOrdered = lo
		}
		localMap := map[string]string{}
		for _, p := range localOrdered {
			localMap[p.Key] = p.Value
		}

		vals = append(vals, validation{
			Name:             name,
			Script:           script,
			PassMessage:      passMsg,
			FailMessage:      failMsg,
			InterpreterPath:  interp,
			InterpreterFlags: flags,
			LocalVarsOrdered: localOrdered,
			LocalVarsMap:     localMap,
			EnvOnly:          envOnly,
			EnvOnlySet:       envOnlySet,
			ShowOutput:       showOutputVal,
			ShowOutputSet:    showOutputSet,
		})
	}

	// If strict mode is on and we saw duplicates, fail parsing.
	if strictMode && dupKeyCount > 0 {
		return nil, manifestDefaults{}, nil, fmt.Errorf("manifest contains %d duplicate key(s); re-run without --strict to see WARN logs", dupKeyCount)
	}

	return globals, defs, vals, nil
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
		const reset = "\x1b[0m"
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

func main() {
	flag.StringVar(&manifest, "manifest", "", "Path to YAML manifest")
	flag.StringVar(&levelArg, "log-level", "INFO", "Log level: DEBUG, INFO, WARN, ERROR")
	flag.BoolVar(&showOutputFlag, "show-output", false, "Show child STDOUT/STDERR (overridden by per-validation show_output and defaults.show_output)")
	flag.BoolVar(&dumpScript, "dump-script", false, "Dump final assembled scripts at DEBUG")
	flag.BoolVar(&showVersion, "version", false, "Print version information and exit")
	flag.BoolVar(&strictMode, "strict", false, "Fail with non-zero exit if duplicate keys are found in the manifest")
	flag.BoolVar(&enableAnsiVars, "ansi-vars", true, "Expose built-in ANSI color variables to scripts (can be overridden by manifest)")
	flag.StringVar(&colorMode, "color", "auto", "Color output: auto|always|never (affects child output pass-through)")
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

	if manifest == "" && flag.NArg() > 0 {
		manifest = flag.Arg(0)
	}
	if manifest == "" {
		fmt.Fprintln(os.Stderr, "Usage: validator --manifest <path> [--log-level DEBUG] [--show-output] [--dump-script] [--version] [--strict] [--color auto|always|never]")
		os.Exit(2)
	}
	setLevel(levelArg)

	// Automatically disable ANSI vars when in DEBUG mode
	if strings.ToUpper(levelArg) == "DEBUG" {
		enableAnsiVars = false
		logAt(DEBUG, "Disabling built-in ANSI color variables because log level is DEBUG")
	}

	_, err := os.ReadFile(manifest)
	if err != nil {
		logAt(ERROR, "Failed to read manifest: %v", err)
		os.Exit(2)
	}
	yamlTemplateData, _ := loadManifest(manifest)
	emptyMap := make(map[string]string)
	env := envMap()
	initialTmplCtx := buildTemplateContext(emptyMap, env, yamlTemplateData)
	tmpl, err := template.New(manifest).Funcs(sprig.FuncMap()).ParseFiles(manifest)
	if err != nil {
		fmt.Printf("Error parsing template: %v\n", err)
		return
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, initialTmplCtx)
	if err != nil {
		fmt.Printf("Error executing template: %v\n", err)
		return
	}

	var yamlData = buf.String()

	var root yaml.Node
	if err := yaml.Unmarshal([]byte(yamlData), &root); err != nil {
		logAt(ERROR, "Failed to parse YAML: %v", err)
		os.Exit(2)
	}

	tplMap := extractTemplates(&root) // add here

	globalOrdered, defs, validations, err := parseManifest(&root)
	if err != nil {
		logAt(ERROR, "Invalid manifest: %v", err)
		os.Exit(2)
	}

	autoInterp, autoKind := autoDetectDefaultInterpreter()
	logAt(INFO, "Using auto-detected default interpreter: %s", autoInterp)

	logAt(INFO, "Found %d validation(s) to run.", len(validations))
	fmt.Println()

	overallRC := 0

	for _, v := range validations {
		logAt(INFO, "▶ Running validation: %s", v.Name)

		if strings.TrimSpace(v.Script) == "" {
			logAt(WARN, "⚠ Skipped '%s': empty script.", v.Name)
			if overallRC == 0 {
				overallRC = 1
			}
			fmt.Println()
			continue
		}

		// Interpreter path: per-validation > defaults > auto-detect
		interpPath := strings.TrimSpace(v.InterpreterPath)
		var kind interpreterKind
		if interpPath == "" {
			if strings.TrimSpace(defs.InterpreterPath) != "" {
				interpPath = strings.TrimSpace(defs.InterpreterPath)
				kind = detectInterpreterKind(interpPath)
			} else {
				interpPath = autoInterp
				kind = autoKind
			}
		} else {
			kind = detectInterpreterKind(interpPath)
		}

		// Flags: per-validation > defaults
		flags := v.InterpreterFlags
		if len(flags) == 0 && len(defs.InterpreterFlags) > 0 {
			flags = append([]string(nil), defs.InterpreterFlags...)
		}

		// env_only: if not explicitly set in validation, inherit defaults
		envOnly := v.EnvOnly
		if !v.EnvOnlySet {
			envOnly = defs.EnvOnly
		}

		// Merge vars
		base := []kv{}
		if enableAnsiVars {
			base = builtinAnsiVars()
		}

		// built-ins, then globals, then locals (later entries override earlier ones)
		mergedBG, _ := mergeVars(base, globalOrdered)
		mergedList, mergedMap := mergeVars(mergedBG, v.LocalVarsOrdered)

		logAt(DEBUG, "[%s] Merged vars: %v", v.Name, mergedMap)

		// Build templating context: Env + templates + mergedVars (locals override globals)
		tmplCtx := buildTemplateContext(mergedMap, tplMap, env)

		// Go-template the script and outcome messages (Sprig-enabled)
		scriptTemplated, err := renderTemplate(v.Name+"_script", v.Script, tmplCtx)
		if err != nil {
			logAt(ERROR, "[%s] Template error in script: %v", v.Name, err)
			overallRC = 1
			fmt.Println()
			continue
		}
		v.Script = scriptTemplated

		if v.PassMessage != "" {
			if passMsgT, err := renderTemplate(v.Name+"_pass", v.PassMessage, tmplCtx); err == nil {
				v.PassMessage = passMsgT
			} else {
				logAt(ERROR, "[%s] Template error in pass message: %v", v.Name, err)
				overallRC = 1
				fmt.Println()
				continue
			}
		}
		if v.FailMessage != "" {
			if failMsgT, err := renderTemplate(v.Name+"_fail", v.FailMessage, tmplCtx); err == nil {
				v.FailMessage = failMsgT
			} else {
				logAt(ERROR, "[%s] Template error in fail message: %v", v.Name, err)
				overallRC = 1
				fmt.Println()
				continue
			}
		}

		finalScript := v.Script
		// Only prepend headers when not env-only
		if !envOnly {
			switch kind {
			case interpShell, interpPowerShell, interpCmd:
				if hdr := buildHeader(kind, mergedList); hdr != "" {
					finalScript = hdr + "\n" + finalScript
				}
			default:
				// other interpreters -> no header
			}
		}

		extraEnv := map[string]string{}
		// Ensure vars reach the script via environment in env-only mode or for non-shell interpreters
		if envOnly || kind == interpOther {
			for k, val := range mergedMap {
				extraEnv[k] = val
			}
		}

		if dumpScript || level == DEBUG {
			logAt(DEBUG, "\n--- [%s] FINAL SCRIPT ---\n%s\n--- end ---", v.Name, finalScript)
		}

		// Effective show_output: per-validation > defaults > CLI flag
		effectiveShowOutput := showOutputFlag
		if defs.ShowOutputSet {
			effectiveShowOutput = defs.ShowOutput
		}
		if v.ShowOutputSet {
			effectiveShowOutput = v.ShowOutput
		}

		var res *runResult
		if effectiveShowOutput {
			// Stream live; strip ANSI codes if color disabled
			res, err = runWithInterpreterLive(
				interpPath, flags, finalScript, extraEnv, kind,
				v.Name,
				!useColor,
			)
		} else {
			// NON-STREAMING: show a progress indicator when log level is not DEBUG
			var stopProgress func()
			if level != DEBUG {
				stopProgress = startProgress(v.Name)
			} else {
				// If DEBUG, don't show spinner; show a plain "Running..." / "Finished" pair for parity.
				stopProgress = startProgress(v.Name)
			}

			res, err = runWithInterpreter(interpPath, flags, finalScript, extraEnv, kind)

			// Stop spinner / finish logs
			if stopProgress != nil {
				stopProgress()
			}
		}

		if err != nil {
			logAt(ERROR, "[%s] Execution error: %v", v.Name, err)
			overallRC = 1
			fmt.Println()
			continue
		}

		passMsg := renderMsg(v.PassMessage, mergedMap)
		failMsg := renderMsg(v.FailMessage, mergedMap)

		if res.ExitCode == 0 {
			logAt(INFO, "✅ Validation '%s' PASSED: %s", v.Name, passMsg)
		} else {
			logAt(ERROR, "❌ Validation '%s' FAILED: %s", v.Name, failMsg)
			overallRC = 1
		}

		fmt.Println()
	}

	if overallRC == 0 {
		logAt(INFO, "All validations PASSED ✅")
	} else {
		logAt(ERROR, "One or more validations FAILED ❌")
	}
	os.Exit(overallRC)
}
