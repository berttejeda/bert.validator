package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

/* =========================
   Version (override via -ldflags)
   ========================= */

// Build with:
// go build -ldflags "-X main.Version=v1.2.3 -X main.GitCommit=$(git rev-parse --short HEAD) -X main.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
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
	manifest         string
	levelArg         string
	defaultUnixShell = "/usr/bin/bash"
	defaultWinShell  = "powershell.exe"

	nameRegex  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	varPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	// Integers or floats (with optional leading dot / scientific notation)
	numPattern = regexp.MustCompile(`^\s*-?(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+\-]?\d+)?\s*$`)

	// duplicate key tracking (incremented whenever we detect duplicates)
	dupKeyCount int
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

/* =========================
   Interpreter detection
   ========================= */

type interpreterKind int

const (
	interpOther interpreterKind = iota
	interpShell      // bash/sh/zsh/dash/ksh
	interpPowerShell // powershell.exe / pwsh
	interpCmd        // cmd.exe
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

// warnDuplicateKeys logs WARN for any duplicate keys in a mapping node,
// increments a global dup counter, and leaves first occurrence as the winner.
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
			b.WriteByte('=')
			b.WriteString(bashFormatValue(p.Value))
		case interpPowerShell:
			b.WriteString(`$env:`)
			b.WriteString(p.Key)
			b.WriteString("=")
			b.WriteString(psQuote(p.Value))
		case interpCmd:
			b.WriteString(`set "`)
			b.WriteString(p.Key)
			b.WriteString("=")
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
   Process exec
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
	flag.Parse()

	if showVersion {
		fmt.Printf("validator %s (commit %s, built %s)\n", Version, GitCommit, BuildDate)
		os.Exit(0)
	}

	if manifest == "" && flag.NArg() > 0 {
		manifest = flag.Arg(0)
	}
	if manifest == "" {
		fmt.Fprintln(os.Stderr, "Usage: validator --manifest <path> [--log-level DEBUG] [--show-output] [--dump-script] [--version] [--strict]")
		os.Exit(2)
	}
	setLevel(levelArg)

	data, err := os.ReadFile(manifest)
	if err != nil {
		logAt(ERROR, "Failed to read manifest: %v", err)
		os.Exit(2)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		logAt(ERROR, "Failed to parse YAML: %v", err)
		os.Exit(2)
	}

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

		// Flags: per-validation > defaults > (internal PS defaults in runWithInterpreter)
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
		mergedList, mergedMap := mergeVars(globalOrdered, v.LocalVarsOrdered)
		logAt(DEBUG, "[%s] Merged vars: %v", v.Name, mergedMap)

		finalScript := v.Script
		header := ""

		// Only prepend headers when not env-only
		if !envOnly {
			switch kind {
			case interpShell, interpPowerShell, interpCmd:
				header = buildHeader(kind, mergedList)
				if header != "" {
					finalScript = header + "\n" + finalScript
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

		res, err := runWithInterpreter(interpPath, flags, finalScript, extraEnv, kind)
		if err != nil {
			logAt(ERROR, "[%s] Execution error: %v", v.Name, err)
			overallRC = 1
			fmt.Println()
			continue
		}

		// Effective show_output: per-validation > defaults > CLI flag
		effectiveShowOutput := showOutputFlag
		if defs.ShowOutputSet {
			effectiveShowOutput = defs.ShowOutput
		}
		if v.ShowOutputSet {
			effectiveShowOutput = v.ShowOutput
		}

		// Print child output when enabled — at INFO, regardless of global log level gate
		if effectiveShowOutput {
			if out := strings.TrimSpace(res.Stdout); out != "" {
				logAt(INFO, "[%s] STDOUT:\n%s", v.Name, out)
			}
			if errOut := strings.TrimSpace(res.Stderr); errOut != "" {
				logAt(INFO, "[%s] STDERR:\n%s", v.Name, errOut)
			}
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
