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
   Logging
   ========================= */

type logLevel int

const (
	DEBUG logLevel = iota
	INFO
	WARN
	ERROR
)

// Version info (override at build time with -ldflags "-X main.Version=... -X main.GitCommit=... -X main.BuildDate=...")
var (
	Version   = "0.1.0"
	GitCommit = "dev"
	BuildDate = "Mon Oct 20 16:02:54 2025"
)


var (
	level      = INFO
	showOutput bool
	dumpScript bool
	showVersion bool
	manifest   string
	levelArg   string

	// These are *fallbacks* if detection fails entirely.
	defaultUnixShell = "/usr/bin/bash"
	defaultWinShell  = "powershell.exe"

	nameRegex  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	varPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	// Integers or floats (with optional leading dot / scientific notation)
	numPattern = regexp.MustCompile(`^\s*-?(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+\-]?\d+)?\s*$`)
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

// findExecutable tries exec.LookPath first; if the candidate looks like an absolute
// path, ensure it exists. Returns the first found executable, else empty string.
func findExecutable(candidates []string) string {
	for _, cand := range candidates {
		// Absolute or explicit path?
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

// autoDetectDefaultInterpreter picks a sensible default based on OS,
// searching PATH and common locations for popular interpreters.
// Returns (path, kind). If nothing is found, returns a conservative fallback.
func autoDetectDefaultInterpreter() (string, interpreterKind) {
	switch runtime.GOOS {
	case "windows":
		// Prefer PowerShell Core (pwsh), then Windows PowerShell, then ComSpec/cmd
		winCandidates := []string{
			"pwsh.exe", "pwsh",
			"powershell.exe", "powershell",
		}
		// ComSpec might be something like C:\Windows\System32\cmd.exe
		if comspec := os.Getenv("ComSpec"); strings.TrimSpace(comspec) != "" {
			winCandidates = append(winCandidates, comspec)
		}
		winCandidates = append(winCandidates, "cmd.exe", "cmd")
		if p := findExecutable(winCandidates); p != "" {
			return p, detectInterpreterKind(p)
		}
		// Fallback
		return defaultWinShell, detectInterpreterKind(defaultWinShell)

	case "darwin":
		// Prefer Homebrew bash if present, then system bash, then zsh/sh, then python3/python
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

	default: // "linux" and others (treat as Unix-like)
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
   YAML helpers (preserve order)
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

func orderedVars(mapNode *yaml.Node) ([]kv, error) {
	out := []kv{}
	if mapNode == nil {
		return out, nil
	}
	if mapNode.Kind != yaml.MappingNode {
		return nil, errors.New("vars must be a mapping")
	}
	for i := 0; i < len(mapNode.Content); i += 2 {
		k := mapNode.Content[i]
		v := mapNode.Content[i+1]
		key := k.Value
		if !nameRegex.MatchString(key) {
			return nil, fmt.Errorf("invalid variable name for shell: %q", key)
		}
		out = append(out, kv{Key: key, Value: toString(v)})
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

// For bash header assignments, leave numeric literals (int/float) unquoted
// so arithmetic contexts like (( var > 0 )) don’t choke. Quote everything else.
func bashFormatValue(s string) string {
	if numPattern.MatchString(s) {
		return strings.TrimSpace(s)
	}
	// Otherwise, double-quote and escape for safe runtime expansion of ${...} / $(...)
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func psQuote(s string) string {
	// PowerShell double-quoted string; escape backtick and quote.
	s = strings.ReplaceAll(s, "`", "``")
	s = strings.ReplaceAll(s, `"`, "`\"")
	return `"` + s + `"`
}

func cmdQuoteValue(s string) string {
	// Use: set "KEY=value"
	// - double % to avoid immediate env expansion
	// - double " inside quotes
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
   Manifest model + parsing
   ========================= */

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
}

func parseManifest(root *yaml.Node) (globals []kv, vals []validation, err error) {
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, nil, errors.New("invalid YAML document")
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, nil, errors.New("top-level YAML must be a mapping")
	}

	// top-level vars
	if gv := getMapValue(top, "vars"); gv != nil {
		globals, err = orderedVars(gv)
		if err != nil {
			return nil, nil, fmt.Errorf("top-level vars: %w", err)
		}
	}

	// validations
	vNode := getMapValue(top, "validations")
	if vNode == nil || vNode.Kind != yaml.SequenceNode {
		return nil, nil, errors.New("`validations` must be a sequence")
	}

	for _, item := range vNode.Content {
		if item.Kind != yaml.MappingNode {
			return nil, nil, errors.New("each validation must be a mapping")
		}

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
			return nil, nil, errors.New("validation missing a name")
		}

		if body == nil || body.Kind != yaml.MappingNode {
			return nil, nil, fmt.Errorf("validation %q body must be a mapping", name)
		}

		script := toString(getMapValue(body, "script"))

		var passMsg, failMsg string
		if outcomes := getMapValue(body, "outcomes"); outcomes != nil && outcomes.Kind == yaml.MappingNode {
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
			if s := getMapValue(interps, "script"); s != nil && toString(s) != "" {
				interp = toString(s)
			}
			if f := getMapValue(interps, "flags"); f != nil && f.Kind == yaml.SequenceNode {
				for _, n := range f.Content {
					flags = append(flags, toString(n))
				}
			}
		}

		envOnly := false
		if eo := getMapValue(body, "env_only"); eo != nil {
			envOnly = strings.EqualFold(strings.TrimSpace(toString(eo)), "true")
		}

		var localOrdered []kv
		if lv := getMapValue(body, "vars"); lv != nil {
			localOrdered, err = orderedVars(lv)
			if err != nil {
				return nil, nil, fmt.Errorf("validation %q vars: %w", name, err)
			}
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
		})
	}
	return globals, vals, nil
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
	_ = f.Chmod(0o700) // best-effort
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

	// Build argument list
	var args []string
	switch kind {
	case interpPowerShell:
		// If no custom flags, use safe defaults
		if len(flags) == 0 {
			args = []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path}
		} else {
			args = append(flags, path)
		}
	case interpCmd:
		// cmd always needs /C <file>
		if len(flags) > 0 {
			args = append(flags, "/C", path) // user flags precede /C file
		} else {
			args = []string{"/C", path}
		}
	default:
		// shell/other: flags first, then script path (typical CLI behavior)
		if len(flags) > 0 {
			args = append(flags, path)
		} else {
			args = []string{path}
		}
	}

	cmd := exec.Command(interpreter, args...)

	// Environment
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
	flag.BoolVar(&showOutput, "show-output", false, "Show child stdout/stderr at DEBUG")
	flag.BoolVar(&dumpScript, "dump-script", false, "Dump final assembled scripts at DEBUG")
	flag.BoolVar(&showVersion, "version", false, "Print version information and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("validator %s (commit %s, built %s)\n", Version, GitCommit, BuildDate)
		os.Exit(0)
	}

	if manifest == "" && flag.NArg() > 0 {
		manifest = flag.Arg(0)
	}
	if manifest == "" {
		fmt.Fprintln(os.Stderr, "Usage: validator --manifest <path> [--log-level DEBUG] [--show-output] [--dump-script]")
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

	globalOrdered, validations, err := parseManifest(&root)
	if err != nil {
		logAt(ERROR, "Invalid manifest: %v", err)
		os.Exit(2)
	}

	// Compute OS-aware default interpreter once, for log visibility.
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

		// Choose interpreter: manifest override or auto-detected default
		interpPath := strings.TrimSpace(v.InterpreterPath)
		kind := interpOther
		if interpPath == "" {
			interpPath = autoInterp
			kind = autoKind
		} else {
			kind = detectInterpreterKind(interpPath)
		}

		// Merge vars & prepare script
		mergedList, mergedMap := mergeVars(globalOrdered, v.LocalVarsOrdered)
		logAt(DEBUG, "[%s] Merged vars: %v", v.Name, mergedMap)

		finalScript := v.Script
		header := ""

		// Only prepend headers when not env-only
		if !v.EnvOnly {
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
		if v.EnvOnly || kind == interpOther {
			for k, val := range mergedMap {
				extraEnv[k] = val
			}
		}

		if dumpScript || level == DEBUG {
			logAt(DEBUG, "\n--- [%s] FINAL SCRIPT ---\n%s\n--- end ---", v.Name, finalScript)
		}

		res, err := runWithInterpreter(interpPath, v.InterpreterFlags, finalScript, extraEnv, kind)
		if err != nil {
			logAt(ERROR, "[%s] Execution error: %v", v.Name, err)
			overallRC = 1
			fmt.Println()
			continue
		}

		if showOutput && level <= DEBUG {
			if strings.TrimSpace(res.Stdout) != "" {
				logAt(DEBUG, "[%s] STDOUT:\n%s", v.Name, strings.TrimSpace(res.Stdout))
			}
			if strings.TrimSpace(res.Stderr) != "" {
				logAt(DEBUG, "[%s] STDERR:\n%s", v.Name, strings.TrimSpace(res.Stderr))
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
