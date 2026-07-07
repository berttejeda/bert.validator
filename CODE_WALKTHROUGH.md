# bert.validator Code Walkthrough

This document provides a high-level overview of the `bert.validator` codebase.

## Overview

`bert.validator` is a Go-based command-line tool designed to execute validation scripts defined in a YAML manifest. It supports outcome-based result determination, Go `text/template` + Sprig templating, reusable functions scoped by interpreter, conditional execution via [expr-lang/expr](https://github.com/expr-lang/expr), recursive manifest includes, and tag/name-based filtering.

## Project Structure

```
bert.validator/
├── main.go               # CLI entry point, manifest parsing, templating, script execution
├── runner_includes.go    # Recursive manifest execution, condition evaluation, summary tracking
├── console_posix.go      # No-op ANSI stub for Unix/macOS
├── console_windows.go    # Windows Virtual Terminal Processing enablement
├── go.mod / go.sum       # Module definition and dependency lock
├── manifest.yaml         # Example manifest
└── other-manifest.yaml   # Example included manifest
```

## Key Components

### `main.go`

Contains the CLI entry point (`main()`), all manifest/YAML parsing logic, interpreter detection, variable quoting, template rendering helpers, and the buffered/live-stream process execution runners.

#### Data Structures

*   **`kv`** — Ordered key-value pair used to preserve variable declaration order during shell header generation.
*   **`manifestData`** — Holds the raw manifest content string and the pre-extracted `templateVars` map.
*   **`manifestDefaults`** — Global defaults from the `defaults:` block:
    *   `InterpreterPath` / `InterpreterFlags` — Default shell and flags.
    *   `EnvOnly` — If `true`, pass variables via environment instead of inline shell assignments.
    *   `ShowOutput` / `ShowOutputSet` — Default output streaming behavior.
*   **`functionDef`** — A single reusable function (`name` + `source`).
*   **`functionsMap`** — `map[string][]functionDef` keyed by interpreter base name (e.g., `bash`, `zsh`, `powershell`).
*   **`includeBlock`** — Represents one `includes` entry: `Name`, `Path`, `Vars` (map), `PropagateTags` (bool).
*   **`outcome`** — A result outcome with `Message` (string) and `ExitCodes` ([]int).
*   **`condition`** — A single condition with an `Eval` expression string.
*   **`validation`** — A complete validation unit:
    *   `ExecNumber` / `ValidationID` — Sequence number and deterministic FNV-32a hash ID.
    *   `Name`, `Tags`, `Conditions` — Identity and filtering metadata.
    *   `Script` — The shell script body.
    *   `Pass` / `Fail` / `Warn` — Outcome definitions.
    *   `InterpreterPath` / `InterpreterFlags` — Per-validation interpreter override.
    *   `LocalVarsOrdered` / `LocalVarsMap` — Scoped variables.
    *   `EnvOnly` / `EnvOnlySet`, `ShowOutput` / `ShowOutputSet` — Per-validation overrides.
    *   `Includes` — Nested manifest includes.
*   **`runResult`** — Captured process output: `Stdout`, `Stderr`, `ExitCode`, `Duration`.

#### Core Functions

1.  **`main()`**
    *   Parses CLI flags (`--manifest`, `--log-level`, `-e`, `-n`, `-t`, `--list`, `--show`, `--dump-script`, `--strict`, `--no-summary`, `--color`, `--ansi-vars`, `--version`).
    *   Resolves color mode and enables Windows VT if needed.
    *   Parses `--extra-var` values (supports JSON object strings).
    *   Builds a `runContext` and delegates to `listManifestValidations()` or `executeManifest()`.
    *   Prints the validation summary table and exits with `0` (all pass) or `1` (any failure).

2.  **`loadManifest(path string) (*manifestData, error)`**
    *   Reads the manifest from local filesystem, HTTP/HTTPS URL, or stdin (`-`).
    *   Performs a first-pass YAML decode to extract the `templateVars` block into a `map[string]any`.

3.  **`parseManifest(root *yaml.Node) ([]kv, manifestDefaults, functionsMap, []validation, error)`**
    *   Extracts top-level keys: `defaults`, `functions`, `vars`, `validations`.
    *   Warns on duplicate keys (fails in `--strict` mode).
    *   Parses each validation item into the `validation` struct, including outcomes, conditions, includes, and per-validation interpreter/var overrides.

4.  **`autoDetectDefaultInterpreter() (string, interpreterKind)`**
    *   Platform-aware shell detection: tries Homebrew bash, system bash, zsh, sh on macOS; bash/zsh/sh on Linux; pwsh/powershell/cmd on Windows.

5.  **`buildTemplateContext(mergedVars, templates, env) map[string]any`**
    *   Flattens environment, templateVars, and shell vars into a single namespace for Go template rendering. Also exposes `.Env` for explicit environment access.

6.  **`renderTemplate(name, text string, ctx any) (string, error)`**
    *   Renders a Go `text/template` string with Sprig functions. Uses `missingkey=default` to avoid hard errors on undefined keys.

7.  **`buildHeader(kind interpreterKind, pairs []kv) string`**
    *   Generates variable assignment preamble for the target shell:
        *   Shell (bash/zsh/sh): `KEY="value"` with proper escaping; numeric literals unquoted.
        *   PowerShell: `$env:KEY="value"` with backtick escaping.
        *   cmd.exe: `set "KEY=value"` with `%` doubling.

8.  **`runWithInterpreter(...)` / `runWithInterpreterLive(...)`**
    *   **Buffered**: Writes the final script to a temp file, executes it, captures stdout/stderr/exit code.
    *   **Live-stream**: Same temp-file approach but pipes stdout/stderr line-by-line to the console in real time with lazy header printing.

9.  **`startProgress(name string) func()`**
    *   Returns a stop callback. On TTYs, displays an animated spinner with elapsed time. On non-TTYs or in DEBUG mode, prints simple start/finish lines.

### `runner_includes.go`

Contains the recursive execution engine and supporting logic that orchestrates validation runs across manifest trees.

#### Data Structures

*   **`summaryResult`** — Tracks per-validation outcome: `ExecDisplay`, `ValidationID`, `Name`, `Status` (PASS/FAIL/WARN/SKIP).
*   **`runContext`** — Shared execution context threaded through recursive calls:
    *   `NameRe` — Compiled regex for `--name` filtering.
    *   `FilterTags` — Active tag filters from `--tag`.
    *   `GlobalExtraVars` — Variables from `--extra-var`.
    *   `ExecPrefix` — Hierarchical numbering prefix (e.g., `1.`, `1.2.`).
    *   `ShowFilter` — Active `--show` filter string.
    *   `Results` — Accumulated summary results (mutex-protected).

#### Core Functions

1.  **`executeManifest(manifestPath string, includeVars map[string]any, depth int, ctx *runContext) int`**
    *   The main recursive execution loop. For each manifest:
        1. Loads and templates the manifest.
        2. Parses into structs.
        3. Iterates validations, applying name/tag/condition filters.
        4. Prepends function bodies matching the active interpreter.
        5. Builds the variable header and renders script templates.
        6. Executes (buffered or live) and evaluates outcomes against exit codes.
        7. Recursively processes `includes` with child `runContext` (respecting `propagate_tags`).
    *   Returns `0` if all validations pass, `1` if any fail.

2.  **`evaluateConditions(conditions []condition, ctx *runContext) (bool, error)`**
    *   Evaluates all conditions using `expr-lang/expr`. Provides built-in environment:
        *   `no_tags()` — Returns `true` if no `--tag` flags were provided.
        *   `env(name)` — Returns the value of an environment variable.
        *   `file_exists(path)` — Returns `true` if a file/directory exists.
        *   `GOOS` / `GOARCH` — Runtime OS and architecture strings.
    *   All conditions must be `true` (AND logic) for the validation to proceed.

3.  **`listManifestValidations(manifestPath string, includeVars map[string]any, depth int)`**
    *   Recursively lists all validations (with IDs, tags, condition counts) without executing them. Used by `--list`.

4.  **`matchesShowFilter(filter, validationID, name string) bool`**
    *   Matches a `--show` filter against validation ID or name (case-insensitive substring or regex).

### `console_posix.go` / `console_windows.go`

Platform-specific terminal initialization via build tags.
*   **`console_posix.go`** (`//go:build !windows`): No-op `enableWindowsANSI()` for Unix/macOS where ANSI codes work natively.
*   **`console_windows.go`** (`//go:build windows`): Enables `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on stdout and stderr handles via `golang.org/x/sys/windows` for proper ANSI color rendering on Windows consoles.

## Execution Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. CLI Parsing                                              │
│    Parse flags, resolve color mode, compile name regex,     │
│    parse --extra-var values (with JSON support)             │
├─────────────────────────────────────────────────────────────┤
│ 2. Manifest Loading (loadManifest)                          │
│    Read source (file/URL/stdin) → first-pass YAML decode    │
│    to extract templateVars                                  │
├─────────────────────────────────────────────────────────────┤
│ 3. Template Rendering                                       │
│    Merge templateVars + extraVars + env → execute           │
│    text/template + Sprig on the raw YAML content            │
├─────────────────────────────────────────────────────────────┤
│ 4. Second-pass Parsing (parseManifest)                      │
│    Unmarshal rendered YAML → extract defaults, functions,   │
│    global vars, and validations into Go structs             │
├─────────────────────────────────────────────────────────────┤
│ 5. Validation Loop (executeManifest)                        │
│    For each validation:                                     │
│    a. Apply name regex filter                               │
│    b. Apply tag filter                                      │
│    c. Evaluate conditions (skip if any false)               │
│    d. Prepend matching function bodies by interpreter       │
│    e. Build variable header (MANIFEST_DIR + ANSI + vars)    │
│    f. Render script body through templates                  │
│    g. Execute via temp file (buffered or live-stream)       │
│    h. Determine outcome (WARN → PASS → FAIL → default)     │
│    i. Process includes recursively                          │
├─────────────────────────────────────────────────────────────┤
│ 6. Summary & Exit                                           │
│    Print summary table (unless --no-summary)                │
│    Exit 0 if all pass, 1 if any fail                        │
└─────────────────────────────────────────────────────────────┘
```

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/Masterminds/sprig/v3` | Extended template functions (over 100 utility functions) |
| `github.com/expr-lang/expr` | Boolean expression evaluation for conditions |
| `gopkg.in/yaml.v3` | YAML parsing with node-level access for order preservation |
| `golang.org/x/sys` | Windows console API for ANSI support |
| `dario.cat/mergo` | Indirect dependency (via Sprig) |

## Variable Precedence

When building the template context, values are layered lowest-to-highest precedence:

1. **OS environment** (lowest)
2. **`templateVars`** from manifest
3. **`--extra-var` overrides**
4. **Merged shell vars** (`vars:` global + per-validation) (highest)

The `.Env` key always provides access to the raw OS environment regardless of overrides.

## Validation ID Generation

Each validation receives a deterministic ID computed as an 8-character hex string from FNV-32a hash of `"{exec_number}:{name}"`. This ID is stable across runs as long as the validation's position and name don't change.
