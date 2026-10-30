# bert.validator Code Walkthrough

This document provides a high-level overview of the `bert.validator` codebase.

## Overview

`bert.validator` is a Go-based command-line tool designed to execute validation scripts defined in a YAML manifest. It supports outcome-based result determination, Go `text/template` + Sprig templating, reusable functions scoped by interpreter, conditional execution via [expr-lang/expr](https://github.com/expr-lang/expr), recursive manifest includes, and tag/name-based filtering.

## Project Structure

```
bert.validator/
├── main.go               # CLI entry point, manifest parsing, templating, script execution, summary/log output
├── runner_includes.go    # Recursive manifest execution, condition evaluation, summary tracking
├── visualize.go          # --visualize: HTML mindmap (Markmap + Mermaid) of the summary
├── mop.go                # --export-as-mop: Markdown Method of Procedure
├── assets/markmap/       # Vendored, embedded browser assets (d3, markmap) for --visualize
├── console_posix.go      # No-op ANSI stub for Unix/macOS
├── console_windows.go    # Windows Virtual Terminal Processing enablement
├── go.mod / go.sum       # Module definition and dependency lock
├── manifest.yaml         # Example manifest
├── other-manifest.yaml   # Example included manifest
├── README.md             # User documentation
└── CHANGELOG.md          # Release history
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
*   **`manifestMeta`** — The optional top-level `title` and `description` (purely descriptive; never affects execution). Parsed by `parseManifestMeta()` from the *rendered* YAML, so both support templating. The root manifest's value is stored in the package-level `rootMeta` (set once, at depth 0, in `executeManifest`; included manifests don't override it).
*   **`logFileReport`** — The JSON/YAML `--log-file` document: `title`, `description` (omitted when empty), `logs`, `results`.
*   **`functionDef`** — A single reusable function (`name` + `source`).
*   **`functionsMap`** — `map[string][]functionDef` keyed by interpreter base name (e.g., `bash`, `zsh`, `powershell`).
*   **`loopItem`** — A single loop iteration: `Name` (string), `Vars` (map), `Tags` ([]string).
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
    *   `Loop` — Loop iteration items for repeated execution.
*   **`runResult`** — Captured process output: `Stdout`, `Stderr`, `ExitCode`, `Duration`.

#### Core Functions

1.  **`main()`**
    *   Parses CLI flags (`--manifest`, `--log-level`, `-e`, `-n`, `-t`, `--list`, `--show`, `--dump-script`, `--strict`, `--no-summary`, `--color`, `--output`, `--ansi-vars`, `--log-file`, `--log-file-format`, `--visualize`, `--export-as-mop`, `--version`).
    *   Resolves color mode and enables Windows VT if needed.
    *   Parses `--extra-var` values (supports JSON object strings).
    *   Builds a `runContext` and delegates to `listManifestValidations()` or `executeManifest()`.
    *   Prints the validation summary table (headed by the manifest title, if any), then optionally writes the `--visualize` page, and exits with `0` (all pass) or `1` (any failure). With `--export-as-mop` it instead writes the Method of Procedure and exits.

2.  **`loadManifest(path string) (*manifestData, error)`**
    *   Reads the manifest from local filesystem, HTTP/HTTPS URL, or stdin (`-`).
    *   Performs a first-pass YAML decode to extract the `templateVars` block into a `map[string]any`.

3.  **`parseManifest(root *yaml.Node) ([]kv, manifestDefaults, functionsMap, []validation, error)`**
    *   Extracts top-level keys: `defaults`, `functions`, `vars`, `validations`.
    *   Warns on duplicate keys (fails in `--strict` mode).
    *   Parses each validation item into the `validation` struct, including outcomes, conditions, includes, and per-validation interpreter/var overrides.

    *   Top-level `title` / `description` are read separately by `parseManifestMeta()` rather than returned from `parseManifest`.

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

#### Title & Description Output

*   **`parseManifestMeta(root *yaml.Node) manifestMeta`** — Reads `title` (whitespace collapsed to one line) and `description` (trimmed, newlines kept).
*   **`printManifestBanner(m manifestMeta)`** — Prints a bold title and dimmed, indented description (links made clickable by `linkify`). Called at the start of a run (`executeManifest`, depth 0, not for `--dump-script`/`--show`/MOP) and under the `--list` heading.
*   The same metadata feeds the summary heading, `--log-file` output (`writeLogFile` / `writeMarkdownLog`), `--export-as-mop` and `--visualize`, so a manifest's identity appears consistently everywhere.

### `runner_includes.go`

Contains the recursive execution engine and supporting logic that orchestrates validation runs across manifest trees.

#### Data Structures

*   **`summaryResult`** — Tracks per-validation outcome: `Manifest`, `ExecDisplay`, `ValidationID`, `Name`, `Status` (PASS/FAIL/WARN/SKIP), `Notes`, and captured `Stdout`/`Stderr` (used by `--visualize`).
*   **`runContext`** — Shared execution context threaded through recursive calls:
    *   `NameRe` — Compiled regex for `--name` filtering.
    *   `FilterTags` — Active tag filters from `--tag`.
    *   `GlobalExtraVars` — Variables from `--extra-var`.
    *   `ExecPrefix` — Hierarchical numbering prefix (e.g., `1.`, `1.2.`).
    *   `ShowFilter` — Active `--show` filter string.
    *   `Results` — Accumulated summary results (mutex-protected).
    *   `MOPSteps` — Steps collected for `--export-as-mop` (mutex-protected).

#### Core Functions

1.  **`executeManifest(manifestPath string, includeVars map[string]any, depth int, ctx *runContext) int`**
    *   The main recursive execution loop. For each manifest:
        1. Loads and templates the manifest.
        2. Parses into structs.
        3. Iterates validations, applying name/tag/condition filters.
        4. Builds iteration list from `loop` (or single pass if no loop).
        5. For each iteration: merges loop vars, prepends function bodies, builds header, renders script.
        6. Executes (buffered or live) and evaluates outcomes against exit codes.
        7. Recursively processes `includes` with child `runContext`. Builds `incVars` for the child by layering: parent global vars → inherited `includeVars` → explicit `include.vars` → loop `vars`. These are passed as both template context (`templateVars`) and shell variables (`includeVarsOrdered` in the merge chain).
    *   Returns `0` if all validations pass, `1` if any fail.

2.  **`evaluateConditions(conditions []condition, ctx *runContext) (bool, error)`**
    *   Evaluates all conditions using `expr-lang/expr`. Provides built-in environment:
        *   `no_tags()` — Returns `true` if no `--tag` flags were provided.
        *   `env(name)` — Returns the value of an environment variable.
        *   `file_exists(path)` — Returns `true` if a file/directory exists.
        *   `GOOS` / `GOARCH` — Runtime OS and architecture strings.
    *   All conditions must be `true` (AND logic) for the validation to proceed.

3.  **`listManifestValidations(manifestPath string, includeVars map[string]any, depth int)`**
    *   Recursively lists all validations (with IDs, tags, condition counts, loop counts) without executing them. Used by `--list`.

4.  **`parseTagFilter(filter string) (baseTag, loopTag string)`**
    *   Splits a tag filter at `@` into the validation-level base tag and an optional loop-level tag qualifier.

5.  **`matchValidationTags(validationTags, filterTags []string) (bool, []string)`**
    *   Checks if a validation's tags match any filter tags, returning matched loop-level qualifiers.

6.  **`shouldRunLoopItem(item loopItem, loopFilters []string) bool`**
    *   Determines whether a specific loop iteration should execute given active loop tag filters.

7.  **`matchesShowFilter(filter, validationID, name string) bool`**
    *   Matches a `--show` filter against validation ID or name (case-insensitive substring or regex).

### `visualize.go`

Implements `--visualize`. Everything needed to render is embedded in the binary (`go:embed` of `assets/markmap/*`), so no Node.js or network access is required; only the Mermaid pie chart is fetched from a CDN and degrades gracefully offline.

*   **`optionalPathFlag`** — A flag that works both bare (`--visualize`) and with a value (`--visualize=path.html`); also backs `--export-as-mop`.
*   **`buildVisualizationMarkdown(results, meta)`** — Renders the results as a Markmap outline: a Mermaid pie overview, then one branch per outcome. The manifest title labels the root node. Branch and pie colors are pinned per status (`statusColors`). All dynamic text goes through `escapeMindmapText` / `escapeMindmapRich` because manifests may come from untrusted URLs and the renderer allows inline HTML.
*   **`reviewPill()`** — Emits each validation's "Needs Review" / "Reviewed" / "Needs Attn" button as inline HTML (a `<button class="bv-pill">` whose `data-state` is `review`, `reviewed` or `attn`; the text is CSS `::after` content). Emitting HTML rather than a Markdown task-list item lets Markmap measure the node at its true width. PASS entries are rendered as `reviewed`.
*   **`buildVisualizationHTML(markdown, meta)`** — Assembles the single-file page: inlined d3/markmap scripts, CSS (including the `.bv-pill` styles with light/dark variants), the header card from **`buildVisualizationHeader`** (title + description, escaped via `htmlEscapeRich`, which only honors http/https/mailto links), and the bootstrap script. `keepReviewState` advances a button to its next state on click and reapplies the reader's choices after Markmap re-renders nodes (fold/unfold); state is in-memory only.
*   **`generateVisualization(results, outPath, meta)`** / **`openInBrowser`** — Write to a path or a temp file, then open with the OS default handler.

### `mop.go`

Implements `--export-as-mop`: the manifest walk collects `mopStep`s (rendered script, expected outcomes, notes) instead of executing, and `buildMOPMarkdown(steps, source, meta)` renders them as a Markdown runbook in execution order. Conditions are kept as informational text rather than evaluated, and `init` entries are included as prerequisite steps. A manifest title becomes the document heading, with the description as a blockquote (`mdBlockquote`). While exporting, log output is sent to stderr (`mopSafePrintf`) so stdout is clean Markdown.

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
│    global vars, and validations into Go structs;            │
│    title/description via parseManifestMeta (root manifest)  │
├─────────────────────────────────────────────────────────────┤
│ 5. Validation Loop (executeManifest)                        │
│    For each validation:                                     │
│    a. Apply name regex filter                               │
│    b. Apply tag filter (parse tag@loop syntax)              │
│    c. Evaluate conditions (skip if any false)               │
│    d. Build iteration list from loop[] (filter by loop tag) │
│    e. For each iteration:                                   │
│       - Merge loop vars into local vars                     │
│       - Inject LOOP_NAME + LOOP_INDEX                       │
│       - Prepend matching function bodies by interpreter     │
│       - Build variable header                                │
│         (MANIFEST_DIR + ANSI + includeVars + global + local) │
│       - Render script body through templates                │
│       - Execute via temp file (buffered or live-stream)     │
│       - Determine outcome (WARN → PASS → FAIL → default)   │
│       - Process includes recursively                        │
│         (parent vars + include vars + loop vars propagated)  │
├─────────────────────────────────────────────────────────────┤
│ 6. Summary & Exit                                           │
│    Print summary table (unless --no-summary)                │
│    Optionally write --visualize page / --log-file           │
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

### Template Context (first-pass rendering)

When building the Go template context for first-pass YAML rendering, values are layered lowest-to-highest precedence:

1. **OS environment** (lowest)
2. **`templateVars`** from manifest
3. **`includeVars`** (parent global vars + explicit include vars + loop vars, merged into `templateVars`)
4. **`--extra-var` overrides** (highest)

The `.Env` key always provides access to the raw OS environment regardless of overrides.

### Shell Variables (script header)

When building the shell variable header for script execution, values are layered lowest-to-highest precedence:

1. **Built-in base vars** — `MANIFEST_DIR`, ANSI color vars (if enabled), `LOOP_NAME`/`LOOP_INDEX` (if in a loop) (lowest)
2. **`includeVars`** — propagated from parent manifest's `vars:` + inherited grandparent vars + explicit `include.vars` + loop `vars`
3. **Global `vars:`** — the current manifest's own `vars:` block
4. **Local/loop vars** — per-validation `vars:` + loop iteration `vars:` (highest)

This means a parent manifest's `vars:` are automatically available as shell variables (`$var`) in child manifests without needing explicit `include.vars` passthrough. Child manifests can override any inherited variable by declaring it in their own `vars:` block.

## Validation ID Generation

Each validation receives a deterministic ID computed as an 8-character hex string from FNV-32a hash of `"{exec_number}:{name}"`. This ID is stable across runs as long as the validation's position and name don't change.
