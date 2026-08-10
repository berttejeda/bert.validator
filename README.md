# bert.validator

`bert.validator` is a flexible, Go-based command-line tool that allows you to define and execute validation scripts using a YAML manifest. It provides variable templating, reusable functions, execution filtering by tags or names, and rich terminal output reporting.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Manifest Syntax](#manifest-syntax)
  - [Outcomes & Exit Codes](#outcomes--exit-codes)
  - [Shell Command Substitution in Variables](#shell-command-substitution-in-variables)
  - [Conditions](#conditions)
  - [Include Blocks](#include-blocks)
  - [Loop Iterations](#loop-iterations)
  - [Validation Notes](#validation-notes)
- [Variable Scopes: `templateVars` vs `vars`](#variable-scopes-templatevars-vs-vars)
- [Validation Summary](#validation-summary)
  - [Exec Numbering Conventions](#exec-numbering-conventions)
- [Command Line Flags](#command-line-flags)
- [Architecture & Walkthrough](#architecture--walkthrough)

## Features
- **YAML Driven:** Define test scripts, outcome messages, and variables cleanly in a single manifest.
- **Templating:** Uses Go's `text/template` with Sprig support to allow dynamic variable injection inside the scripts.
- **Execution Filtering:** Selectively run validations matching a specific tag (`-t`) or regular expression (`-n`).
- **Dynamic Overrides:** Override manifest `templateVars` manually at runtime using `--extra-var` / `-e`. Support is included for deep JSON objects.
- **Cross-Platform Compatibility:** Automatically detects default shell interpreters (bash/zsh vs PowerShell).
- **Reusable Functions:** Define `functions` natively in the manifest to embed shared code across multiple validation blocks, reducing duplicate logic.
- **Outcome-Based Results:** Define `pass`, `fail`, and `warn` outcomes with optional `exit_codes` lists for fine-grained result determination.
- **Shell Command Substitution:** Variables are double-quoted in the generated script, so `$(...)` expressions are naturally evaluated at runtime.
- **Conditional Execution:** Gate validation execution with `conditions` using Go-like boolean expressions powered by [expr](https://github.com/expr-lang/expr).
- **Inspection Tools:** Use `--list` to enumerate all validations with IDs, or `--show` to view the fully rendered script for a specific validation without executing.
- **Loop Iterations:** Execute a validation multiple times with per-iteration variable overrides and loop-level tag filtering (`-t tag@loop_tag`).
- **Manifest Includes:** Compose manifests by including other YAML files with variable passthrough and optional tag propagation.
- **Validation Notes:** Attach free-form notes to any validation; notes are rendered with the same template engine and displayed under the validation's summary line.
- **Validation Summary:** Displays a summary table of all Pass/Fail/Warn/Skip results at the end of execution.

## Installation

### Homebrew (macOS / Linux)

The easiest way to install `bert.validator` is via the Homebrew tap:

```bash
brew tap berttejeda/tap https://github.com/berttejeda/bert.validator.git
brew install berttejeda/tap/bert-validator
```

This builds the latest release from source using Homebrew's Go toolchain and installs the binary as `validator`.

### Download a pre-built binary

Pre-built archives for Linux, Windows, and macOS (Intel and Apple Silicon) are
attached to each [GitHub Release](https://github.com/berttejeda/bert.validator/releases).
Each archive contains the binary named `validator` (`validator.exe` on Windows).

Choose the asset that matches your platform, for example:

```bash
# macOS Apple Silicon
curl -L -o bert.validator-darwin-arm64.tar.gz https://github.com/berttejeda/bert.validator/releases/latest/download/bert.validator-darwin-arm64.tar.gz
tar -xzf bert.validator-darwin-arm64.tar.gz
mv validator /usr/local/bin/
```

Replace `bert.validator-darwin-arm64.tar.gz` with the appropriate asset for your OS and architecture:

| OS      | x86          | x64            | Apple Silicon  |
|---------|--------------|----------------|----------------|
| Linux   | `linux-386`  | `linux-amd64`  | —              |
| Windows | `windows-386`| `windows-amd64`| —              |
| macOS   | —            | `darwin-amd64` | `darwin-arm64` |

### Build from source

Ensure you have [Go](https://go.dev/) installed, then clone the repository and build:

```bash
git clone https://github.com/berttejeda/bert.validator.git
cd bert.validator
go build -o validator .
```

Move the `validator` binary to a directory on your `PATH`.

## Usage

Basic execution using a local manifest file:
```bash
validator --manifest manifest.yaml
```

Run validations restricted to a specific tag:
```bash
validator --manifest manifest.yaml -t my_tag
```

Override a variable defined in the manifest (JSON object strings are supported):
```bash
validator --manifest manifest.yaml -e my_var=override_value -e user='{"name": "Alice"}'
```

Dump the rendered shell scripts locally to debug evaluating context, bypassing execution:
```bash
validator --manifest manifest.yaml --dump-script
```

## Manifest Syntax

A basic `manifest.yaml` looks like this:

```yaml
# Define variables available to the template engine
templateVars:
  app_name: "MyApp"

# Global default interpreter and settings
defaults:
  show_output: false
  interpreters:
    script: "/bin/bash"

# Define reusable script functions (keyed by interpreter)
functions:
  bash:
    - name: my_shared_func
      source: |
        my_shared_func() { echo "This is a shared utility"; }
  zsh:
    - name: my_shared_func
      source: |
        my_shared_func() { echo "This is a shared utility"; }

# Global script variables mapped to environment
vars:
  global_var: 123

# The actual assertions/validations to run
validations:
  - name: "Check File Exists"
    tags:
      - "system"
      - "core"
    script: |
      my_shared_func
      if [ -f "/etc/hosts" ]; then
        echo "{{ .app_name }} config found"
        exit 0
      elif [ ! -s "/etc/hosts" ]; then
        exit 2
      else
        exit 1
      fi
    outcomes:
      warn:
        message: "File is present, but empty"
        exit_codes:
          - 2
      pass:
        message: "File is present"
        exit_codes:
          - 0
      fail:
        message: "File is missing"
```

### Outcomes & Exit Codes

Each validation can define `pass`, `fail`, and `warn` outcomes under the `outcomes` key. Each outcome supports:
- **`message`** — A human-readable message displayed when the outcome is triggered.
- **`exit_codes`** — A list of integer exit codes that trigger the outcome.

Outcome evaluation order:
1. If `warn.exit_codes` is defined and the script's exit code matches, the result is **WARN**.
2. If `pass.exit_codes` is defined and the exit code matches, the result is **PASS**.
3. If `fail.exit_codes` is defined and the exit code matches, the result is **FAIL**.
4. If no `exit_codes` match, the default behavior applies: exit code `0` = PASS, anything else = FAIL.

```yaml
outcomes:
  warn:
    message: "File is present, but empty"
    exit_codes:
      - 2
  pass:
    message: "File is present"
    exit_codes:
      - 0
  fail:
    message: "File is missing"
```

### Shell Command Substitution in Variables

String variables are emitted inside double quotes in the generated shell header (e.g., `MY_VAR="value"`). Because bash/zsh evaluate `$(...)` within double quotes, command substitution works naturally:

```yaml
vars:
  my_computed_var: "$(hostname -s)"
```

At runtime, the shell evaluates `$(hostname -s)` and assigns the result to `my_computed_var`.

This also works inside include blocks:

```yaml
includes:
  - name: other
    path: other-manifest.yaml
    vars:
      myvar: "$(echo MyyyyyVarrrrr)"
```

> **Note:** Numeric literals are emitted unquoted for bash arithmetic compatibility.

### Conditions

Validations can be conditionally executed using the `conditions` key. Each condition is an object with an `eval` field containing a Go-like boolean expression, powered by [expr-lang/expr](https://github.com/expr-lang/expr).

**All conditions must evaluate to `true`** for the validation to run (AND logic). If any condition is `false`, the validation is skipped.

```yaml
validations:
  - name: "RunMyConditionalTag"
    tags:
      - my_tag
    conditions:
      - eval: "!no_tags()"            # only run when -t flag is provided
      - eval: file_exists("/etc/hosts")
      - eval: 1 == 1
      - eval: GOOS == "darwin"
    script: echo "Running conditional validation"
    show_output: true
```

#### Built-in Functions & Variables

| Name | Type | Description |
|---|---|---|
| `no_tags()` | function | Returns `true` if no `-t`/`--tag` flags were provided at the command line. |
| `env(name)` | function | Returns the value of the environment variable `name`. |
| `file_exists(path)` | function | Returns `true` if a file or directory exists at `path`. |
| `GOOS` | variable | The current operating system (e.g., `"darwin"`, `"linux"`, `"windows"`). |
| `GOARCH` | variable | The current architecture (e.g., `"amd64"`, `"arm64"`). |

#### Expression Examples

```yaml
# Negate with ! (must be quoted in YAML)
- eval: "!no_tags()"

# Check environment variables
- eval: env("CI") != ""
- eval: env("DEPLOY_ENV") == "production"
- eval: len(env("MY_VAR")) > 0

# File existence
- eval: file_exists("/etc/hosts")

# Platform checks
- eval: GOOS == "darwin"
- eval: GOARCH == "arm64"

# Compound expressions
- eval: GOOS == "linux" && env("CI") != ""
```

> **Note:** When using `!` for negation, the value **must be quoted** in YAML (e.g., `"!no_tags()"`) because unquoted `!` is interpreted as a YAML tag.

### Include Blocks

Validations can include other manifest files, enabling modular and reusable configurations:

```yaml
validations:
  - name: "From other"
    includes:
      - name: other
        path: other-manifest.yaml
        vars:
          myvar: "$(echo MyyyyyVarrrrr)"
        propagate_tags: false
    tags:
      - gabbledegak
```

| Field | Description |
|---|---|
| `name` | A descriptive name for the include. |
| `path` | Path to the included manifest file (relative to the parent manifest or absolute). |
| `vars` | Variables to pass into the included manifest's `templateVars`. |
| `propagate_tags` | If `true` (default), the parent's tag filter is applied to the included manifest's validations. Set to `false` to run all validations in the include regardless of tag filters. |

#### Parent Variable Propagation

The parent manifest's `vars:` block is automatically propagated to child manifests. Child scripts can reference parent variables using shell syntax (`$var`) without the parent needing to explicitly pass them via `include.vars`:

```yaml
# parent-manifest.yaml
vars:
  global_var: 123

validations:
  - name: "From other"
    includes:
      - name: other
        path: child-manifest.yaml
```

```yaml
# child-manifest.yaml
validations:
  - name: "Child Validation"
    script: echo "parent global_var is $global_var"   # outputs: 123
```

The precedence order for shell variables in child manifests (lowest → highest):
1. **Built-in vars** — `MANIFEST_DIR`, ANSI vars, `LOOP_NAME`/`LOOP_INDEX`
2. **Parent vars** — parent's `vars:` block + any vars inherited from grandparent includes
3. **Include vars** — explicit `include.vars` + loop `vars` from the parent
4. **Child global vars** — the child manifest's own `vars:` block
5. **Child local/loop vars** — per-validation and per-loop-iteration vars in the child

### Loop Iterations

Validations can be executed multiple times using the `loop` key. Each loop item can define its own `name`, `vars`, and `tags`:

```yaml
validations:
  - name: "SkipMe"
    tags: ["other"]
    script: echo "Running $LOOP_NAME with myvar=$myvar"
    show_output: true
    loop:
      - name: "Loop 1"
        vars:
          myvar: var_from_loop_1
        tags:
          - loop1
      - name: "Loop 2"
        tags:
          - loop2
```

| Field | Description |
|---|---|
| `name` | Display name for the iteration (shown in output as `ValidationName [LoopName]`). If omitted, defaults to `loop N`. |
| `vars` | Variables that override the validation's local `vars` for this iteration. Also override include `vars` when used with includes. |
| `tags` | Loop-level tags used for selective iteration filtering with the `tag@loop_tag` syntax. |

#### Loop Tag Filtering

Use the `@` separator in `-t` to target specific loop iterations:

```bash
# Run ALL iterations of validations tagged "other"
validator --manifest manifest.yaml -t other

# Run ONLY iterations tagged "loop1" within validations tagged "other"
validator --manifest manifest.yaml -t other@loop1
```

#### Built-in Loop Variables

When inside a loop, two extra shell variables are injected:

| Variable | Description |
|---|---|
| `LOOP_NAME` | The `name` of the current loop item. |
| `LOOP_INDEX` | The 0-based index of the current iteration. |

#### Loop with Includes

Loops work with includes — each iteration re-executes the included manifest with the loop's vars merged on top of the include's vars:

```yaml
validations:
  - name: "From other"
    includes:
      - name: other
        path: other-manifest.yaml
        vars:
          myvar: "$(echo DefaultVar)"
        propagate_tags: false
    tags:
      - gabbledegak
    loop:
      - name: "Loop 1"
        vars:
          myvar: "$(echo OverrideVar1)"
      - name: "Loop 2"
        vars:
          myvar: "$(echo OverrideVar2)"
```

In this example, the included manifest runs twice — once with `myvar` set to the result of `$(echo OverrideVar1)` and once with `$(echo OverrideVar2)`.

### Validation Notes

Validations can include a `notes` list. Each note is rendered with the same Go template context as the validation script (`templateVars`, shell `vars`, loop variables, environment variables, and `--extra-var` overrides) and is printed under the validation's summary line.

```yaml
validations:
  - name: "Check File Exists"
    notes:
      - "Checked file, my app name is {{ .app_name }}"
    tags:
      - "system"
      - "core"
    script: |
      if [ -f "/etc/hosts" ]; then
        exit 0
      fi
```

This produces:

```text
✅ Validation #2    [280dd229] Check File Exists              [PASS]
   Notes:
   - Checked file, my app name is MyApp
```

Loop items can also define their own `notes` list. When a loop item has notes, those override the top-level notes for that iteration. If a validation has no top-level `notes` and only one loop item defines notes, only that iteration displays a note.

```yaml
validations:
  - name: "Check File Exists"
    notes:
      - "Checked file, my app name is {{ .app_name }}"
    script: |
      if [ -f "/etc/hosts" ]; then
        exit 0
      fi
    loop:
      - name: "Loop 1"
        notes:
          - "Checked file for Loop 1, my app name is {{ .app_name }}"
      - name: "Loop 2"
      - name: "Loop 3"
```

This produces for `Loop 1`:

```text
✅ Validation #2@Loop 1 [280dd229] Check File Exists [Loop 1] [PASS]
   Notes:
   - Checked file for Loop 1, my app name is MyApp
```

and for `Loop 2` and `Loop 3` the top-level note is used.

> **Caveat:** A validation that only includes other manifests and does not itself produce a summary result will not display its notes. Place `notes` on validations that execute their own scripts (or on the child validations inside the included manifests) so the notes appear in the summary.

## Variable Scopes: `templateVars` vs `vars`

The manifest has two distinct variable systems. Understanding the difference is important when composing manifests with includes and loops.

| Section | Available as | Resolved during | Syntax in scripts |
|---|---|---|---|
| `templateVars:` | Go template context | First-pass YAML rendering (before parsing) | `{{ .myvar }}` |
| `vars:` (global or per-validation) | Shell variables | After parsing, injected into the script header | `$myvar` |

### How it works

1. **First pass** — The entire YAML file is rendered as a Go template. The context includes `templateVars`, variables passed via `include.vars` / loop `vars`, parent `vars:` (propagated automatically), environment variables, and `--extra-var` overrides.
2. **Second pass** — After the rendered YAML is parsed, each validation's script is rendered again with the full merged variable set (`vars` + local vars + loop vars + parent vars).

Because `{{ .myvar }}` expressions are consumed during the **first pass**, only values present in `templateVars` or passed via `includeVars` are available at that stage. The `vars:` block is parsed *after* the first pass and is only available as shell variables (`$myvar`) or during the second-pass template rendering.

### Practical implications

**Using `templateVars` for template defaults in included manifests:**

```yaml
# child-manifest.yaml
templateVars:
  myvar: "default_value"    # available as {{ .myvar }} during first-pass rendering

vars:
  myvar: '{{ .myvar }}'      # captures the resolved template value into a shell variable

validations:
  - name: "Example"
    script: echo "template={{ .myvar }} shell=$myvar"
```

When the parent passes `myvar` via `include.vars` or loop `vars`, it overrides the child's `templateVars` default. If the parent does NOT pass `myvar`, the child's `templateVars` default is used.

**Common pitfall — using `vars` alone for template expressions:**

```yaml
# child-manifest.yaml
vars:
  myvar: "some_value"       # NOT available as {{ .myvar }} during first-pass rendering

validations:
  - name: "Example"
    script: echo "{{ .myvar }}"   # ⚠ resolves to <no value>
```

Since `vars:` is parsed after the first-pass rendering, `{{ .myvar }}` in the script is evaluated before `myvar` exists in the template context. Use `$myvar` (shell syntax) instead, or move the default to `templateVars:`.

## Validation Summary

After all validations complete, a summary table is printed showing the result of each validation:

```
--- Validation Summary ---
✅ Validation #1    [a1b2c3d4] Check File Exists              [PASS]
⚠️ Validation #2    [e5f6a7b8] Check Config                   [WARN]
❌ Validation #3    [c9d0e1f2] Check Service                   [FAIL]
⏭️  Validation #4    [a3b4c5d6] RunMyConditionalTag            [SKIP]

Total: 4 (Pass: 1, Fail: 1, Warn: 1, Skip: 1)
```

Each line shows:
- **Status icon** — ✅ PASS, ⚠️ WARN, ❌ FAIL, or ⏭️ SKIP.
- **Exec number** — `#N` identifies the validation's position, with dot-levels for includes and `@LoopName` for loop iterations (see below).
- **Validation ID** — A deterministic FNV-32a hash in brackets.
- **Name** — The validation name, with `[LoopName]` suffix for loop iterations.
- **Result** — The outcome label.

### Exec Numbering Conventions

The exec number encodes the nesting hierarchy so you can trace exactly which validation ran and under which loop iteration.

#### Format

```
#<parent>[.child[.grandchild...]][@LoopName]
```

- **Dot levels** (`.`) represent include nesting depth. `#1.2` means parent validation 1, child validation 2.
- **`@LoopName`** identifies the loop iteration. It appears on the segment that has a loop — the current validation or a parent that iterated over includes.

#### Examples by scenario

**No loops, no includes** — simple sequential numbering:

```
✅ Validation #1    [a1b2c3d4] Check File Exists    [PASS]
✅ Validation #2    [e5f6a7b8] Check Config          [PASS]
```

**Includes, no loops** — dot-separated parent/child:

```
✅ Validation #1.1  [a1b2c3d4] Included Validation   [PASS]
✅ Validation #1.2  [e5f6a7b8] Included Validation 2 [PASS]
```

Here `#1.1` = parent validation 1 → child validation 1.

**Loops on a parent with includes (child has no loop)** — parent loop name appears in the prefix:

```
✅ Validation #1@Loop 1.1 [a1b2c3d4] Included Validation   [PASS]
✅ Validation #1@Loop 1.2 [e5f6a7b8] Included Validation 2 [PASS]
✅ Validation #1@Loop 2.1 [a1b2c3d4] Included Validation   [PASS]
✅ Validation #1@Loop 2.2 [e5f6a7b8] Included Validation 2 [PASS]
```

`#1@Loop 1.1` = parent validation 1, parent loop "Loop 1", child validation 1.

**Loops on a standalone validation (no includes):**

```
✅ Validation #3@Loop 1 [c9d0e1f2] SkipMe [Loop 1]   [PASS]
✅ Validation #3@Loop 2 [c9d0e1f2] SkipMe [Loop 2]   [PASS]
```

`#3@Loop 1` = validation 3, loop iteration "Loop 1". The validation name also shows `[Loop 1]` as a suffix.

**Loops on both parent and child** — each `@` refers to its own level:

```
✅ Validation #1@Loop 1.1@Child loop 1 [a1b2c3d4] Included Validation [Child loop 1] [PASS]
✅ Validation #1@Loop 1.1@Child loop 2 [a1b2c3d4] Included Validation [Child loop 2] [PASS]
✅ Validation #1@Loop 1.2              [e5f6a7b8] Included Validation 2              [PASS]
✅ Validation #1@Loop 2.1@Child loop 1 [a1b2c3d4] Included Validation [Child loop 1] [PASS]
✅ Validation #1@Loop 2.1@Child loop 2 [a1b2c3d4] Included Validation [Child loop 2] [PASS]
✅ Validation #1@Loop 2.2              [e5f6a7b8] Included Validation 2              [PASS]
```

Reading `#1@Loop 1.1@Child loop 2`:
- `1` — parent validation number
- `@Loop 1` — parent loop iteration name
- `.1` — child validation number within the include
- `@Child loop 2` — child's own loop iteration name

Non-looped children (like `#1@Loop 1.2`) have no trailing `@`.

To suppress the summary, use the `--no-summary` flag:

```bash
validator --manifest manifest.yaml --no-summary
```

## Command Line Flags

| Flag | Alias | Description |
|---|---|---|
| `--manifest` | | Path to the YAML manifest file, remote HTTPS URL, or `-` for stdin. |
| `--extra-var` | `-e` | Specify extra variables for the config template as `key=value` pairs. Supports nested JSON string values. Can be specified multiple times. |
| `--name` | `-n` | Regex pattern to filter validations by sequence name. |
| `--tag` | `-t` | Filter validations by tag assignment. Can be specified multiple times. |
| `--log-level` | | Set the Log level: `DEBUG`, `INFO`, `WARN`, `ERROR` (Default: `INFO`). |
| `--show-output` | | Force outputting raw child STDOUT/STDERR for all validations. |
| `--dump-script` | | Check templating definitions and dump the resulting scripts to the console without executing them. |
| `--list` | | List all validations with their Execution Number and Validation ID, then exit without running. |
| `--show` | | Show rendered script for validations matching the given Validation ID or name pattern, then exit. |
| `--ansi-vars` | | Expose built-in ANSI color variables (e.g. `$red`, `$bold_green`) to nested shell scripts. Enabled by default. |
| `--color` | | Define global output color engine: `auto` (default), `always`, or `never`. |
| `--strict` | | Fail processing immediately if duplicate keys are populated within the manifest template constraints. |
| `--no-summary` | | Skip printing the validation summary at the end of execution. |
| `--version` | | Print the framework's version information and exit unconditionally. |

## Architecture & Walkthrough

For a deeper technical dive into the codebase constraints and parsing layout, please see the [Code Walkthrough](CODE_WALKTHROUGH.md).
