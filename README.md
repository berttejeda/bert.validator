# bert.validator

`bert.validator` is a flexible, Go-based command-line tool that allows you to define and execute validation scripts using a YAML manifest. It provides variable templating, reusable functions, execution filtering by tags or names, and rich terminal output reporting.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Manifest Syntax](#manifest-syntax)
  - [Outcomes & Exit Codes](#outcomes--exit-codes)
  - [Raw Variables](#raw-variables)
  - [Conditions](#conditions)
  - [Include Blocks](#include-blocks)
- [Validation Summary](#validation-summary)
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
- **Raw Variables:** Use the `raw:` variable type to bypass automatic quoting and enable shell command substitution.
- **Conditional Execution:** Gate validation execution with `conditions` using Go-like boolean expressions powered by [expr](https://github.com/expr-lang/expr).
- **Manifest Includes:** Compose manifests by including other YAML files with variable passthrough and optional tag propagation.
- **Validation Summary:** Displays a summary table of all Pass/Fail/Warn/Skip results at the end of execution.

## Installation

Ensure you have Go installed, then clone the repository and build:

```bash
git clone https://github.com/bertejeda/bert.validator.git
cd bert.validator
go build -o validator .
```

Move the `validator` binary to your PATH.

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
  interpreter: "/bin/bash"
  show_output: false

# Define reusable script functions
functions:
  - name: my_shared_func
    interpreters: [sh, bash, zsh]
    script: |
      echo "This is a shared utility"

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

### Raw Variables

By default, string variables are automatically quoted when passed to shell scripts. To allow shell expansion (e.g., command substitution), use the `raw:` variable type:

```yaml
vars:
  my_computed_var:
    raw: "$(echo hello world)"
```

Raw variables bypass automatic quoting, so the shell evaluates `$(echo hello world)` at runtime instead of treating it as a literal string.

This also works inside include blocks:

```yaml
includes:
  - name: other
    path: other-manifest.yaml
    vars:
      myvar: "$(echo MyyyyyVarrrrr)"
```

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

## Validation Summary

After all validations complete, a summary table is printed showing the result of each validation:

```
--- Validation Summary ---
✅ Check File Exists              [PASS]
⚠️ Check Config                   [WARN]
❌ Check Service                   [FAIL]
⏭️  RunMyConditionalTag            [SKIP]

Total: 4 (Pass: 1, Fail: 1, Warn: 1, Skip: 1)
```

To suppress the summary, use the `--no-summary` flag:

```bash
validator --manifest manifest.yaml --no-summary
```

## Command Line Flags

| Flag | Alias | Description |
|---|---|---|
| `--manifest` | | Path to the YAML manifest file or remote HTTPS URL. |
| `--extra-var` | `-e` | Specify extra variables for the config template as `key=value` pairs. Supports nested JSON string values. Can be specified multiple times. |
| `--name` | `-n` | Regex pattern to filter validations by sequence name. |
| `--tag` | `-t` | Filter validations by tag assignment. Can be specified multiple times. |
| `--log-level` | | Set the Log level: `DEBUG`, `INFO`, `WARN`, `ERROR` (Default: `INFO`). |
| `--show-output` | | Force outputting raw child STDOUT/STDERR for all validations. |
| `--dump-script` | | Check templating definitions and dump the resulting scripts to the console without executing them. |
| `--ansi-vars` | | Expose built-in ANSI color variables (e.g. `$red`, `$bold_green`) to nested shell scripts. Enabled by default. |
| `--color` | | Define global output color engine: `auto` (default), `always`, or `never`. |
| `--strict` | | Fail processing immediately if duplicate keys are populated within the manifest template constraints. |
| `--no-summary` | | Skip printing the validation summary at the end of execution. |
| `--version` | | Print the framework's version information and exit unconditionally. |

## Architecture & Walkthrough

For a deeper technical dive into the codebase constraints and parsing layout, please see the [Code Walkthrough](CODE_WALKTHROUGH.md).
