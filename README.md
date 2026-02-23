# bert.validator

`bert.validator` is a flexible, Go-based command-line tool that allows you to define and execute validation scripts using a YAML manifest. It provides variable templating, reusable functions, execution filtering by tags or names, and rich terminal output reporting.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Manifest Syntax](#manifest-syntax)
- [Command Line Flags](#command-line-flags)
- [Architecture & Walkthrough](#architecture--walkthrough)

## Features
- **YAML Driven:** Define test scripts, outcome messages, and variables cleanly in a single manifest.
- **Templating:** Uses Go's `text/template` with Sprig support to allow dynamic variable injection inside the scripts.
- **Execution Filtering:** Selectively run validations matching a specific tag (`-t`) or regular expression (`-n`).
- **Dynamic Overrides:** Override manifest `templateVars` manually at runtime using `--extra-var` / `-e`. Support is included for deep JSON objects.
- **Cross-Platform Compatibility:** Automatically detects default shell interpreters (bash/zsh vs PowerShell).
- **Reusable Functions:** Define `functions` natively in the manifest to embed shared code across multiple validation blocks, reducing duplicate logic.

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
validator --manifest my_manifest.yaml
```

Run validations restricted to a specific tag:
```bash
validator --manifest my_manifest.yaml -t my_tag
```

Override a variable defined in the manifest (JSON object strings are supported):
```bash
validator --manifest my_manifest.yaml -e my_var=override_value -e user='{"name": "Alice"}'
```

Dump the rendered shell scripts locally to debug evaluating context, bypassing execution:
```bash
validator --manifest my_manifest.yaml --dump-script
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
      else
        exit 1
      fi
    outcomes:
      pass:
        message: "File is present"
      fail:
        message: "File is missing"
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
| `--version` | | Print the framework's version information and exit unconditionally. |

## Architecture & Walkthrough

For a deeper technical dive into the codebase constraints and parsing layout, please see the [Code Walkthrough](CODE_WALKTHROUGH.md).
