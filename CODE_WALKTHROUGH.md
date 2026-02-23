# bert.validator Code Walkthrough

This document provides a high-level overview of the `bert.validator` codebase.

## Overview

The `bert.validator` is a Go-based command-line tool designed to execute validation scripts defined in a YAML manifest. It allows you to run scripts, handle outcomes, inject dynamic variables via templating, define reusable functions, and filter which validations to run.

## Key Components

### `main.go`

This is the primary file and contains almost all of the application's logic.

#### Data Structures

*   **`manifestDefaults`**: Holds the global default settings defined in the `defaults:` block of the manifest, such as `show_output`, `interpreter`, and `env_only`.
*   **`validation`**: Represents a single validation block from the manifest. It includes:
    *   `Name`: The name of the validation.
    *   `Tags`: Tags for filtering.
    *   `Script`: The actual shell script to execute.
    *   `PassMessage` / `FailMessage`: Custom strings to print based on the outcome.
    *   `InterpreterPath` / `InterpreterFlags`: The shell to use (e.g., `/bin/bash`, `-c`).
    *   `LocalVarsMap`: Variables scoped only to this validation.
*   **`kv`**: A key-value struct used to maintain the order of variables during template rendering.

#### Core Functions

1.  **`main()`**
    *   Parses command-line flags (e.g., `--manifest`, `--log-level`, `-e`, `-n`, `-t`).
    *   Handles color initialization and ANSI support.
    *   Loads and pre-parses the manifest using `loadManifest`.
    *   Executes the Go text template on the manifest file using the globally merged variables.
    *   Unmarshals the templated YAML into Go structs.
    *   Filters the validations by name regex (`-n`) or tags (`-t`).
    *   Iterates over the filtered validations, builds the script by injecting ANSI variables, global variables, and defined functions, and then executes it.
    *   Tracks overall success/failure and prints a final log summary.

2.  **`parseManifest(root *yaml.Node) (globalVars, manifestDefaults, functions, validations, error)`**
    *   Extracts all the top-level keys (`vars`, `defaults`, `functions`, `validations`) from the unmarshaled YAML node.
    *   Converts individual validation items into the `validation` struct.

3.  **`loadManifest(path string) (*manifestTemplateData, error)`**
    *   Reads the manifest file from the local filesystem or via an HTTP/HTTPS URL.
    *   Performs an initial sweep to extract the `templateVars` block.

4.  **`autoDetectDefaultInterpreter()`**
    *   A helper method that tries to find a suitable shell for the underlying OS (e.g., PowerShell on Windows, zsh/bash/sh on macOS and Unix).

5.  **`runValidation(...)`**
    *   Constructs the environment and full command to run a script block.
    *   Executes the script as a child process, capturing output.
    *   Optionally streams output via STDOUT/STDERR or displays a progress spinner indicator.

#### Templating

The validator utilizes `text/template` coupled with the Sprig library to provide rich templating capabilities inside the YAML manifest. When the manifest is read, any variables passed via `--extra-var` (`-e`) are overlaid onto `templateVars` before the manifest is fully evaluated.

Variables are made available in `{{ .var_name }}` syntax inside the script bodies as well. Nested JSON keys are mapped dynamically.

### `console_posix.go` / `ansi_windows.go`

These files handle platform-specific terminal output logic.
*   **`console_posix.go`**: Provides a no-op fallback for Unix systems where ANSI codes typically work out-of-the-box.
*   **`ansi_windows.go`**: Wraps standard output or enables Virtual Terminal Processing to properly display colors on Windows environments.

## Execution Flow

1. **Initialization:** CLI flags are parsed.
2. **First-pass Parsing:** Manifest is read; `templateVars` are extracted and merged with `--extra-var` overrides from the user prompt.
3. **Template Rendering:** The raw YAML strings go through `text/template` parameter injection.
4. **Second-pass Parsing:** The populated YAML is parsed into the internal structs (`defaults`, `vars`, `functions`, `validations`).
5. **Filtering Check:** Regular expressions and tags are checked to skip/run specific validations.
6. **Execution:** The application loops over the requested validations and runs them.
7. **Reporting:** A running summary is collected, exiting with `0` if all pass, or `1` if any validation returns a non-zero exit code.
