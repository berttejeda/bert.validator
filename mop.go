package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

/* =========================
   --export-as-mop: Markdown Method of Procedure
   ========================= */

// exportMOP is read throughout runner_includes.go/main.go to switch the
// manifest walk from "execute" to "render the resolved script and move on,
// don't run it" — the same shape as --dump-script, but conditions are kept
// as informational text instead of being evaluated (a MOP may be handed to
// an operator on a different machine than the one that generated it, so the
// generating machine's env/OS shouldn't decide what steps they see), and
// init entries are included as procedure steps too.
var exportMOP bool

var mopOpt optionalPathFlag

// mopStep is one step of the generated procedure: either an `init:` entry
// (a prerequisite) or a validation, with its script already fully rendered
// (templates expanded, shell header prepended) exactly as it would have run.
type mopStep struct {
	ExecDisplay string
	Kind        string // "init" | "validation"
	Manifest    string
	Name        string
	Tags        []string
	Conditions  []string
	Script      string
	Interpreter string
	PassMsg     string
	FailMsg     string
	WarnMsg     string
	PassCodes   []int
	FailCodes   []int
	WarnCodes   []int
	Notes       []string
	SkipError   bool // init-only: a non-fatal step
}

func conditionEvalStrings(conditions []condition) []string {
	if len(conditions) == 0 {
		return nil
	}
	out := make([]string, 0, len(conditions))
	for _, c := range conditions {
		if strings.TrimSpace(c.Eval) != "" {
			out = append(out, c.Eval)
		}
	}
	return out
}

// mopSafePrintf is like fmt.Printf, except in --export-as-mop mode (where
// stdout may be the Markdown document itself) it writes to stderr instead.
func mopSafePrintf(format string, a ...any) {
	if exportMOP {
		fmt.Fprintf(os.Stderr, format, a...)
		return
	}
	fmt.Printf(format, a...)
}

// mdFence picks a backtick fence long enough that it can't be closed early
// by a run of backticks that happens to appear inside content.
func mdFence(content string) string {
	longest := 0
	run := 0
	for _, r := range content {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	n := longest + 1
	if n < 3 {
		n = 3
	}
	return strings.Repeat("`", n)
}

func fenceLang(interpreterPath string) string {
	switch detectInterpreterKind(interpreterPath) {
	case interpShell:
		return "bash"
	case interpPowerShell:
		return "powershell"
	case interpCmd:
		return "bat"
	default:
		return ""
	}
}

func codeCsv(codes []int) string {
	parts := make([]string, len(codes))
	for i, c := range codes {
		parts[i] = fmt.Sprintf("%d", c)
	}
	return strings.Join(parts, ", ")
}

// buildMOPMarkdown renders the collected steps as a standalone Markdown
// Method of Procedure, in the exact order they'd execute in.
func buildMOPMarkdown(steps []mopStep, sourceManifest string) string {
	var b strings.Builder
	b.WriteString("# Method of Procedure\n\n")
	fmt.Fprintf(&b, "- **Source manifest:** `%s`\n", escapeMindmapText(sourceManifest))
	fmt.Fprintf(&b, "- **Generated:** %s by bert.validator %s\n\n", time.Now().Format("2006-01-02 15:04:05"), Version)
	b.WriteString("This document lists the steps `validator` would run for the manifest above, " +
		"for use when the `validator` command itself can't be run. Follow the steps in order; " +
		"for each one, run the command in a terminal and compare its exit code against the " +
		"listed expected results.\n\n")

	if len(steps) == 0 {
		b.WriteString("_No steps matched the current filters._\n")
		return b.String()
	}

	b.WriteString("---\n\n")

	for _, s := range steps {
		kindLabel := "Validation"
		if s.Kind == "init" {
			kindLabel = "Prerequisite"
		}
		fmt.Fprintf(&b, "## Step %s — %s: %s\n\n", escapeMindmapText(s.ExecDisplay), kindLabel, escapeMindmapRich(s.Name))
		fmt.Fprintf(&b, "- **Manifest:** `%s`\n", escapeMindmapText(s.Manifest))
		if len(s.Tags) > 0 {
			fmt.Fprintf(&b, "- **Tags:** %s\n", escapeMindmapText(strings.Join(s.Tags, ", ")))
		}
		if len(s.Conditions) > 0 {
			b.WriteString("- **Run only if** (check before starting this step):\n")
			for _, c := range s.Conditions {
				fmt.Fprintf(&b, "  - `%s`\n", c)
			}
		}
		b.WriteString("\n")

		if strings.TrimSpace(s.Script) == "" {
			b.WriteString("_(This step has no script of its own — see its included steps below.)_\n\n")
		} else {
			fence := mdFence(s.Script)
			fmt.Fprintf(&b, "%s%s\n%s\n%s\n\n", fence, fenceLang(s.Interpreter), s.Script, fence)
		}

		b.WriteString("**Expected result:**\n\n")
		switch {
		case len(s.WarnCodes) > 0 || len(s.PassCodes) > 0 || len(s.FailCodes) > 0:
			if len(s.WarnCodes) > 0 {
				fmt.Fprintf(&b, "- ⚠️ **WARN** if exit code is one of: %s", codeCsv(s.WarnCodes))
				if s.WarnMsg != "" {
					fmt.Fprintf(&b, " — %s", escapeMindmapRich(s.WarnMsg))
				}
				b.WriteString("\n")
			}
			if len(s.PassCodes) > 0 {
				fmt.Fprintf(&b, "- ✅ **PASS** if exit code is one of: %s", codeCsv(s.PassCodes))
				if s.PassMsg != "" {
					fmt.Fprintf(&b, " — %s", escapeMindmapRich(s.PassMsg))
				}
				b.WriteString("\n")
			}
			if len(s.FailCodes) > 0 {
				fmt.Fprintf(&b, "- ❌ **FAIL** if exit code is one of: %s", codeCsv(s.FailCodes))
				if s.FailMsg != "" {
					fmt.Fprintf(&b, " — %s", escapeMindmapRich(s.FailMsg))
				}
				b.WriteString("\n")
			}
			b.WriteString("- Any other exit code: **PASS** if `0`, **FAIL** otherwise.\n")
		default:
			b.WriteString("- ✅ **PASS** if the exit code is `0`.\n")
			if s.PassMsg != "" {
				fmt.Fprintf(&b, "  - %s\n", escapeMindmapRich(s.PassMsg))
			}
			b.WriteString("- ❌ **FAIL** otherwise.\n")
			if s.FailMsg != "" {
				fmt.Fprintf(&b, "  - %s\n", escapeMindmapRich(s.FailMsg))
			}
		}
		b.WriteString("\n")

		if s.Kind == "init" {
			if s.SkipError {
				b.WriteString("If this step fails: note the failure and continue to the next step.\n\n")
			} else {
				b.WriteString("If this step fails: **stop here** — do not continue with the remaining steps.\n\n")
			}
		}

		if len(s.Notes) > 0 {
			b.WriteString("**Notes:**\n\n")
			for _, n := range s.Notes {
				fmt.Fprintf(&b, "- %s\n", escapeMindmapRich(n))
			}
			b.WriteString("\n")
		}

		b.WriteString("---\n\n")
	}

	return b.String()
}

// generateMOP renders the collected steps and writes them to outPath, or to
// stdout when outPath is empty.
func generateMOP(steps []mopStep, sourceManifest, outPath string) error {
	markdown := buildMOPMarkdown(steps, sourceManifest)
	if outPath == "" {
		_, err := fmt.Print(markdown)
		return err
	}
	return os.WriteFile(outPath, []byte(markdown), 0o644)
}
