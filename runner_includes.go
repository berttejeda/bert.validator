package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"gopkg.in/yaml.v3"
)

type runContext struct {
	NameRe          *regexp.Regexp
	FilterTags      []string
	GlobalExtraVars map[string]any
}

func executeManifest(manifestPath string, includeVars map[string]any, depth int, ctx *runContext) int {
	yamlTemplateData, err := loadManifest(manifestPath)
	if err != nil {
		logAt(ERROR, "Failed to load manifest: %v", err)
		return 2
	}
	emptyMap := make(map[string]string)

	if yamlTemplateData.TemplateVars == nil {
		yamlTemplateData.TemplateVars = make(map[string]any)
	}

	for k, val := range includeVars {
		yamlTemplateData.TemplateVars[k] = val
	}
	for k, val := range ctx.GlobalExtraVars {
		yamlTemplateData.TemplateVars[k] = val
	}

	env := envMap()
	initialTmplCtx := buildTemplateContext(emptyMap, yamlTemplateData.TemplateVars, env)
	tmpl, err := template.New(manifestPath).
		Funcs(sprig.FuncMap()).
		Option("missingkey=default").
		Parse(yamlTemplateData.Content)
	if err != nil {
		fmt.Printf("Error parsing template: %v\n", err)
		return 2
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, initialTmplCtx)
	if err != nil {
		fmt.Printf("Error executing template: %v\n", err)
		return 2
	}

	var yamlData = buf.String()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(yamlData), &root); err != nil {
		logAt(ERROR, "Failed to parse YAML: %v", err)
		if level == DEBUG {
			logAt(DEBUG, "\n--- Rendered YAML (failed to parse) ---\n%s\n--- end ---", yamlData)
		}
		return 2
	}

	tplMap := extractTemplates(&root)

	globalOrdered, defs, funcs, validations, err := parseManifest(&root)
	if err != nil {
		logAt(ERROR, "Invalid manifest: %v", err)
		return 2
	}

	autoInterp, autoKind := autoDetectDefaultInterpreter()
	if !dumpScript && depth == 0 {
		logAt(INFO, "Using auto-detected default interpreter: %s", autoInterp)
		logAt(INFO, "Found %d validation(s) to run.", len(validations))
		fmt.Println()
	}

	overallRC := 0

	for _, v := range validations {
		if ctx.NameRe != nil {
			if !ctx.NameRe.MatchString(v.Name) {
				continue
			}
		}

		if len(ctx.FilterTags) > 0 {
			logAt(DEBUG, "Checking tags for %s: %v against filter %v", v.Name, v.Tags, ctx.FilterTags)
			found := false
			for _, t := range ctx.FilterTags {
				for _, vt := range v.Tags {
					if vt == t {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				continue
			}
		}

		if !dumpScript {
			prefix := ""
			if depth > 0 {
				prefix = strings.Repeat("  ", depth)
			}
			logAt(INFO, "%s▶ Running validation: %s", prefix, v.Name)
		}

		if strings.TrimSpace(v.Script) == "" {
			if len(v.Includes) == 0 {
				logAt(WARN, "⚠ Skipped '%s': empty script.", v.Name)
				if overallRC == 0 {
					overallRC = 1
				}
				fmt.Println()
				continue
			}
		} else {
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

			interpBase := strings.ToLower(filepath.Base(interpPath))
			interpBase = strings.TrimSuffix(interpBase, ".exe")

			for key, fList := range funcs {
				match := false
				if key == interpBase {
					match = true
				} else if key == "powershell" && interpBase == "pwsh" {
					match = true
				}
				if match {
					var sb strings.Builder
					for _, fn := range fList {
						sb.WriteString(fn.Source)
						sb.WriteByte('\n')
					}
					v.Script = sb.String() + v.Script
				}
			}

			flags := v.InterpreterFlags
			if len(flags) == 0 && len(defs.InterpreterFlags) > 0 {
				flags = append([]string(nil), defs.InterpreterFlags...)
			}

			envOnly := v.EnvOnly
			if !v.EnvOnlySet {
				envOnly = defs.EnvOnly
			}

			base := []kv{}
			manifestDir := "."
			if !strings.HasPrefix(manifestPath, "http://") && !strings.HasPrefix(manifestPath, "https://") {
				if abs, err := filepath.Abs(manifestPath); err == nil {
					manifestDir = filepath.Dir(abs)
				}
			}
			base = append(base, kv{Key: "MANIFEST_DIR", Value: manifestDir})

			if enableAnsiVars {
				base = append(base, builtinAnsiVars()...)
			}

			mergedBG, _ := mergeVars(base, globalOrdered)
			mergedList, mergedMap := mergeVars(mergedBG, v.LocalVarsOrdered)

			if !dumpScript {
				logAt(DEBUG, "[%s] Merged vars: %v", v.Name, mergedMap)
			}

			templatesAny := make(map[string]any, len(tplMap))
			for k, vTpl := range tplMap {
				templatesAny[k] = vTpl
			}

			tmplCtx := buildTemplateContext(mergedMap, templatesAny, env)

			scriptTemplated, err := renderTemplate(v.Name+"_script", v.Script, tmplCtx)
			if err != nil {
				logAt(ERROR, "[%s] Template error in script: %v", v.Name, err)
				overallRC = 1
				fmt.Println()
				continue
			}
			v.Script = scriptTemplated

			if v.Pass.Message != "" {
				if passMsgT, err := renderTemplate(v.Name+"_pass", v.Pass.Message, tmplCtx); err == nil {
					v.Pass.Message = passMsgT
				} else {
					logAt(ERROR, "[%s] Template error in pass message: %v", v.Name, err)
					overallRC = 1
					fmt.Println()
					continue
				}
			}
			if v.Fail.Message != "" {
				if failMsgT, err := renderTemplate(v.Name+"_fail", v.Fail.Message, tmplCtx); err == nil {
					v.Fail.Message = failMsgT
				} else {
					logAt(ERROR, "[%s] Template error in fail message: %v", v.Name, err)
					overallRC = 1
					fmt.Println()
					continue
				}
			}
			if v.Warn.Message != "" {
				if warnMsgT, err := renderTemplate(v.Name+"_warn", v.Warn.Message, tmplCtx); err == nil {
					v.Warn.Message = warnMsgT
				} else {
					logAt(ERROR, "[%s] Template error in warn message: %v", v.Name, err)
					overallRC = 1
					fmt.Println()
					continue
				}
			}

			finalScript := v.Script
			if !envOnly {
				switch kind {
				case interpShell, interpPowerShell, interpCmd:
					if hdr := buildHeader(kind, mergedList); hdr != "" {
						finalScript = hdr + "\n" + finalScript
					}
				}
			}

			extraEnv := map[string]string{}
			if envOnly || kind == interpOther {
				for k, val := range mergedMap {
					extraEnv[k] = val
				}
			}

			if dumpScript {
				logAt(INFO, "\n--- [%s] FINAL SCRIPT ---\n%s\n--- end ---", v.Name, finalScript)
			} else if level == DEBUG {
				logAt(DEBUG, "\n--- [%s] FINAL SCRIPT ---\n%s\n--- end ---", v.Name, finalScript)
			}

			if !dumpScript {
				effectiveShowOutput := showOutputFlag
				if defs.ShowOutputSet {
					effectiveShowOutput = defs.ShowOutput
				}
				if v.ShowOutputSet {
					effectiveShowOutput = v.ShowOutput
				}

				var res *runResult
				if effectiveShowOutput {
					res, err = runWithInterpreterLive(
						interpPath, flags, finalScript, extraEnv, kind,
						v.Name, !useColor,
					)
				} else {
					var stopProgress func()
					if level != DEBUG {
						stopProgress = startProgress(v.Name)
					} else {
						stopProgress = startProgress(v.Name)
					}

					res, err = runWithInterpreter(interpPath, flags, finalScript, extraEnv, kind)

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

				passMsg := renderMsg(v.Pass.Message, mergedMap)
				failMsg := renderMsg(v.Fail.Message, mergedMap)
				warnMsg := renderMsg(v.Warn.Message, mergedMap)

				matchCode := func(code int, codes []int) bool {
					for _, c := range codes {
						if c == code {
							return true
						}
					}
					return false
				}

				if len(v.Warn.ExitCodes) > 0 && matchCode(res.ExitCode, v.Warn.ExitCodes) {
					logAt(WARN, "⚠️ Validation '%s' WARNING: %s", v.Name, warnMsg)
				} else if len(v.Pass.ExitCodes) > 0 && matchCode(res.ExitCode, v.Pass.ExitCodes) {
					logAt(INFO, "✅ Validation '%s' PASSED: %s", v.Name, passMsg)
				} else if len(v.Fail.ExitCodes) > 0 && matchCode(res.ExitCode, v.Fail.ExitCodes) {
					logAt(ERROR, "❌ Validation '%s' FAILED: %s", v.Name, failMsg)
					overallRC = 1
				} else if res.ExitCode == 0 {
					logAt(INFO, "✅ Validation '%s' PASSED: %s", v.Name, passMsg)
				} else {
					logAt(ERROR, "❌ Validation '%s' FAILED: %s", v.Name, failMsg)
					overallRC = 1
				}
			}
		}

		if len(v.Includes) > 0 {
			for _, inc := range v.Includes {
				if !dumpScript {
					prefix := strings.Repeat("  ", depth)
					logAt(INFO, "%s🔗 Including manifest: %s (path: %s)", prefix, inc.Name, inc.Path)
				}

				incPath := inc.Path
				if !strings.HasPrefix(incPath, "http://") && !strings.HasPrefix(incPath, "https://") && !filepath.IsAbs(incPath) {
					manifestDir := "."
					if !strings.HasPrefix(manifestPath, "http://") && !strings.HasPrefix(manifestPath, "https://") {
						if abs, err := filepath.Abs(manifestPath); err == nil {
							manifestDir = filepath.Dir(abs)
						}
					}
					incPath = filepath.Join(manifestDir, incPath)
				}

				incVars := make(map[string]any)
				for k, val := range includeVars {
					incVars[k] = val
				}
				for k, val := range inc.Vars {
					incVars[k] = val
				}

				childCtx := ctx
				if !inc.PropagateTags {
					childCtxCopy := *ctx
					childCtxCopy.FilterTags = nil
					childCtx = &childCtxCopy
				}

				incRC := executeManifest(incPath, incVars, depth+1, childCtx)
				if incRC != 0 {
					overallRC = incRC
				}
			}
		}

		if len(v.Includes) == 0 || strings.TrimSpace(v.Script) != "" {
			fmt.Println()
		}
	}
	return overallRC
}
