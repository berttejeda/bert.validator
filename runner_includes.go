package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/expr-lang/expr"
	"gopkg.in/yaml.v3"
)

type summaryResult struct {
	ExecDisplay  string
	ValidationID string
	Name         string
	Status       string // PASS, FAIL, WARN, SKIP
}

type runContext struct {
	NameRe          *regexp.Regexp
	FilterTags      []string
	GlobalExtraVars map[string]any
	ExecPrefix      string
	ShowFilter      string
	Results         []summaryResult
	mu              sync.Mutex
}

func matchesShowFilter(filter, validationID, name string) bool {
	if filter == "" {
		return false
	}
	if validationID == filter {
		return true
	}
	if strings.Contains(strings.ToLower(name), strings.ToLower(filter)) {
		return true
	}
	if re, err := regexp.Compile("(?i)" + filter); err == nil {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// parseTagFilter splits a tag filter into base tag and optional loop qualifier.
// e.g. "other@loop1" → ("other", "loop1"), "system" → ("system", "")
func parseTagFilter(filter string) (baseTag, loopTag string) {
	if idx := strings.Index(filter, "@"); idx >= 0 {
		return filter[:idx], filter[idx+1:]
	}
	return filter, ""
}

// matchValidationTags checks if a validation's tags match any of the filter tags.
// Returns: (matched bool, loopTagFilters []string)
// loopTagFilters contains any loop-specific qualifiers that were matched.
func matchValidationTags(validationTags []string, filterTags []string) (bool, []string) {
	if len(filterTags) == 0 {
		return true, nil
	}
	matched := false
	var loopFilters []string
	for _, ft := range filterTags {
		baseTag, loopTag := parseTagFilter(ft)
		for _, vt := range validationTags {
			if vt == baseTag {
				matched = true
				if loopTag != "" {
					loopFilters = append(loopFilters, loopTag)
				}
				break
			}
		}
	}
	return matched, loopFilters
}

// shouldRunLoopItem checks whether a specific loop iteration should execute
// given the active loop tag filters. If no loop filters are active, all items run.
// If loop filters are active, only items with matching tags run.
func shouldRunLoopItem(item loopItem, loopFilters []string) bool {
	if len(loopFilters) == 0 {
		return true
	}
	for _, lf := range loopFilters {
		for _, it := range item.Tags {
			if it == lf {
				return true
			}
		}
	}
	return false
}

func (ctx *runContext) addResult(execDisplay, validationID, name, status string) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.Results = append(ctx.Results, summaryResult{ExecDisplay: execDisplay, ValidationID: validationID, Name: name, Status: status})
}

func evaluateConditions(conditions []condition, ctx *runContext) (bool, error) {
	env := map[string]any{
		"no_tags": func() bool {
			return len(ctx.FilterTags) == 0
		},
		"env": os.Getenv,
		"file_exists": func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
		"GOOS":   runtime.GOOS,
		"GOARCH": runtime.GOARCH,
	}

	for _, c := range conditions {
		if c.Eval == "" {
			continue
		}
		result, err := expr.Eval(c.Eval, env)
		if err != nil {
			return false, fmt.Errorf("condition %q: %w", c.Eval, err)
		}
		b, ok := result.(bool)
		if !ok {
			return false, fmt.Errorf("condition %q: expected bool, got %T", c.Eval, result)
		}
		if !b {
			return false, nil
		}
	}
	return true, nil
}

func listManifestValidations(manifestPath string, includeVars map[string]any, depth int) {
	yamlTemplateData, err := loadManifest(manifestPath)
	if err != nil {
		logAt(ERROR, "Failed to load manifest: %v", err)
		return
	}
	emptyMap := make(map[string]string)

	if yamlTemplateData.TemplateVars == nil {
		yamlTemplateData.TemplateVars = make(map[string]any)
	}
	for k, val := range includeVars {
		yamlTemplateData.TemplateVars[k] = val
	}

	env := envMap()
	initialTmplCtx := buildTemplateContext(emptyMap, yamlTemplateData.TemplateVars, env)
	tmpl, err := template.New(manifestPath).
		Funcs(sprig.FuncMap()).
		Option("missingkey=default").
		Parse(yamlTemplateData.Content)
	if err != nil {
		logAt(ERROR, "Error parsing template: %v", err)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, initialTmplCtx); err != nil {
		logAt(ERROR, "Error executing template: %v", err)
		return
	}

	var root yaml.Node
	if err := yaml.Unmarshal(buf.Bytes(), &root); err != nil {
		logAt(ERROR, "Failed to parse YAML: %v", err)
		return
	}

	_, _, _, validations, err := parseManifest(&root)
	if err != nil {
		logAt(ERROR, "Invalid manifest: %v", err)
		return
	}

	prefix := strings.Repeat("  ", depth)
	if depth == 0 {
		fmt.Println("--- Validation List ---")
	}

	for _, v := range validations {
		tags := ""
		if len(v.Tags) > 0 {
			tags = " tags=[" + strings.Join(v.Tags, ", ") + "]"
		}
		conditions := ""
		if len(v.Conditions) > 0 {
			conditions = fmt.Sprintf(" conditions=%d", len(v.Conditions))
		}
		loopInfo := ""
		if len(v.Loop) > 0 {
			loopInfo = fmt.Sprintf(" loop=%d", len(v.Loop))
		}
		fmt.Printf("%sValidation #%-2d [%s] %s%s%s%s\n", prefix, v.ExecNumber, v.ValidationID, v.Name, tags, conditions, loopInfo)

		for i, li := range v.Loop {
			loopTags := ""
			if len(li.Tags) > 0 {
				loopTags = " tags=[" + strings.Join(li.Tags, ", ") + "]"
			}
			loopVars := ""
			if len(li.Vars) > 0 {
				loopVars = fmt.Sprintf(" vars=%d", len(li.Vars))
			}
			name := li.Name
			if name == "" {
				name = fmt.Sprintf("loop %d", i+1)
			}
			fmt.Printf("%s  🔄 %s%s%s\n", prefix, name, loopTags, loopVars)
		}

		for _, inc := range v.Includes {
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
			fmt.Printf("%s  └─ include: %s (path: %s)\n", prefix, inc.Name, inc.Path)
			listManifestValidations(incPath, incVars, depth+1)
		}
	}
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
	if !dumpScript && ctx.ShowFilter == "" && depth == 0 {
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

		var loopFilters []string
		if len(ctx.FilterTags) > 0 {
			logAt(DEBUG, "Checking tags for %s: %v against filter %v", v.Name, v.Tags, ctx.FilterTags)
			matched, lf := matchValidationTags(v.Tags, ctx.FilterTags)
			if !matched {
				continue
			}
			loopFilters = lf
		}

		if len(v.Conditions) > 0 {
			ok, err := evaluateConditions(v.Conditions, ctx)
			if err != nil {
				execDisp := fmt.Sprintf("%s%d", ctx.ExecPrefix, v.ExecNumber)
				if !dumpScript && ctx.ShowFilter == "" {
					logAt(ERROR, "⚠ Condition error for '#%s %s %s': %v", execDisp, v.ValidationID, v.Name, err)
					overallRC = 1
					ctx.addResult(execDisp, v.ValidationID, v.Name, "FAIL")
					fmt.Println()
				} else if dumpScript {
					fmt.Printf("\n# --- [%s] SKIPPED (condition error: %v) ---\n", v.Name, err)
				}
				continue
			}
			if !ok {
				if !dumpScript && ctx.ShowFilter == "" {
					execDisp := fmt.Sprintf("%s%d", ctx.ExecPrefix, v.ExecNumber)
					logAt(INFO, "⏭️  Skipped '#%s %s %s': condition not met", execDisp, v.ValidationID, v.Name)
					ctx.addResult(execDisp, v.ValidationID, v.Name, "SKIP")
					fmt.Println()
				} else if dumpScript {
					fmt.Printf("\n# --- [%s] SKIPPED (condition not met) ---\n", v.Name)
				}
				continue
			}
		}

		// Build list of iterations: if loop is defined, iterate; otherwise single pass with nil item.
		type iteration struct {
			item  *loopItem
			index int
		}
		var iterations []iteration
		if len(v.Loop) > 0 {
			for i := range v.Loop {
				if shouldRunLoopItem(v.Loop[i], loopFilters) {
					iterations = append(iterations, iteration{item: &v.Loop[i], index: i})
				}
			}
			if len(iterations) == 0 {
				// All loop items were filtered out
				continue
			}
		} else {
			iterations = []iteration{{item: nil, index: 0}}
		}

		for _, iter := range iterations {
			// Compute display name for this iteration
			iterName := v.Name
			iterSuffix := ""
			if iter.item != nil {
				if iter.item.Name != "" {
					iterSuffix = " [" + iter.item.Name + "]"
				} else {
					iterSuffix = fmt.Sprintf(" [loop %d]", iter.index+1)
				}
				iterName = v.Name + iterSuffix
			}

			// Compute the exec display string, including @LoopName for loop iterations
			baseExecDisp := fmt.Sprintf("%s%d", ctx.ExecPrefix, v.ExecNumber)
			iterExecDisp := baseExecDisp
			if iter.item != nil {
				loopLabel := iter.item.Name
				if loopLabel == "" {
					loopLabel = fmt.Sprintf("loop %d", iter.index+1)
				}
				iterExecDisp = baseExecDisp + "@" + loopLabel
			}

			if !dumpScript && ctx.ShowFilter == "" {
				prefix := ""
				if depth > 0 {
					prefix = strings.Repeat("  ", depth)
				}
				if iter.item != nil {
					logAt(INFO, "%s▶ [#%s %s] Running validation: %s", prefix, iterExecDisp, v.ValidationID, iterName)
				} else {
					logAt(INFO, "%s▶ [#%s %s] Running validation: %s", prefix, iterExecDisp, v.ValidationID, v.Name)
				}
			}

			// Merge loop-level vars into the validation's local vars
			iterLocalVarsOrdered := v.LocalVarsOrdered
			if iter.item != nil && len(iter.item.Vars) > 0 {
				// Convert loop vars to kv pairs and merge (loop overrides local)
				var loopKVs []kv
				for k, val := range iter.item.Vars {
					switch sv := val.(type) {
					case string:
						loopKVs = append(loopKVs, kv{Key: k, Value: sv})
					default:
						loopKVs = append(loopKVs, kv{Key: k, Value: fmt.Sprintf("%v", sv)})
					}
				}
				// Start with validation locals, then override with loop vars
				merged := make([]kv, 0, len(v.LocalVarsOrdered)+len(loopKVs))
				merged = append(merged, v.LocalVarsOrdered...)
				for _, lkv := range loopKVs {
					found := false
					for i, existing := range merged {
						if existing.Key == lkv.Key {
							merged[i].Value = lkv.Value
							found = true
							break
						}
					}
					if !found {
						merged = append(merged, lkv)
					}
				}
				iterLocalVarsOrdered = merged
			}

			// Use a fresh copy of the script for each iteration to avoid double-prepending functions
			iterScript := v.Script

			if strings.TrimSpace(iterScript) == "" {
				if len(v.Includes) == 0 {
					logAt(WARN, "⚠ Skipped '%s': empty script.", iterName)
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
						iterScript = sb.String() + iterScript
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

				// Inject LOOP_NAME and LOOP_INDEX for scripts to reference
				if iter.item != nil {
					base = append(base, kv{Key: "LOOP_NAME", Value: iter.item.Name})
					base = append(base, kv{Key: "LOOP_INDEX", Value: fmt.Sprintf("%d", iter.index)})
				}

				// Inject includeVars as shell variables (parent vars propagated to child)
				includeVarsOrdered := []kv{}
				for k, val := range includeVars {
					includeVarsOrdered = append(includeVarsOrdered, kv{Key: k, Value: fmt.Sprintf("%v", val)})
				}
				mergedBI, _ := mergeVars(base, includeVarsOrdered)
				mergedBG, _ := mergeVars(mergedBI, globalOrdered)
				mergedList, mergedMap := mergeVars(mergedBG, iterLocalVarsOrdered)

				if !dumpScript {
					logAt(DEBUG, "[%s] Merged vars: %v", iterName, mergedMap)
				}

				templatesAny := make(map[string]any, len(tplMap))
				for k, vTpl := range tplMap {
					templatesAny[k] = vTpl
				}

				tmplCtx := buildTemplateContext(mergedMap, templatesAny, env)

				scriptTemplated, err := renderTemplate(iterName+"_script", iterScript, tmplCtx)
				if err != nil {
					logAt(ERROR, "[%s] Template error in script: %v", iterName, err)
					overallRC = 1
					fmt.Println()
					continue
				}
				iterScript = scriptTemplated

				// Template outcome messages (use copies to avoid mutating original across iterations)
				passMsg := v.Pass.Message
				failMsg := v.Fail.Message
				warnMsg := v.Warn.Message

				if passMsg != "" {
					if t, err := renderTemplate(iterName+"_pass", passMsg, tmplCtx); err == nil {
						passMsg = t
					} else {
						logAt(ERROR, "[%s] Template error in pass message: %v", iterName, err)
						overallRC = 1
						fmt.Println()
						continue
					}
				}
				if failMsg != "" {
					if t, err := renderTemplate(iterName+"_fail", failMsg, tmplCtx); err == nil {
						failMsg = t
					} else {
						logAt(ERROR, "[%s] Template error in fail message: %v", iterName, err)
						overallRC = 1
						fmt.Println()
						continue
					}
				}
				if warnMsg != "" {
					if t, err := renderTemplate(iterName+"_warn", warnMsg, tmplCtx); err == nil {
						warnMsg = t
					} else {
						logAt(ERROR, "[%s] Template error in warn message: %v", iterName, err)
						overallRC = 1
						fmt.Println()
						continue
					}
				}

				finalScript := iterScript
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

				if ctx.ShowFilter != "" {
					if matchesShowFilter(ctx.ShowFilter, v.ValidationID, iterName) || matchesShowFilter(ctx.ShowFilter, v.ValidationID, v.Name) {
						fmt.Printf("--- Validation #%s [%s] %s ---\n", iterExecDisp, v.ValidationID, iterName)
						if len(v.Tags) > 0 {
							fmt.Printf("Tags:       %s\n", strings.Join(v.Tags, ", "))
						}
						if iter.item != nil && len(iter.item.Tags) > 0 {
							fmt.Printf("Loop Tags:  %s\n", strings.Join(iter.item.Tags, ", "))
						}
						if len(v.Conditions) > 0 {
							fmt.Printf("Conditions: %d\n", len(v.Conditions))
							for _, c := range v.Conditions {
								fmt.Printf("  - eval: %s\n", c.Eval)
							}
						}
						if passMsg != "" {
							fmt.Printf("Pass:       %s\n", passMsg)
						}
						if failMsg != "" {
							fmt.Printf("Fail:       %s\n", failMsg)
						}
						if warnMsg != "" {
							fmt.Printf("Warn:       %s\n", warnMsg)
						}
						fmt.Printf("\n%s\n", finalScript)
					}
					continue
				}

				if dumpScript {
					fmt.Printf("\n# --- [%s] ---\n%s\n", iterName, finalScript)
				} else if level == DEBUG {
					logAt(DEBUG, "\n--- [%s] FINAL SCRIPT ---\n%s\n--- end ---", iterName, finalScript)
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
							iterName, !useColor,
						)
					} else {
						var stopProgress func()
						if level != DEBUG {
							stopProgress = startProgress(iterName)
						} else {
							stopProgress = startProgress(iterName)
						}

						res, err = runWithInterpreter(interpPath, flags, finalScript, extraEnv, kind)

						if stopProgress != nil {
							stopProgress()
						}
					}

					if err != nil {
						logAt(ERROR, "[%s] Execution error: %v", iterName, err)
						overallRC = 1
						fmt.Println()
						continue
					}

					renderedPassMsg := renderMsg(passMsg, mergedMap)
					renderedFailMsg := renderMsg(failMsg, mergedMap)
					renderedWarnMsg := renderMsg(warnMsg, mergedMap)

					matchCode := func(code int, codes []int) bool {
						for _, c := range codes {
							if c == code {
								return true
							}
						}
						return false
					}

					if len(v.Warn.ExitCodes) > 0 && matchCode(res.ExitCode, v.Warn.ExitCodes) {
						logAt(WARN, "⚠️ Validation '#%s %s %s' WARNING: %s", iterExecDisp, v.ValidationID, iterName, renderedWarnMsg)
						ctx.addResult(iterExecDisp, v.ValidationID, iterName, "WARN")
					} else if len(v.Pass.ExitCodes) > 0 && matchCode(res.ExitCode, v.Pass.ExitCodes) {
						logAt(INFO, "✅ Validation '#%s %s %s' PASSED: %s", iterExecDisp, v.ValidationID, iterName, renderedPassMsg)
						ctx.addResult(iterExecDisp, v.ValidationID, iterName, "PASS")
					} else if len(v.Fail.ExitCodes) > 0 && matchCode(res.ExitCode, v.Fail.ExitCodes) {
						logAt(ERROR, "❌ Validation '#%s %s %s' FAILED: %s", iterExecDisp, v.ValidationID, iterName, renderedFailMsg)
						overallRC = 1
						ctx.addResult(iterExecDisp, v.ValidationID, iterName, "FAIL")
					} else if res.ExitCode == 0 {
						logAt(INFO, "✅ Validation '#%s %s %s' PASSED: %s", iterExecDisp, v.ValidationID, iterName, renderedPassMsg)
						ctx.addResult(iterExecDisp, v.ValidationID, iterName, "PASS")
					} else {
						logAt(ERROR, "❌ Validation '#%s %s %s' FAILED: %s", iterExecDisp, v.ValidationID, iterName, renderedFailMsg)
						overallRC = 1
						ctx.addResult(iterExecDisp, v.ValidationID, iterName, "FAIL")
					}
				}
			}

			if len(v.Includes) > 0 {
				for _, inc := range v.Includes {
					if !dumpScript && ctx.ShowFilter == "" {
						prefix := strings.Repeat("  ", depth)
						if iter.item != nil {
							logAt(INFO, "%s🔗 Including manifest: %s (path: %s)%s", prefix, inc.Name, inc.Path, iterSuffix)
						} else {
							logAt(INFO, "%s🔗 Including manifest: %s (path: %s)", prefix, inc.Name, inc.Path)
						}
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
					// Parent manifest's global vars at lowest precedence
					for _, gv := range globalOrdered {
						incVars[gv.Key] = gv.Value
					}
					for k, val := range includeVars {
						incVars[k] = val
					}
					for k, val := range inc.Vars {
						incVars[k] = val
					}
					// Loop-level vars override include vars
					if iter.item != nil {
						for k, val := range iter.item.Vars {
							incVars[k] = val
						}
					}

					childCtx := ctx
					if !inc.PropagateTags {
						childCtx = &runContext{
							NameRe:          ctx.NameRe,
							FilterTags:      nil,
							GlobalExtraVars: ctx.GlobalExtraVars,
							ExecPrefix:      iterExecDisp + ".",
							ShowFilter:      ctx.ShowFilter,
							Results:         ctx.Results,
						}
					} else {
						childCtx = &runContext{
							NameRe:          ctx.NameRe,
							FilterTags:      ctx.FilterTags,
							GlobalExtraVars: ctx.GlobalExtraVars,
							ExecPrefix:      iterExecDisp + ".",
							ShowFilter:      ctx.ShowFilter,
							Results:         ctx.Results,
						}
					}

					incRC := executeManifest(incPath, incVars, depth+1, childCtx)
					if incRC != 0 {
						overallRC = incRC
					}

					if childCtx != ctx {
						ctx.mu.Lock()
						ctx.Results = childCtx.Results
						ctx.mu.Unlock()
					}
				}
			}

			if len(v.Includes) == 0 || strings.TrimSpace(iterScript) != "" {
				fmt.Println()
			}
		}
	}
	return overallRC
}
