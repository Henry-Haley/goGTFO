package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	gtfoBinsAPIURL         = "https://gtfobins.org/api.json"
	maxCatalogResponseSize = 5 << 20
)

type catalog struct {
	Functions   map[string]functionMeta  `json:"functions"`
	Contexts    map[string]contextMeta   `json:"contexts"`
	Executables map[string]executableDef `json:"executables"`
}

type functionMeta struct {
	Label       string                     `json:"label"`
	Description string                     `json:"description"`
	Mitre       []string                   `json:"mitre"`
	Extra       map[string]json.RawMessage `json:"extra"`
}

type contextMeta struct {
	Label       string                     `json:"label"`
	Description string                     `json:"description"`
	Extra       map[string]json.RawMessage `json:"extra"`
}

type executableDef struct {
	Alias     string                  `json:"alias"`
	Comment   string                  `json:"comment"`
	Functions map[string][]exampleDef `json:"functions"`
}

type exampleDef struct {
	Code      string                     `json:"code"`
	Comment   string                     `json:"comment"`
	Version   string                     `json:"version"`
	From      string                     `json:"from"`
	Contexts  map[string]json.RawMessage `json:"contexts"`
	Blind     *bool                      `json:"blind"`
	TTY       *bool                      `json:"tty"`
	Binary    *bool                      `json:"binary"`
	Listener  json.RawMessage            `json:"listener"`
	Connector json.RawMessage            `json:"connector"`
	Sender    json.RawMessage            `json:"sender"`
	Receiver  json.RawMessage            `json:"receiver"`
}

type contextDef struct {
	Code    string   `json:"code"`
	Comment string   `json:"comment"`
	Shell   string   `json:"shell"`
	List    []string `json:"list"`
}

type companionMeta struct {
	Comment string `json:"comment"`
	Code    string `json:"code"`
}

type companionDef struct {
	Reference string
	Inline    *companionMeta
}

type resolutionResult struct {
	Findings []finding
	Warnings []string
}

type finding struct {
	Name              string
	InvocablePath     string
	CanonicalPath     string
	AliasChain        []string
	Comment           string
	Techniques        []technique
	Warnings          []string
	DiscoveryWarnings []string
}

type technique struct {
	TargetExecutable   string
	FunctionKey        string
	FunctionLabel      string
	Description        string
	MitreIDs           []string
	ContextKey         string
	ContextLabel       string
	ContextDescription string
	Code               string
	ExampleComment     string
	ContextComment     string
	Version            string
	ContextShell       string
	ContextList        []string
	Blind              *bool
	TTY                *bool
	Binary             *bool
	Companions         []companionCommand
	InheritanceChain   []string
	Launchers          []launcherStep
	Warnings           []string
	State              applicabilityState
	Evidence           []string
}

type companionCommand struct {
	Role    string
	Comment string
	Code    string
}

type launcherStep struct {
	Executable     string
	ContextKey     string
	Code           string
	ExampleComment string
	ContextComment string
	Version        string
	ContextShell   string
	ContextList    []string
	Blind          *bool
	TTY            *bool
	Binary         *bool
}

type resolvedContext struct {
	Code    string
	Comment string
	Shell   string
	List    []string
}

func decodeCatalog(r io.Reader) (catalog, error) {
	var c catalog
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&c); err != nil {
		return catalog{}, fmt.Errorf("decode catalog: %w", err)
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return catalog{}, fmt.Errorf("decode catalog: trailing JSON value")
		}
		return catalog{}, fmt.Errorf("decode trailing catalog data: %w", err)
	}

	if err := validateCatalog(c); err != nil {
		return catalog{}, fmt.Errorf("validate catalog: %w", err)
	}
	return c, nil
}

func fetchCatalog(ctx context.Context) (catalog, error) {
	return fetchCatalogFrom(ctx, &http.Client{Timeout: 15 * time.Second}, gtfoBinsAPIURL)
}

func fetchCatalogFrom(ctx context.Context, client *http.Client, endpoint string) (catalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return catalog{}, fmt.Errorf("create catalog request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return catalog{}, fmt.Errorf("fetch catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return catalog{}, fmt.Errorf("fetch catalog: unexpected HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCatalogResponseSize+1))
	if err != nil {
		return catalog{}, fmt.Errorf("read catalog response: %w", err)
	}
	if len(body) > maxCatalogResponseSize {
		return catalog{}, fmt.Errorf("read catalog response: body exceeds %d-byte limit", maxCatalogResponseSize)
	}

	return decodeCatalog(bytes.NewReader(body))
}

func sanitizeTerminalText(text string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || unicode.IsPrint(r) {
			return r
		}
		return -1
	}, text)
}

func validateCatalog(c catalog) error {
	sections := []struct {
		name    string
		missing bool
		empty   bool
	}{
		{"functions", c.Functions == nil, len(c.Functions) == 0},
		{"contexts", c.Contexts == nil, len(c.Contexts) == 0},
		{"executables", c.Executables == nil, len(c.Executables) == 0},
	}
	for _, section := range sections {
		if section.missing {
			return fmt.Errorf("catalog %s section is missing", section.name)
		}
		if section.empty {
			return fmt.Errorf("catalog %s section is empty", section.name)
		}
	}

	for name := range c.Executables {
		switch {
		case name == "":
			return fmt.Errorf("invalid executable name: name is empty")
		case strings.ContainsRune(name, '\x00'):
			return fmt.Errorf("invalid executable name %q: contains NUL", name)
		case strings.ContainsRune(name, '/'):
			return fmt.Errorf("invalid executable name %q: contains slash", name)
		case name == "." || name == "..":
			return fmt.Errorf("invalid executable name %q: dot path is not allowed", name)
		}
	}
	return nil
}

func decodeContext(raw json.RawMessage) (*contextDef, error) {
	data := bytes.TrimSpace(raw)
	if bytes.Equal(data, []byte("null")) {
		return nil, nil
	}
	if len(data) == 0 || data[0] != '{' {
		return nil, fmt.Errorf("context value must be null or an object")
	}
	var value contextDef
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("decode context object: %w", err)
	}
	return &value, nil
}

func decodeCompanion(raw json.RawMessage) (companionDef, error) {
	data := bytes.TrimSpace(raw)
	if len(data) == 0 {
		return companionDef{}, nil
	}

	switch data[0] {
	case '"':
		var reference string
		if err := json.Unmarshal(data, &reference); err != nil {
			return companionDef{}, fmt.Errorf("decode companion reference: %w", err)
		}
		return companionDef{Reference: reference}, nil
	case '{':
		var inline companionMeta
		if err := json.Unmarshal(data, &inline); err != nil {
			return companionDef{}, fmt.Errorf("decode inline companion: %w", err)
		}
		return companionDef{Inline: &inline}, nil
	default:
		return companionDef{}, fmt.Errorf("companion value must be a string reference or an object")
	}
}

func resolveCatalog(c catalog) resolutionResult {
	var result resolutionResult
	for _, name := range slices.Sorted(maps.Keys(c.Executables)) {
		f := finding{Name: name}
		targetName, target, aliasChain, err := resolveAlias(c, name)
		if err != nil {
			f.Warnings = []string{fmt.Sprintf("catalog executable %q: %v", name, err)}
			result.Findings = append(result.Findings, f)
			result.Warnings = append(result.Warnings, f.Warnings...)
			continue
		}

		if len(aliasChain) > 1 {
			f.AliasChain = aliasChain
		}
		f.Comment = target.Comment
		f.Techniques, f.Warnings = resolveExecutable(c, name, targetName, target, map[string]bool{})
		f.Techniques = deduplicateTechniques(name, f.Techniques)
		f.Warnings = sortedUniqueStrings(f.Warnings)
		result.Findings = append(result.Findings, f)
		result.Warnings = append(result.Warnings, f.Warnings...)
		for _, technique := range f.Techniques {
			result.Warnings = append(result.Warnings, technique.Warnings...)
		}
	}
	result.Warnings = sortedUniqueStrings(result.Warnings)
	return result
}

func resolveAlias(c catalog, name string) (string, executableDef, []string, error) {
	visited := make(map[string]bool)
	var chain []string
	for current := name; ; {
		if visited[current] {
			return "", executableDef{}, chain, fmt.Errorf("alias cycle reaches %q", current)
		}
		entry, ok := c.Executables[current]
		if !ok {
			return "", executableDef{}, chain, fmt.Errorf("alias target %q is missing", current)
		}
		visited[current] = true
		chain = append(chain, current)
		if entry.Alias == "" {
			return current, entry, chain, nil
		}
		current = entry.Alias
	}
}

func resolveExecutable(c catalog, originalName, executableName string, entry executableDef, visited map[string]bool) ([]technique, []string) {
	var techniques []technique
	var warnings []string

	for _, functionKey := range slices.Sorted(maps.Keys(entry.Functions)) {
		if functionKey == "inherit" {
			continue
		}
		for _, example := range entry.Functions[functionKey] {
			for _, contextKey := range slices.Sorted(maps.Keys(example.Contexts)) {
				value, err := normalizeTechnique(c, originalName, executableName, functionKey, contextKey, example)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("catalog executable %q function %q context %q: %v", originalName, functionKey, contextKey, err))
					continue
				}
				techniques = append(techniques, value)
			}
		}
	}

	inheritExamples := entry.Functions["inherit"]
	if len(inheritExamples) == 0 {
		return techniques, warnings
	}

	visitKey := executableName + "\x00inherit"
	if visited[visitKey] {
		return techniques, append(warnings, fmt.Sprintf("catalog executable %q: inheritance cycle at executable %q function %q", originalName, executableName, "inherit"))
	}
	visited[visitKey] = true
	defer delete(visited, visitKey)

	for _, example := range inheritExamples {
		if example.From == "" {
			warnings = append(warnings, fmt.Sprintf("catalog executable %q function %q in %q has an empty inheritance source", originalName, "inherit", executableName))
			continue
		}

		targetName, target, aliasChain, err := resolveAlias(c, example.From)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("catalog executable %q function %q in %q cannot resolve source %q: %v", originalName, "inherit", executableName, example.From, err))
			continue
		}

		launchers := make(map[string]launcherStep)
		for _, contextKey := range slices.Sorted(maps.Keys(example.Contexts)) {
			context, err := resolveExampleContext(example, example.Contexts[contextKey])
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("catalog executable %q function %q context %q in %q: %v", originalName, "inherit", contextKey, executableName, err))
				continue
			}
			launchers[contextKey] = launcherStep{
				Executable:     executableName,
				ContextKey:     contextKey,
				Code:           context.Code,
				ExampleComment: example.Comment,
				ContextComment: context.Comment,
				Version:        example.Version,
				ContextShell:   context.Shell,
				ContextList:    append([]string(nil), context.List...),
				Blind:          example.Blind,
				TTY:            example.TTY,
				Binary:         example.Binary,
			}
		}

		targetTechniques, targetWarnings := resolveExecutable(c, originalName, targetName, target, visited)
		warnings = append(warnings, targetWarnings...)
		for _, targetTechnique := range targetTechniques {
			launcher, ok := launchers[targetTechnique.ContextKey]
			if !ok {
				continue
			}

			resolved := targetTechnique
			resolved.Launchers = append([]launcherStep{launcher}, targetTechnique.Launchers...)
			chain := targetTechnique.InheritanceChain
			if len(chain) == 0 {
				chain = []string{targetTechnique.TargetExecutable}
			}
			if len(aliasChain) > 1 {
				chain = append(append([]string(nil), aliasChain[:len(aliasChain)-1]...), chain...)
			}
			resolved.InheritanceChain = append([]string{executableName}, chain...)
			techniques = append(techniques, resolved)
		}
	}

	return techniques, warnings
}

func normalizeTechnique(c catalog, originalName, executableName, functionKey, contextKey string, example exampleDef) (technique, error) {
	context, err := resolveExampleContext(example, example.Contexts[contextKey])
	if err != nil {
		return technique{}, err
	}

	function := c.Functions[functionKey]
	functionLabel := function.Label
	if strings.TrimSpace(functionLabel) == "" {
		functionLabel = functionKey
	}
	contextMeta := c.Contexts[contextKey]
	contextLabel := contextMeta.Label
	if strings.TrimSpace(contextLabel) == "" {
		contextLabel = contextKey
	}

	companions, warnings := resolveCompanions(function, example, originalName, functionKey, contextKey)
	return technique{
		TargetExecutable:   executableName,
		FunctionKey:        functionKey,
		FunctionLabel:      functionLabel,
		Description:        function.Description,
		MitreIDs:           append([]string(nil), function.Mitre...),
		ContextKey:         contextKey,
		ContextLabel:       contextLabel,
		ContextDescription: contextMeta.Description,
		Code:               context.Code,
		ExampleComment:     example.Comment,
		ContextComment:     context.Comment,
		Version:            example.Version,
		ContextShell:       context.Shell,
		ContextList:        append([]string(nil), context.List...),
		Blind:              example.Blind,
		TTY:                example.TTY,
		Binary:             example.Binary,
		Companions:         companions,
		Warnings:           warnings,
	}, nil
}

func resolveExampleContext(example exampleDef, raw json.RawMessage) (resolvedContext, error) {
	result := resolvedContext{Code: example.Code}
	context, err := decodeContext(raw)
	if err != nil {
		return resolvedContext{}, err
	}
	if context == nil {
		return result, nil
	}
	if context.Code != "" {
		result.Code = context.Code
	}
	result.Comment = context.Comment
	result.Shell = context.Shell
	result.List = append([]string(nil), context.List...)
	return result, nil
}

func resolveCompanions(function functionMeta, example exampleDef, executableName, functionKey, contextKey string) ([]companionCommand, []string) {
	roles := []struct {
		name string
		raw  json.RawMessage
	}{
		{"listener", example.Listener},
		{"connector", example.Connector},
		{"sender", example.Sender},
		{"receiver", example.Receiver},
	}

	var companions []companionCommand
	var warnings []string
	for _, role := range roles {
		if len(bytes.TrimSpace(role.raw)) == 0 {
			continue
		}

		definition, err := decodeCompanion(role.raw)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("catalog executable %q function %q context %q has malformed %s companion: %v", executableName, functionKey, contextKey, role.name, err))
			continue
		}

		var value *companionMeta
		if definition.Reference != "" {
			raw, ok := function.Extra[definition.Reference]
			if !ok {
				warnings = append(warnings, fmt.Sprintf("catalog executable %q function %q context %q companion %s reference %q is missing", executableName, functionKey, contextKey, role.name, definition.Reference))
				continue
			}
			referenced, err := decodeCompanion(raw)
			if err != nil || referenced.Inline == nil {
				warnings = append(warnings, fmt.Sprintf("catalog executable %q function %q context %q companion %s reference %q is malformed", executableName, functionKey, contextKey, role.name, definition.Reference))
				continue
			}
			value = referenced.Inline
		} else {
			value = definition.Inline
		}
		if value == nil {
			warnings = append(warnings, fmt.Sprintf("catalog executable %q function %q context %q has malformed %s companion", executableName, functionKey, contextKey, role.name))
			continue
		}
		companions = append(companions, companionCommand{Role: role.name, Comment: value.Comment, Code: value.Code})
	}
	return companions, warnings
}

func deduplicateTechniques(name string, techniques []technique) []technique {
	type identity struct {
		name        string
		functionKey string
		contextKey  string
		code        string
		inheritance string
	}

	seen := make(map[identity]bool)
	result := make([]technique, 0, len(techniques))
	for _, technique := range techniques {
		key := identity{
			name:        name,
			functionKey: technique.FunctionKey,
			contextKey:  technique.ContextKey,
			code:        technique.Code,
			inheritance: strings.Join(technique.InheritanceChain, "\x00"),
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, technique)
	}
	return result
}

func sortedUniqueStrings(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}
