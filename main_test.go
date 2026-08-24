package main

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode"

	"golang.org/x/sys/unix"
)

func TestDecodeCatalogFixture(t *testing.T) {
	f, err := os.Open("testdata/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	c, err := decodeCatalog(f)
	if err != nil {
		t.Fatal(err)
	}

	meta, ok := c.Functions["command"]
	if !ok || len(meta.Mitre) != 2 || meta.Mitre[0] != "T0001" || meta.Mitre[1] != "T0002" {
		t.Fatalf("multiple MITRE IDs were not preserved: %#v", meta.Mitre)
	}
	if _, ok := c.Functions["fixture-unknown"]; !ok {
		t.Fatal("unknown function was not retained")
	}
	if _, ok := c.Contexts["fixture-context"]; !ok {
		t.Fatal("unknown context was not retained")
	}

	tool := c.Executables["fixture-tool"]
	if tool.Comment == "" {
		t.Fatal("executable comment was not preserved")
	}
	examples := tool.Functions["command"]
	if len(examples) != 1 {
		t.Fatalf("command examples = %d, want 1", len(examples))
	}
	example := examples[0]
	if example.Version != "fixture-version <= 1" {
		t.Fatalf("version = %q", example.Version)
	}
	for _, context := range []string{"unprivileged", "sudo", "suid", "capabilities", "fixture-context"} {
		if _, ok := example.Contexts[context]; !ok {
			t.Errorf("fixture context %q is missing", context)
		}
	}
	if example.Blind == nil || *example.Blind || example.TTY == nil || !*example.TTY || example.Binary == nil || *example.Binary {
		t.Fatalf("explicit boolean values were not preserved: blind=%v tty=%v binary=%v", example.Blind, example.TTY, example.Binary)
	}

	if value, err := decodeContext(example.Contexts["unprivileged"]); err != nil || value != nil {
		t.Fatalf("null context = %#v, %v", value, err)
	}
	sudo, err := decodeContext(example.Contexts["sudo"])
	if err != nil || sudo.Code != "fixture-command --sudo-example" || sudo.Comment == "" {
		t.Fatalf("sudo override = %#v, %v", sudo, err)
	}
	capabilities, err := decodeContext(example.Contexts["capabilities"])
	if err != nil || len(capabilities.List) != 1 || capabilities.List[0] != "CAP_FIXTURE" {
		t.Fatalf("capability list = %#v, %v", capabilities, err)
	}

	listener, err := decodeCompanion(example.Listener)
	if err != nil || listener.Reference != "fixture-listener" || listener.Inline != nil {
		t.Fatalf("listener = %#v, %v", listener, err)
	}
	connector, err := decodeCompanion(example.Connector)
	if err != nil || connector.Inline == nil || connector.Inline.Code != "echo fixture" {
		t.Fatalf("connector = %#v, %v", connector, err)
	}

	if got := c.Executables["fixture-alias"].Alias; got != "fixture-tool" {
		t.Fatalf("one-hop alias = %q", got)
	}
	if got := c.Executables["fixture-alias-two"].Alias; got != "fixture-alias" {
		t.Fatalf("two-hop alias = %q", got)
	}
	if got := c.Executables["fixture-parent"].Functions["inherit"][0].From; got != "fixture-tool" {
		t.Fatalf("one-hop inheritance = %q", got)
	}
	if got := c.Executables["fixture-grandparent"].Functions["inherit"][0].From; got != "fixture-parent" {
		t.Fatalf("two-hop inheritance = %q", got)
	}
}

func TestResolveCatalogFixture(t *testing.T) {
	c := loadFixtureCatalog(t)
	result := resolveCatalog(c)
	if len(result.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", result.Warnings)
	}

	tool := findingNamed(t, result, "fixture-tool")
	if tool.Comment != "Synthetic executable used only by tests." {
		t.Fatalf("executable comment = %q", tool.Comment)
	}
	base := techniqueNamed(t, tool, "command", "unprivileged")
	if base.Code != "fixture-command --example" || base.ExampleComment != "Harmless placeholder example." || base.ContextComment != "" {
		t.Fatalf("direct technique lost command or comments: %#v", base)
	}
	if base.Version != "fixture-version <= 1" || !reflect.DeepEqual(base.MitreIDs, []string{"T0001", "T0002"}) {
		t.Fatalf("version/MITRE metadata = %q/%v", base.Version, base.MitreIDs)
	}
	if base.Blind == nil || *base.Blind || base.TTY == nil || !*base.TTY || base.Binary == nil || *base.Binary {
		t.Fatalf("explicit booleans were not preserved: blind=%v tty=%v binary=%v", base.Blind, base.TTY, base.Binary)
	}
	if len(base.Companions) != 2 || base.Companions[0].Role != "listener" || base.Companions[0].Comment != "Synthetic shared companion." || base.Companions[0].Code != "echo fixture" || base.Companions[1].Role != "connector" {
		t.Fatalf("companions = %#v", base.Companions)
	}
	if strings.Contains(base.Code, base.Companions[0].Code) {
		t.Fatalf("companion code was concatenated with primary code: %q", base.Code)
	}

	sudo := techniqueNamed(t, tool, "command", "sudo")
	if sudo.Code != "fixture-command --sudo-example" || sudo.ExampleComment == "" || sudo.ContextComment != "Synthetic context-specific override." {
		t.Fatalf("context override = %#v", sudo)
	}
	suid := techniqueNamed(t, tool, "command", "suid")
	if suid.Code != "fixture-command --example" || suid.ContextShell == nil || !*suid.ContextShell {
		t.Fatalf("SUID context = %#v", suid)
	}
	capabilities := techniqueNamed(t, tool, "command", "capabilities")
	if !reflect.DeepEqual(capabilities.ContextList, []string{"CAP_FIXTURE"}) {
		t.Fatalf("capability list = %v", capabilities.ContextList)
	}
	unknownContext := techniqueNamed(t, tool, "command", "fixture-context")
	if unknownContext.ContextKey == "unprivileged" || unknownContext.ContextLabel != "Unknown fixture context" || unknownContext.ContextDescription == "" {
		t.Fatalf("unknown context was remapped: %#v", unknownContext)
	}
	unknownFunction := techniqueNamed(t, tool, "fixture-unknown", "unprivileged")
	if unknownFunction.FunctionLabel != "Unknown fixture function" {
		t.Fatalf("unknown function metadata was lost: %#v", unknownFunction)
	}

	alias := findingNamed(t, result, "fixture-alias")
	if alias.Name != "fixture-alias" || !reflect.DeepEqual(alias.AliasChain, []string{"fixture-alias", "fixture-tool"}) {
		t.Fatalf("one-hop alias = %#v", alias.AliasChain)
	}
	aliasTechnique := techniqueNamed(t, alias, "command", "unprivileged")
	if aliasTechnique.TargetExecutable != "fixture-tool" || aliasTechnique.Code != "fixture-command --example" || aliasTechnique.FunctionLabel != "Fixture command" {
		t.Fatalf("alias target data was rewritten: %#v", aliasTechnique)
	}
	aliasTwo := findingNamed(t, result, "fixture-alias-two")
	if !reflect.DeepEqual(aliasTwo.AliasChain, []string{"fixture-alias-two", "fixture-alias", "fixture-tool"}) {
		t.Fatalf("multi-hop alias chain = %v", aliasTwo.AliasChain)
	}

	parent := findingNamed(t, result, "fixture-parent")
	parentTechnique := techniqueNamed(t, parent, "command", "unprivileged")
	if !reflect.DeepEqual(parentTechnique.InheritanceChain, []string{"fixture-parent", "fixture-tool"}) || len(parentTechnique.Launchers) != 1 {
		t.Fatalf("one-hop inheritance = %#v", parentTechnique)
	}
	if parentTechnique.Launchers[0].Code != "fixture-command --example" || parentTechnique.Code != "fixture-command --example" {
		t.Fatalf("launcher and target were not kept separately: %#v", parentTechnique)
	}
	for _, value := range parent.Techniques {
		if value.ContextKey != "unprivileged" {
			t.Fatalf("context %q escaped launcher/target intersection", value.ContextKey)
		}
	}

	grandparent := findingNamed(t, result, "fixture-grandparent")
	grandTechnique := techniqueNamed(t, grandparent, "command", "unprivileged")
	if !reflect.DeepEqual(grandTechnique.InheritanceChain, []string{"fixture-grandparent", "fixture-parent", "fixture-tool"}) || len(grandTechnique.Launchers) != 2 {
		t.Fatalf("multi-hop inheritance = %#v", grandTechnique)
	}

	if again := resolveCatalog(c); !reflect.DeepEqual(result, again) {
		t.Fatal("repeated resolution produced different ordered output")
	}
}

func TestResolveUnknownMetadataUsesKeyLabels(t *testing.T) {
	c := catalog{
		Functions: map[string]functionMeta{"placeholder": {}},
		Contexts:  map[string]contextMeta{"placeholder": {}},
		Executables: map[string]executableDef{
			"tool": {Functions: map[string][]exampleDef{
				"future-function": {{Code: "future-code", Contexts: map[string]json.RawMessage{"future-context": json.RawMessage("null")}}},
			}},
		},
	}

	value := techniqueNamed(t, findingNamed(t, resolveCatalog(c), "tool"), "future-function", "future-context")
	if value.FunctionLabel != "future-function" || value.ContextLabel != "future-context" || value.ContextKey == "unprivileged" {
		t.Fatalf("fallback labels = %#v", value)
	}
}

func TestResolveAliasFailuresAreLocal(t *testing.T) {
	tests := []struct {
		name        string
		executables map[string]executableDef
		warning     string
	}{
		{
			name: "cycle",
			executables: map[string]executableDef{
				"alias-a": {Alias: "alias-b"},
				"alias-b": {Alias: "alias-a"},
			},
			warning: "alias cycle",
		},
		{
			name: "missing target",
			executables: map[string]executableDef{
				"broken-alias": {Alias: "missing-target"},
			},
			warning: "alias target \"missing-target\" is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.executables["valid"] = executableDef{Functions: map[string][]exampleDef{
				"command": {{Code: "valid-code", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}}},
			}}
			c := basicResolutionCatalog(tt.executables)
			result := resolveCatalog(c)
			if !warningContains(result.Warnings, tt.warning) {
				t.Fatalf("warnings %v do not contain %q", result.Warnings, tt.warning)
			}
			if got := techniqueNamed(t, findingNamed(t, result, "valid"), "command", "unprivileged"); got.Code != "valid-code" {
				t.Fatalf("unrelated valid entry was lost: %#v", got)
			}
		})
	}
}

func TestResolveAllCompanionRoles(t *testing.T) {
	c := basicResolutionCatalog(map[string]executableDef{
		"tool": {Functions: map[string][]exampleDef{
			"command": {{
				Code:      "primary-code",
				Contexts:  map[string]json.RawMessage{"unprivileged": json.RawMessage("null")},
				Listener:  json.RawMessage(`"shared"`),
				Connector: json.RawMessage(`{"comment":"connector-comment","code":"connector-code"}`),
				Sender:    json.RawMessage(`"sender"`),
				Receiver:  json.RawMessage(`"receiver"`),
			}},
		}},
	})
	meta := c.Functions["command"]
	meta.Extra = map[string]json.RawMessage{
		"listener": json.RawMessage(`{"shared":{"comment":"listener-comment","code":"listener-code"}}`),
		"sender":   json.RawMessage(`{"sender":{"comment":"sender-comment","code":"sender-code"}}`),
		"receiver": json.RawMessage(`{"receiver":{"comment":"receiver-comment","code":"receiver-code"}}`),
	}
	c.Functions["command"] = meta

	value := techniqueNamed(t, findingNamed(t, resolveCatalog(c), "tool"), "command", "unprivileged")
	wantRoles := []string{"listener", "connector", "sender", "receiver"}
	if len(value.Companions) != len(wantRoles) {
		t.Fatalf("companions = %#v", value.Companions)
	}
	for index, role := range wantRoles {
		if value.Companions[index].Role != role {
			t.Fatalf("companion roles = %#v", value.Companions)
		}
	}
	if value.Code != "primary-code" {
		t.Fatalf("companion code changed primary command: %q", value.Code)
	}
}

func TestResolvedCompanionDoesNotHideApplicableTechnique(t *testing.T) {
	c := basicResolutionCatalog(map[string]executableDef{
		"tool": {Functions: map[string][]exampleDef{
			"command": {{
				Code:     "primary-code",
				Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage(`{"shell":true}`)},
				Listener: json.RawMessage(`"shared"`),
			}},
		}},
	})
	meta := c.Functions["command"]
	meta.Extra = map[string]json.RawMessage{"listener": json.RawMessage(`{"shared":{"code":"listener-code"}}`)}
	c.Functions["command"] = meta

	resolved := resolveCatalog(c)
	value := findingNamed(t, resolved, "tool")
	evaluated := evaluateFindings([]finding{value}, []executableDiscovery{
		staticDiscovery("tool", "/fixture/tool", "/fixture/tool", 0o755, mountStatus{Known: true}),
	}, hostSnapshot{procStatus: procStatus{NoNewPrivsKnown: true, CapBndKnown: true}}, sudoProbeBatch{}, nil)
	report := filterFindings(evaluated, false)
	if report.DisplayedTechniques != 1 || report.HiddenUnknown != 0 || len(report.Findings) != 1 {
		t.Fatalf("valid companion was hidden: %#v", report)
	}
	if got := report.Findings[0].Techniques[0]; got.State != stateConfirmed || len(got.Companions) != 1 || len(got.Warnings) != 0 {
		t.Fatalf("applicability = %#v", got)
	}
}

func TestResolveInvalidCompanionsWarnButKeepTechnique(t *testing.T) {
	c := basicResolutionCatalog(map[string]executableDef{
		"tool": {Functions: map[string][]exampleDef{
			"command": {{
				Code:      "primary-code",
				Contexts:  map[string]json.RawMessage{"unprivileged": json.RawMessage("null")},
				Listener:  json.RawMessage(`"missing"`),
				Connector: json.RawMessage(`"malformed"`),
			}},
		}},
	})
	meta := c.Functions["command"]
	meta.Extra = map[string]json.RawMessage{
		"listener":  json.RawMessage(`{"other":{"code":"other"}}`),
		"connector": json.RawMessage(`{"malformed":{"code":1}}`),
	}
	c.Functions["command"] = meta

	result := resolveCatalog(c)
	value := techniqueNamed(t, findingNamed(t, result, "tool"), "command", "unprivileged")
	if value.Code != "primary-code" || len(value.Companions) != 0 || len(value.Warnings) != 2 {
		t.Fatalf("invalid companion handling = %#v", value)
	}
	if !warningContains(value.Warnings, "reference \"missing\" is missing") || !warningContains(value.Warnings, "reference \"malformed\" is malformed") {
		t.Fatalf("companion warnings = %v", value.Warnings)
	}
}

func TestResolveInheritanceMetadataAndContextIntersection(t *testing.T) {
	c := catalog{
		Functions: map[string]functionMeta{
			"command": {Label: "Command", Description: "target-description", Mitre: []string{"T1000", "T2000"}},
			"inherit": {Label: "Inherit"},
		},
		Contexts: map[string]contextMeta{
			"unprivileged":  {Label: "Unprivileged"},
			"sudo":          {Label: "Sudo"},
			"future":        {Label: "Future"},
			"launcher-only": {Label: "Launcher only"},
		},
		Executables: map[string]executableDef{
			"target": {Functions: map[string][]exampleDef{
				"command": {{
					Code:    "target-code",
					Comment: "target-example-comment",
					Version: "target-version",
					Contexts: map[string]json.RawMessage{
						"unprivileged": json.RawMessage(`{"comment":"target-context-comment","shell":true,"list":["TARGET"]}`),
						"sudo":         json.RawMessage("null"),
						"future":       json.RawMessage("null"),
					},
				}},
			}},
			"parent": {Functions: map[string][]exampleDef{
				"inherit": {{
					Code:    "launcher-code",
					Comment: "launcher-example-comment",
					Version: "launcher-version",
					From:    "target",
					Contexts: map[string]json.RawMessage{
						"unprivileged": json.RawMessage(`{"code":"launcher-override","comment":"launcher-context-comment","shell":false,"list":["LAUNCH"]}`),
						"future":       json.RawMessage("null"),
					},
				}},
			}},
			"grand": {Functions: map[string][]exampleDef{
				"inherit": {{Code: "outer-launcher", Comment: "outer-comment", Version: "outer-version", From: "parent", Contexts: map[string]json.RawMessage{
					"unprivileged": json.RawMessage("null"),
					"future":       json.RawMessage("null"),
				}}},
			}},
			"no-intersection": {Functions: map[string][]exampleDef{
				"inherit": {{Code: "unused-launcher", From: "target", Contexts: map[string]json.RawMessage{"launcher-only": json.RawMessage("null")}}},
			}},
		},
	}

	result := resolveCatalog(c)
	parent := findingNamed(t, result, "parent")
	if len(parent.Techniques) != 2 {
		t.Fatalf("parent techniques = %d, want exact context intersection of 2", len(parent.Techniques))
	}
	value := techniqueNamed(t, parent, "command", "unprivileged")
	if value.Code != "target-code" || value.ExampleComment != "target-example-comment" || value.ContextComment != "target-context-comment" || value.Version != "target-version" {
		t.Fatalf("target metadata = %#v", value)
	}
	if value.Description != "target-description" || !reflect.DeepEqual(value.MitreIDs, []string{"T1000", "T2000"}) || value.ContextShell == nil || !*value.ContextShell || !reflect.DeepEqual(value.ContextList, []string{"TARGET"}) {
		t.Fatalf("target function/context metadata = %#v", value)
	}
	if len(value.Launchers) != 1 {
		t.Fatalf("launchers = %#v", value.Launchers)
	}
	launcher := value.Launchers[0]
	if launcher.Code != "launcher-override" || launcher.ExampleComment != "launcher-example-comment" || launcher.ContextComment != "launcher-context-comment" || launcher.Version != "launcher-version" || launcher.ContextShell == nil || *launcher.ContextShell || !reflect.DeepEqual(launcher.ContextList, []string{"LAUNCH"}) {
		t.Fatalf("launcher metadata = %#v", launcher)
	}
	if strings.Contains(value.Code, launcher.Code) || strings.Contains(launcher.Code, value.Code) {
		t.Fatalf("launcher and target code were synthesized: launcher=%q target=%q", launcher.Code, value.Code)
	}
	if !reflect.DeepEqual(value.InheritanceChain, []string{"parent", "target"}) {
		t.Fatalf("inheritance chain = %v", value.InheritanceChain)
	}
	if techniqueNamed(t, parent, "command", "future").ContextKey != "future" {
		t.Fatal("unknown context did not intersect by exact key")
	}
	for _, candidate := range parent.Techniques {
		if candidate.ContextKey == "sudo" {
			t.Fatal("target-only sudo context escaped intersection")
		}
	}

	grand := techniqueNamed(t, findingNamed(t, result, "grand"), "command", "unprivileged")
	if !reflect.DeepEqual(grand.InheritanceChain, []string{"grand", "parent", "target"}) || len(grand.Launchers) != 2 {
		t.Fatalf("multi-hop inheritance = %#v", grand)
	}
	if grand.Launchers[0].Code != "outer-launcher" || grand.Launchers[1].Code != "launcher-override" || grand.Code != "target-code" {
		t.Fatalf("multi-hop commands were not separate: %#v", grand)
	}
	if got := findingNamed(t, result, "no-intersection"); len(got.Techniques) != 0 {
		t.Fatalf("empty context intersection emitted techniques: %#v", got.Techniques)
	}
}

func TestResolveInheritanceFailuresAreLocalAndDeterministic(t *testing.T) {
	c := basicResolutionCatalog(map[string]executableDef{
		"cycle-a": {Functions: map[string][]exampleDef{"inherit": {{From: "cycle-b", Code: "a", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}}}}},
		"cycle-b": {Functions: map[string][]exampleDef{"inherit": {{From: "cycle-a", Code: "b", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}}}}},
		"missing": {Functions: map[string][]exampleDef{"inherit": {{From: "not-there", Code: "missing", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}}}}},
		"empty":   {Functions: map[string][]exampleDef{"inherit": {{Code: "empty", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}}}}},
		"valid":   {Functions: map[string][]exampleDef{"command": {{Code: "valid-code", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}}}}},
	})

	result := resolveCatalog(c)
	if !warningContains(result.Warnings, "inheritance cycle") || !warningContains(result.Warnings, "not-there") || !warningContains(result.Warnings, "empty inheritance source") {
		t.Fatalf("inheritance warnings = %v", result.Warnings)
	}
	if !slices.IsSorted(result.Warnings) {
		t.Fatalf("warnings are not sorted: %v", result.Warnings)
	}
	if len(findingNamed(t, result, "cycle-a").Techniques) != 0 || len(findingNamed(t, result, "missing").Techniques) != 0 || len(findingNamed(t, result, "empty").Techniques) != 0 {
		t.Fatal("invalid inheritance emitted techniques")
	}
	if got := techniqueNamed(t, findingNamed(t, result, "valid"), "command", "unprivileged"); got.Code != "valid-code" {
		t.Fatalf("unrelated valid entry was lost: %#v", got)
	}
	if again := resolveCatalog(c); !reflect.DeepEqual(result, again) {
		t.Fatal("warning or technique order changed across resolutions")
	}
}

func TestResolveMalformedContextSkipsOnlyAffectedContext(t *testing.T) {
	c := basicResolutionCatalog(map[string]executableDef{
		"tool": {Functions: map[string][]exampleDef{"command": {{Code: "code", Contexts: map[string]json.RawMessage{
			"unprivileged": json.RawMessage(`[]`),
			"sudo":         json.RawMessage("null"),
		}}}}},
	})

	result := resolveCatalog(c)
	f := findingNamed(t, result, "tool")
	if len(f.Techniques) != 1 || f.Techniques[0].ContextKey != "sudo" || !warningContains(f.Warnings, "context \"unprivileged\"") {
		t.Fatalf("partial context failure = techniques %#v warnings %v", f.Techniques, f.Warnings)
	}
}

func TestResolutionDeduplicationUsesExplicitIdentity(t *testing.T) {
	c := basicResolutionCatalog(map[string]executableDef{
		"duplicate": {Functions: map[string][]exampleDef{"command": {
			{Code: "same-target", Comment: "first", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}},
			{Code: "same-target", Comment: "second", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}},
		}}},
		"target":   {Functions: map[string][]exampleDef{"command": {{Code: "same-target", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}}}}},
		"middle-a": {Functions: map[string][]exampleDef{"inherit": {{Code: "middle-a", From: "target", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}}}}},
		"middle-b": {Functions: map[string][]exampleDef{"inherit": {{Code: "middle-b", From: "target", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}}}}},
		"root": {Functions: map[string][]exampleDef{"inherit": {
			{Code: "root-a", From: "middle-a", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}},
			{Code: "root-b", From: "middle-b", Contexts: map[string]json.RawMessage{"unprivileged": json.RawMessage("null")}},
		}}},
	})
	meta := c.Functions["command"]
	meta.Mitre = []string{"T1000", "T2000"}
	c.Functions["command"] = meta

	result := resolveCatalog(c)
	duplicate := findingNamed(t, result, "duplicate")
	if len(duplicate.Techniques) != 1 || duplicate.Techniques[0].ExampleComment != "first" || !reflect.DeepEqual(duplicate.Techniques[0].MitreIDs, []string{"T1000", "T2000"}) {
		t.Fatalf("duplicate handling = %#v", duplicate.Techniques)
	}
	root := findingNamed(t, result, "root")
	if len(root.Techniques) != 2 {
		t.Fatalf("different inheritance chains were deduplicated: %#v", root.Techniques)
	}
	wantChains := [][]string{{"root", "middle-a", "target"}, {"root", "middle-b", "target"}}
	for index, want := range wantChains {
		if !reflect.DeepEqual(root.Techniques[index].InheritanceChain, want) {
			t.Fatalf("inheritance chain %d = %v, want %v", index, root.Techniques[index].InheritanceChain, want)
		}
	}
}

func TestParseProcStatus(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		want         procStatus
		wantWarnings bool
	}{
		{
			name:         "NoNewPrivs zero",
			input:        "NoNewPrivs:\t0\n",
			want:         procStatus{NoNewPrivsKnown: true},
			wantWarnings: true,
		},
		{
			name:         "NoNewPrivs one",
			input:        "NoNewPrivs:\t1\n",
			want:         procStatus{NoNewPrivs: true, NoNewPrivsKnown: true},
			wantWarnings: true,
		},
		{
			name:         "valid CapBnd",
			input:        "CapBnd:\t00000000a80425fb\n",
			want:         procStatus{CapBnd: 0xa80425fb, CapBndKnown: true},
			wantWarnings: true,
		},
		{
			name:  "both valid",
			input: "NoNewPrivs:\t0\nCapBnd:\t00000000a80425fb\n",
			want:  procStatus{NoNewPrivsKnown: true, CapBnd: 0xa80425fb, CapBndKnown: true},
		},
		{
			name:         "missing NoNewPrivs",
			input:        "CapBnd:\t1\n",
			want:         procStatus{CapBnd: 1, CapBndKnown: true},
			wantWarnings: true,
		},
		{
			name:         "missing CapBnd",
			input:        "NoNewPrivs:\t1\n",
			want:         procStatus{NoNewPrivs: true, NoNewPrivsKnown: true},
			wantWarnings: true,
		},
		{
			name:         "both missing",
			input:        "Name:\tfixture\n",
			want:         procStatus{},
			wantWarnings: true,
		},
		{
			name:         "malformed decimal",
			input:        "NoNewPrivs:\tinvalid\nCapBnd:\t2\n",
			want:         procStatus{CapBnd: 2, CapBndKnown: true},
			wantWarnings: true,
		},
		{
			name:         "NoNewPrivs outside boolean range",
			input:        "NoNewPrivs:\t2\nCapBnd:\t3\n",
			want:         procStatus{CapBnd: 3, CapBndKnown: true},
			wantWarnings: true,
		},
		{
			name:         "malformed hexadecimal",
			input:        "NoNewPrivs:\t1\nCapBnd:\tnot-hex\n",
			want:         procStatus{NoNewPrivs: true, NoNewPrivsKnown: true},
			wantWarnings: true,
		},
		{
			name:  "unrelated lines ignored",
			input: "Name:\tfixture\nState:\tR\nNoNewPrivs:\t0\nCapBnd:\tf\nThreads:\t1\n",
			want:  procStatus{NoNewPrivsKnown: true, CapBnd: 0xf, CapBndKnown: true},
		},
		{
			name:  "arbitrary whitespace",
			input: "  NoNewPrivs :   1  \n\tCapBnd:\t  000f \t\n",
			want:  procStatus{NoNewPrivs: true, NoNewPrivsKnown: true, CapBnd: 0xf, CapBndKnown: true},
		},
		{
			name:         "malformed field preserves other valid field",
			input:        "NoNewPrivs:\tbad\nCapBnd:\tff\n",
			want:         procStatus{CapBnd: 0xff, CapBndKnown: true},
			wantWarnings: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warnings := parseProcStatus(strings.NewReader(tt.input))
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("status = %#v, want %#v", got, tt.want)
			}
			if (len(warnings) != 0) != tt.wantWarnings {
				t.Fatalf("warnings = %v, wantWarnings = %v", warnings, tt.wantWarnings)
			}
		})
	}
}

func TestParseProcStatusRejectsDuplicateSecurityFields(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  procStatus
		warn  string
	}{
		{"valid NoNewPrivs values", "NoNewPrivs: 0\nNoNewPrivs: 1\nCapBnd: ff\n", procStatus{CapBnd: 0xff, CapBndKnown: true}, "NoNewPrivs is duplicated"},
		{"identical NoNewPrivs values", "NoNewPrivs: 1\nCapBnd: ff\nNoNewPrivs: 1\n", procStatus{CapBnd: 0xff, CapBndKnown: true}, "NoNewPrivs is duplicated"},
		{"valid CapBnd values", "NoNewPrivs: 0\nCapBnd: ff\nCapBnd: 0\n", procStatus{NoNewPrivsKnown: true}, "CapBnd is duplicated"},
		{"valid then malformed", "NoNewPrivs: 0\nNoNewPrivs: bad\nCapBnd: ff\n", procStatus{CapBnd: 0xff, CapBndKnown: true}, "NoNewPrivs is duplicated"},
		{"malformed then valid", "NoNewPrivs: bad\nCapBnd: ff\nNoNewPrivs: 0\n", procStatus{CapBnd: 0xff, CapBndKnown: true}, "NoNewPrivs is duplicated"},
		{"malformed twice", "NoNewPrivs: bad\nNoNewPrivs: worse\nCapBnd: ff\n", procStatus{CapBnd: 0xff, CapBndKnown: true}, "NoNewPrivs is duplicated"},
		{"more than two", "NoNewPrivs: 0\nName: fixture\nNoNewPrivs: 1\nNoNewPrivs: 0\nCapBnd: ff\n", procStatus{CapBnd: 0xff, CapBndKnown: true}, "NoNewPrivs is duplicated"},
		{"CapBnd separated", "NoNewPrivs: 0\nCapBnd: ff\nName: fixture\nCapBnd: 0\n", procStatus{NoNewPrivsKnown: true}, "CapBnd is duplicated"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warnings := parseProcStatus(strings.NewReader(tt.input))
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("status = %#v, want %#v", got, tt.want)
			}
			if !warningContains(warnings, tt.warn) {
				t.Fatalf("warnings = %v, want %q", warnings, tt.warn)
			}
		})
	}
}

func TestParseProcStatusReadFailurePoisonsSecurityFields(t *testing.T) {
	input := "NoNewPrivs: 0\nCapBnd: ff\n" + strings.Repeat("x", 128*1024) + "\n"
	status, warnings := parseProcStatus(strings.NewReader(input))
	if status.NoNewPrivsKnown || status.CapBndKnown {
		t.Fatalf("read failure retained trusted security fields: %#v", status)
	}
	if !warningContains(warnings, "read process status") {
		t.Fatalf("warnings = %v; want scanner failure warning", warnings)
	}
}

func TestSearchCatalogName(t *testing.T) {
	executables := map[string]executableDef{
		"Tool":      {},
		"tool":      {},
		"Unique":    {},
		"thing.exe": {},
		"plain":     {},
	}
	tests := []struct {
		name           string
		query          string
		wantName       string
		wantCandidates []string
		wantErr        error
	}{
		{"exact match", "Tool", "Tool", nil, nil},
		{"exact match wins", "tool", "tool", nil, nil},
		{"unique case-insensitive", "UNIQUE", "Unique", nil, nil},
		{"ambiguous case-insensitive", "TOOL", "", []string{"Tool", "tool"}, errCatalogNameAmbiguous},
		{"no match", "missing", "", nil, errCatalogNameNotFound},
		{"directory prefix", "/usr/bin/Unique", "Unique", nil, nil},
		{"no suffix insertion", "thing", "", nil, errCatalogNameNotFound},
		{"suffix preserved", "thing.exe", "thing.exe", nil, nil},
		{"no suffix stripping", "plain.exe", "", nil, errCatalogNameNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := searchCatalogName(executables, tt.query)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if result.Name != tt.wantName || !reflect.DeepEqual(result.Candidates, tt.wantCandidates) {
				t.Fatalf("result = %#v, want name %q candidates %v", result, tt.wantName, tt.wantCandidates)
			}
			if tt.query == "UNIQUE" && result.Name != "Unique" {
				t.Fatalf("catalog capitalization was not preserved: %#v", result)
			}
		})
	}
}

func TestDiscoverExecutables(t *testing.T) {
	dir := t.TempDir()
	directPath := writeTestExecutable(t, dir, "CaseTool")
	targetPath := writeTestExecutable(t, dir, "shared-target")
	aliasAPath := filepath.Join(dir, "AliasA")
	aliasBPath := filepath.Join(dir, "AliasB")
	if err := os.Symlink(targetPath, aliasAPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath, aliasBPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "absent-target"), filepath.Join(dir, "Broken")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "Directory"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	results := discoverExecutables(map[string]executableDef{
		"Missing":   {},
		"Directory": {},
		"CaseTool":  {},
		"Broken":    {},
		"AliasB":    {},
		"AliasA":    {},
	})
	wantOrder := []string{"AliasA", "AliasB", "Broken", "CaseTool", "Directory", "Missing"}
	for index, name := range wantOrder {
		if results[index].CatalogName != name {
			t.Fatalf("discovery order = %#v, want %v", results, wantOrder)
		}
	}

	direct := discoveryNamed(t, results, "CaseTool")
	if !direct.Found || !direct.Executable || direct.InvocablePath != directPath || direct.CanonicalPath != directPath || direct.FileInfo == nil || direct.FileInfo.Mode().Perm()&0o111 == 0 {
		t.Fatalf("direct discovery = %#v", direct)
	}
	if direct.CatalogName != "CaseTool" || strings.Contains(direct.InvocablePath, "casetool") {
		t.Fatalf("catalog/path case was changed: %#v", direct)
	}

	aliasA := discoveryNamed(t, results, "AliasA")
	aliasB := discoveryNamed(t, results, "AliasB")
	if aliasA.InvocablePath != aliasAPath || aliasB.InvocablePath != aliasBPath || aliasA.CanonicalPath != targetPath || aliasB.CanonicalPath != targetPath {
		t.Fatalf("symlink discovery A=%#v B=%#v", aliasA, aliasB)
	}
	if aliasA.CatalogName == aliasB.CatalogName || len(results) != len(wantOrder) {
		t.Fatal("distinct catalog names sharing one canonical target were deduplicated")
	}

	for _, name := range []string{"Broken", "Directory", "Missing"} {
		value := discoveryNamed(t, results, name)
		if value.Found || value.Warning == "" {
			t.Fatalf("nonfatal discovery failure for %q = %#v", name, value)
		}
	}
}

func TestDiscoverExecutableRejectsErrDot(t *testing.T) {
	dir := t.TempDir()
	writeTestExecutable(t, dir, "RelativeTool")
	t.Chdir(dir)
	t.Setenv("PATH", ".")

	result := discoverExecutable("RelativeTool")
	if result.Found || !strings.Contains(result.Warning, "current directory") {
		t.Fatalf("ErrDot result = %#v", result)
	}
}

func TestCanonicalTargetFailuresAreNonfatal(t *testing.T) {
	t.Run("stat failure", func(t *testing.T) {
		result := inspectCanonicalExecutable(executableDiscovery{
			CatalogName:   "missing",
			Found:         true,
			InvocablePath: "/fixture/missing",
			CanonicalPath: filepath.Join(t.TempDir(), "missing"),
		})
		if result.Executable || !strings.Contains(result.Warning, "stat canonical target") {
			t.Fatalf("stat failure = %#v", result)
		}
	})

	t.Run("directory rejected", func(t *testing.T) {
		dir := t.TempDir()
		result := inspectCanonicalExecutable(executableDiscovery{
			CatalogName:   "directory",
			Found:         true,
			InvocablePath: dir,
			CanonicalPath: dir,
		})
		if result.Executable || !strings.Contains(result.Warning, "not a regular file") {
			t.Fatalf("directory result = %#v", result)
		}
	})
}

func TestInspectCanonicalExecutableDoesNotBlockOnFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0o700); err != nil {
		t.Skipf("FIFO unavailable: %v", err)
	}
	done := make(chan executableDiscovery, 1)
	go func() {
		done <- inspectCanonicalExecutable(executableDiscovery{CatalogName: "fifo", Found: true, CanonicalPath: path})
	}()
	select {
	case result := <-done:
		if result.Warning == "" || result.FileInfo == nil || result.FileInfo.Mode().IsRegular() {
			t.Fatalf("FIFO inspection = %#v; want bounded non-regular warning", result)
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO inspection blocked")
	}
}

func TestCapabilityInspectionUsesOpenedDescriptor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "candidate")
	replacement := filepath.Join(dir, "replacement")
	writeTestExecutable(t, dir, "candidate")
	writeTestExecutable(t, dir, "replacement")
	capA := capabilityXattrFixture(vfsCapabilityRevision2, 1, 0, true, 0)
	capB := capabilityXattrFixture(vfsCapabilityRevision2, 2, 0, true, 0)
	if err := unix.Setxattr(path, securityCapabilityXattr, capA, 0); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("security.capability unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err := unix.Setxattr(replacement, securityCapabilityXattr, capB, 0); err != nil {
		t.Fatal(err)
	}

	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	got := inspectFileCapabilitiesDescriptor(file)
	if !got.Known || !got.Present || got.Capabilities.Permitted != 1 {
		t.Fatalf("descriptor capability inspection = %#v, want inode A capability", got)
	}
}

func TestInterpretMountFlags(t *testing.T) {
	tests := []struct {
		name   string
		flags  int64
		noExec bool
		noSUID bool
	}{
		{"neither", 0, false, false},
		{"noexec", unix.ST_NOEXEC, true, false},
		{"nosuid", unix.ST_NOSUID, false, true},
		{"both", unix.ST_NOEXEC | unix.ST_NOSUID, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := interpretMountFlags(tt.flags)
			if !status.Known || status.NoExec != tt.noExec || status.NoSUID != tt.noSUID {
				t.Fatalf("mount status = %#v", status)
			}
			if discoveryUsable(true, status) == tt.noExec {
				t.Fatalf("usable state did not reflect noexec: %#v", status)
			}
		})
	}

	status, err := inspectMount(filepath.Join(t.TempDir(), "missing"))
	if err == nil || status.Known || discoveryUsable(true, status) {
		t.Fatalf("failed Statfs was treated as permissive: status=%#v err=%v", status, err)
	}
}

func TestCaptureHostSnapshot(t *testing.T) {
	dir := t.TempDir()
	writeTestExecutable(t, dir, "sudo")
	statusPath := filepath.Join(dir, "status")
	if err := os.WriteFile(statusPath, []byte("NoNewPrivs:\t1\nCapBnd:\tff\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	snapshot := captureHostSnapshotAtWithSudoResolver(statusPath, true, func() (string, error) { return filepath.Join(dir, "sudo"), nil })
	if snapshot.RealUID != os.Getuid() || snapshot.EffectiveUID != os.Geteuid() {
		t.Fatalf("UID snapshot = real %d effective %d", snapshot.RealUID, snapshot.EffectiveUID)
	}
	if !snapshot.NoNewPrivsKnown || !snapshot.NoNewPrivs || !snapshot.CapBndKnown || snapshot.CapBnd != 0xff {
		t.Fatalf("process status snapshot = %#v", snapshot)
	}
	if !snapshot.SudoPresent || !snapshot.SudoProbeRequested {
		t.Fatalf("sudo snapshot = %#v", snapshot)
	}

	t.Setenv("PATH", t.TempDir())
	missing := captureHostSnapshotAt(filepath.Join(dir, "missing-status"), false)
	if missing.NoNewPrivsKnown || missing.CapBndKnown || missing.SudoPresent || missing.SudoProbeRequested || len(missing.Warnings) == 0 {
		t.Fatalf("missing process status was not retained as unknown: %#v", missing)
	}

	smoke := captureHostSnapshot(false)
	if smoke.RealUID != os.Getuid() || smoke.EffectiveUID != os.Geteuid() {
		t.Fatalf("live snapshot lost UIDs: %#v", smoke)
	}
}

func TestCaptureHostSnapshotRejectsErrDotSudo(t *testing.T) {
	dir := t.TempDir()
	writeTestExecutable(t, dir, "sudo")
	statusPath := filepath.Join(dir, "status")
	if err := os.WriteFile(statusPath, []byte("NoNewPrivs:\t0\nCapBnd:\t0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("PATH", ".")

	snapshot := captureHostSnapshotAt(statusPath, false)
	if snapshot.SudoPresent || !warningContains(snapshot.Warnings, "not safely available") {
		t.Fatalf("ErrDot sudo snapshot = %#v", snapshot)
	}
}

func TestLocateTrustedSudoRejectsUntrustedPath(t *testing.T) {
	dir := t.TempDir()
	writeTestExecutable(t, dir, "sudo")
	t.Setenv("PATH", dir)
	if path, err := locateTrustedSudo(); err == nil {
		t.Fatalf("untrusted sudo path accepted: %q", path)
	}

	t.Chdir(dir)
	t.Setenv("PATH", ".")
	if path, err := locateTrustedSudo(); err == nil {
		t.Fatalf("relative sudo path accepted: %q", path)
	}
}

func TestLocateTrustedSudoFindsTrustedSystemSudo(t *testing.T) {
	path, err := locateTrustedSudo()
	if err != nil {
		t.Skipf("trusted sudo unavailable: %v", err)
	}
	if !filepath.IsAbs(path) || filepath.Base(path) != "sudo" {
		t.Fatalf("trusted sudo path = %q", path)
	}
	if err := trustedFile(path); err != nil {
		t.Fatalf("trusted sudo failed validation: %v", err)
	}
}

func TestTrustedUserNamespaceIdentity(t *testing.T) {
	for _, tt := range []struct {
		name          string
		namespaceType int
		inode         uint64
		wantTrusted   bool
	}{
		{"initial namespace", unix.CLONE_NEWUSER, initialUserNamespaceInode, true},
		{"ordinary nested namespace", unix.CLONE_NEWUSER, initialUserNamespaceInode + 1, false},
		{"identity-mapped nested namespace", unix.CLONE_NEWUSER, initialUserNamespaceInode + 2, false},
		{"namespace root remains nested", unix.CLONE_NEWUSER, initialUserNamespaceInode + 3, false},
		{"unsupported namespace descriptor", 0, initialUserNamespaceInode, false},
		{"malformed namespace metadata", unix.CLONE_NEWUSER, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := trustedUserNamespaceIdentity(tt.namespaceType, tt.inode)
			if (err == nil) != tt.wantTrusted {
				t.Fatalf("trustedUserNamespaceIdentity(%#x, %d) = %v, wantTrusted %v", tt.namespaceType, tt.inode, err, tt.wantTrusted)
			}
		})
	}
}

func TestTrustedUserNamespaceProductionPath(t *testing.T) {
	info, err := os.Stat("/proc/self/ns/user")
	if err != nil {
		t.Skipf("user namespace metadata unavailable: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		t.Skip("user namespace inode unavailable")
	}
	err = trustedUserNamespace()
	if (err == nil) != (stat.Ino == initialUserNamespaceInode) {
		t.Fatalf("trustedUserNamespace() = %v for inode %d", err, stat.Ino)
	}

	if err := trustedUserNamespaceAt(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("unavailable namespace evidence was trusted")
	}
	if err := trustedUserNamespaceAt(t.TempDir()); err == nil {
		t.Fatal("non-namespace descriptor was trusted")
	}
}

func TestNestedUserNamespaceProductionPath(t *testing.T) {
	const childMode = "GOGTFO_TEST_USER_NAMESPACE"
	if mode := os.Getenv(childMode); mode != "" {
		if err := trustedUserNamespace(); err == nil {
			t.Fatalf("%s nested user namespace was trusted", mode)
		}
		host := captureHostSnapshot(false)
		suid := validSUIDEvaluationInput()
		suid.UserNamespaceKnown = host.UserNamespaceKnown
		suid.InitialUserNamespace = host.InitialUserNamespace
		if got := evaluateSUID(suid); got.State == stateConfirmed {
			t.Fatalf("%s nested SUID applicability = %#v", mode, got)
		}
		capabilities := validCapabilityEvaluationInput()
		capabilities.UserNamespaceKnown = host.UserNamespaceKnown
		capabilities.InitialUserNamespace = host.InitialUserNamespace
		if got := evaluateCapabilities(capabilities); got.State == stateConfirmed {
			t.Fatalf("%s nested capability applicability = %#v", mode, got)
		}
		return
	}

	run := func(mode string, args ...string) {
		command := exec.Command("unshare", append(args, os.Args[0], "-test.run=^TestNestedUserNamespaceProductionPath$")...)
		command.Env = append(os.Environ(), childMode+"="+mode)
		if output, err := command.CombinedOutput(); err != nil {
			t.Skipf("%s namespace integration unavailable: %v: %s", mode, err, output)
		}
	}
	run("ordinary", "-Ur", "--fork", "--")
	if os.Geteuid() != 0 {
		t.Skip("identity-mapped namespace integration requires root")
	}
	run("identity-mapped", "-U", "--map-users", "0:0:4294967295", "--map-groups", "0:0:4294967295", "--setgroups", "allow", "--fork", "--")
}

func TestLocateTrustedSudoRejectsSymlinkAndWritableCandidates(t *testing.T) {
	dir := t.TempDir()
	fake := writeTestExecutable(t, dir, "fake-sudo")
	paths := map[string]string{
		"direct fake":            filepath.Join(dir, "sudo"),
		"file symlink":           filepath.Join(dir, "file-link"),
		"multi-hop file symlink": filepath.Join(dir, "file-link-2"),
		"broken symlink":         filepath.Join(dir, "broken"),
	}
	if err := os.Rename(fake, paths["direct fake"]); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(paths["direct fake"], paths["file symlink"]); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(paths["file symlink"], paths["multi-hop file symlink"]); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "missing"), paths["broken symlink"]); err != nil {
		t.Fatal(err)
	}
	for name, candidate := range paths {
		t.Run(name, func(t *testing.T) {
			pathDir := t.TempDir()
			if name == "direct fake" {
				pathDir = dir
			}
			t.Setenv("PATH", pathDir)
			if name != "direct fake" {
				if err := os.Symlink(candidate, filepath.Join(pathDir, "sudo")); err != nil {
					t.Fatal(err)
				}
			}
			if found, err := locateTrustedSudo(); err == nil {
				t.Fatalf("untrusted candidate accepted: %q", found)
			}
		})
	}

	for _, mode := range []os.FileMode{0o775, 0o777} {
		writable := filepath.Join(t.TempDir(), "nested")
		if err := os.Mkdir(writable, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(writable, "sudo"), []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", writable)
		if found, err := locateTrustedSudo(); err == nil {
			t.Fatalf("writable ancestor accepted: mode=%o path=%q", mode, found)
		}
	}
}

func TestLocateTrustedSudoThroughTrustedDirectorySymlink(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sudo"); err != nil {
		t.Skipf("system sudo unavailable: %v", err)
	}
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	if err := os.Symlink("/usr/bin", first); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(first, second); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", second)
	found, err := locateTrustedSudo()
	if err != nil || found != "/usr/bin/sudo" {
		t.Fatalf("trusted directory symlink chain = %q, %v", found, err)
	}
}

func TestLocateTrustedSudoFromTrustedNonstandardDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned disposable directory")
	}
	if _, err := os.Stat("/usr/bin/sudo"); err != nil {
		t.Skipf("system sudo unavailable: %v", err)
	}
	dir, err := os.MkdirTemp("/opt", "gogtfo-sudo-")
	if err != nil {
		t.Skipf("trusted nonstandard directory unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	first := filepath.Join(dir, "sudo-first")
	if err := os.Symlink("/usr/bin/sudo", first); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(first, filepath.Join(dir, "sudo")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	found, err := locateTrustedSudo()
	if err != nil || found != "/usr/bin/sudo" {
		t.Fatalf("trusted nonstandard sudo = %q, %v", found, err)
	}
}

func writeTestExecutable(t *testing.T, dir, name string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("fixture"), 0o700); err != nil {
		t.Fatalf("os.WriteFile(%q): %v", path, err)
	}
	return path
}

func discoveryNamed(t *testing.T, discoveries []executableDiscovery, name string) executableDiscovery {
	t.Helper()

	for _, discovery := range discoveries {
		if discovery.CatalogName == name {
			return discovery
		}
	}
	t.Fatalf("discovery for %q not found", name)
	return executableDiscovery{}
}

func TestComposeApplicability(t *testing.T) {
	tests := []struct {
		name   string
		states []applicabilityState
		want   applicabilityState
	}{
		{"confirmed", []applicabilityState{stateConfirmed}, stateConfirmed},
		{"potential", []applicabilityState{statePotential}, statePotential},
		{"unknown", []applicabilityState{stateUnknown}, stateUnknown},
		{"unavailable", []applicabilityState{stateUnavailable}, stateUnavailable},
		{"confirmed potential", []applicabilityState{stateConfirmed, statePotential}, statePotential},
		{"confirmed unknown", []applicabilityState{stateConfirmed, stateUnknown}, stateUnknown},
		{"confirmed unavailable", []applicabilityState{stateConfirmed, stateUnavailable}, stateUnavailable},
		{"potential unknown", []applicabilityState{statePotential, stateUnknown}, stateUnknown},
		{"potential unavailable", []applicabilityState{statePotential, stateUnavailable}, stateUnavailable},
		{"unknown unavailable", []applicabilityState{stateUnknown, stateUnavailable}, stateUnavailable},
		{"confirmed potential unknown", []applicabilityState{stateConfirmed, statePotential, stateUnknown}, stateUnknown},
		{"confirmed unknown unavailable", []applicabilityState{stateConfirmed, stateUnknown, stateUnavailable}, stateUnavailable},
		{"empty", nil, stateUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := composeApplicability(tt.states...); got != tt.want {
				t.Fatalf("composeApplicability(%v) = %q, want %q", tt.states, got, tt.want)
			}
			reversed := slices.Clone(tt.states)
			slices.Reverse(reversed)
			if got := composeApplicability(reversed...); got != tt.want {
				t.Fatalf("reverse-order composeApplicability(%v) = %q, want %q", reversed, got, tt.want)
			}
		})
	}
}

func TestComposeApplicabilityResultsDeduplicatesEvidence(t *testing.T) {
	got := composeApplicabilityResults(
		applicabilityResult{State: stateConfirmed, Evidence: []string{"first", "shared"}},
		applicabilityResult{State: stateUnknown, Evidence: []string{"shared", "second"}},
	)
	if got.State != stateUnknown || !reflect.DeepEqual(got.Evidence, []string{"first", "shared", "second"}) {
		t.Fatalf("composed result = %#v", got)
	}
}

type fileInfoWithSys struct {
	os.FileInfo
	sys any
}

func (info fileInfoWithSys) Sys() any { return info.sys }

type staticFileInfo struct {
	name string
	mode os.FileMode
	uid  uint32
}

func (info staticFileInfo) Name() string       { return info.name }
func (info staticFileInfo) Size() int64        { return 1 }
func (info staticFileInfo) Mode() os.FileMode  { return info.mode }
func (info staticFileInfo) ModTime() time.Time { return time.Time{} }
func (info staticFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info staticFileInfo) Sys() any           { return &syscall.Stat_t{Uid: info.uid} }

func staticDiscovery(name, invocable, canonical string, mode os.FileMode, mount mountStatus) executableDiscovery {
	return executableDiscovery{
		CatalogName:   name,
		Found:         true,
		InvocablePath: invocable,
		CanonicalPath: canonical,
		FileInfo:      staticFileInfo{name: filepath.Base(canonical), mode: mode},
		Executable:    mode.Perm()&0o111 != 0,
		Format:        executableFormatELF,
		Mount:         mount,
		Usable:        discoveryUsable(mode.Perm()&0o111 != 0, mount),
	}
}

func TestCanonicalOwnerUID(t *testing.T) {
	path := writeTestExecutable(t, t.TempDir(), "owner-fixture")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	uid, known := canonicalOwnerUID(info)
	if !known || uid != uint32(os.Getuid()) {
		t.Fatalf("canonicalOwnerUID() = %d, %v; want %d, true", uid, known, os.Getuid())
	}
	for _, candidate := range []os.FileInfo{nil, fileInfoWithSys{FileInfo: info, sys: struct{}{}}} {
		if uid, known := canonicalOwnerUID(candidate); known || uid != 0 {
			t.Fatalf("canonicalOwnerUID(%#v) = %d, %v; want unknown", candidate, uid, known)
		}
	}
}

func validSUIDEvaluationInput() suidEvaluationInput {
	return suidEvaluationInput{
		FileInspected:   true,
		Regular:         true,
		Format:          executableFormatELF,
		Mode:            0o755 | os.ModeSetuid,
		OwnerUIDKnown:   true,
		Mount:           mountStatus{Known: true},
		NoNewPrivsKnown: true,
	}
}

func TestEvaluateSUID(t *testing.T) {
	tests := []struct {
		name     string
		change   func(*suidEvaluationInput)
		want     applicabilityState
		evidence string
	}{
		{"fully valid root-owned SUID", func(*suidEvaluationInput) {}, stateConfirmed, ""},
		{"non-root owner", func(input *suidEvaluationInput) { input.OwnerUID = 1000 }, stateUnavailable, "owner UID is 1000"},
		{"setuid absent", func(input *suidEvaluationInput) { input.Mode &^= os.ModeSetuid }, stateUnavailable, "does not have setuid bit"},
		{"non-regular", func(input *suidEvaluationInput) { input.Regular = false }, stateUnavailable, "not a regular file"},
		{"nosuid", func(input *suidEvaluationInput) { input.Mount.NoSUID = true }, stateUnavailable, "mounted nosuid"},
		{"noexec", func(input *suidEvaluationInput) { input.Mount.NoExec = true }, stateUnavailable, "mounted noexec"},
		{"NoNewPrivs enabled", func(input *suidEvaluationInput) { input.NoNewPrivs = true }, stateUnavailable, "NoNewPrivs is enabled"},
		{"non-initial user namespace", func(input *suidEvaluationInput) { input.UserNamespaceKnown = true; input.InitialUserNamespace = false }, stateUnavailable, "initial user namespace"},
		{"owner unknown", func(input *suidEvaluationInput) { input.OwnerUIDKnown = false }, stateUnknown, "owner UID could not be determined"},
		{"mount unknown", func(input *suidEvaluationInput) { input.Mount.Known = false }, stateUnknown, "mount flags could not be determined"},
		{"NoNewPrivs unknown", func(input *suidEvaluationInput) { input.NoNewPrivsKnown = false }, stateUnknown, "NoNewPrivs could not be determined"},
		{"version restriction", func(input *suidEvaluationInput) { input.Version = "fixture <= 1" }, stateUnknown, "version restriction was not verified"},
		{"setuid absent outranks version", func(input *suidEvaluationInput) { input.Mode &^= os.ModeSetuid; input.Version = "fixture <= 1" }, stateUnavailable, "does not have setuid bit"},
		{"NoNewPrivs outranks unknown mount", func(input *suidEvaluationInput) { input.NoNewPrivs = true; input.Mount.Known = false }, stateUnavailable, "NoNewPrivs is enabled"},
		{"file inspection unknown", func(input *suidEvaluationInput) { input.FileInspected = false }, stateUnknown, "file information could not be determined"},
		{"interpreter script", func(input *suidEvaluationInput) { input.Format = executableFormatScript }, stateUnavailable, "interpreter scripts ignore the setuid bit"},
		{"format unknown", func(input *suidEvaluationInput) { input.Format = executableFormatUnknown }, stateUnknown, "executable format could not be verified"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validSUIDEvaluationInput()
			tt.change(&input)
			got := evaluateSUID(input)
			if got.State != tt.want {
				t.Fatalf("state = %q, want %q; evidence %v", got.State, tt.want, got.Evidence)
			}
			if tt.want == stateConfirmed && len(got.Evidence) != 0 {
				t.Fatalf("confirmed result has evidence %v", got.Evidence)
			}
			if tt.want != stateConfirmed && (len(got.Evidence) == 0 || !warningContains(got.Evidence, tt.evidence)) {
				t.Fatalf("evidence = %v, want containing %q", got.Evidence, tt.evidence)
			}
			if again := evaluateSUID(input); !reflect.DeepEqual(got, again) {
				t.Fatalf("evidence order changed: first %v, second %v", got.Evidence, again.Evidence)
			}
		})
	}
}

func TestInspectExecutableFormat(t *testing.T) {
	dir := t.TempDir()
	valid, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	magicOnly := filepath.Join(dir, "magic-only")
	if err := os.WriteFile(magicOnly, []byte{0x7f, 'E', 'L', 'F'}, 0o700); err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(dir, "truncated")
	if err := os.WriteFile(truncated, []byte{0x7f, 'E', 'L', 'F', 2, 1}, 0o700); err != nil {
		t.Fatal(err)
	}
	malformed := filepath.Join(dir, "malformed")
	if err := os.WriteFile(malformed, []byte{0x7f, 'E', 'L', 'F', 99, 99, 99, 99, 99, 99, 99, 99}, 0o700); err != nil {
		t.Fatal(err)
	}
	headerOnly := filepath.Join(dir, "header-only")
	header := make([]byte, 64)
	copy(header, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(header[16:18], 2)
	binary.LittleEndian.PutUint16(header[18:20], 62)
	binary.LittleEndian.PutUint32(header[20:24], 1)
	binary.LittleEndian.PutUint16(header[52:54], 64)
	binary.LittleEndian.PutUint16(header[54:56], 56)
	if err := os.WriteFile(headerOnly, header, 0o700); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(dir, "unknown")
	if err := os.WriteFile(unknown, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	validLink := filepath.Join(dir, "valid-link")
	scriptLink := filepath.Join(dir, "script-link")
	malformedLink := filepath.Join(dir, "malformed-link")
	for link, target := range map[string]string{validLink: valid, scriptLink: script, malformedLink: malformed} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	paths := map[string]executableFormat{
		valid:         executableFormatELF,
		script:        executableFormatScript,
		magicOnly:     executableFormatMalformedELF,
		truncated:     executableFormatMalformedELF,
		malformed:     executableFormatMalformedELF,
		headerOnly:    executableFormatMalformedELF,
		unknown:       executableFormatUnknown,
		empty:         executableFormatUnknown,
		validLink:     executableFormatELF,
		scriptLink:    executableFormatScript,
		malformedLink: executableFormatMalformedELF,
	}
	for path, want := range paths {
		got, err := inspectExecutableFormat(path)
		if err != nil || got != want {
			t.Fatalf("inspectExecutableFormat(%q) = %v, %v; want %v", path, got, err, want)
		}
	}
}

func writeELFProgramHeaderFixture(t *testing.T, path string, types ...elf.ProgType) {
	machine, ok := hostELFMachine()
	if !ok {
		t.Fatal("test host ELF machine is unknown")
	}
	writeELFProgramHeaderFixtureMachine(t, path, machine, types...)
}

func writeELFProgramHeaderFixtureMachine(t *testing.T, path string, machine elf.Machine, types ...elf.ProgType) {
	writeELFProgramHeaderFixtureMachineData(t, path, machine, elf.ELFDATA2LSB, types...)
}

func writeELFProgramHeaderFixtureMachineData(t *testing.T, path string, machine elf.Machine, encoding elf.Data, types ...elf.ProgType) {
	t.Helper()
	data := make([]byte, 64+56*len(types))
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, byte(encoding), 1})
	order := binary.ByteOrder(binary.LittleEndian)
	if encoding == elf.ELFDATA2MSB {
		order = binary.BigEndian
	}
	order.PutUint16(data[16:18], uint16(elf.ET_DYN))
	order.PutUint16(data[18:20], uint16(machine))
	order.PutUint32(data[20:24], 1)
	order.PutUint64(data[32:40], 64)
	order.PutUint16(data[52:54], 64)
	order.PutUint16(data[54:56], 56)
	order.PutUint16(data[56:58], uint16(len(types)))
	for index, typ := range types {
		offset := 64 + index*56
		order.PutUint32(data[offset:offset+4], uint32(typ))
	}
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestInspectExecutableFormatRejectsForeignArchitecture(t *testing.T) {
	dir := t.TempDir()
	foreign := elf.EM_AARCH64
	if runtime.GOARCH == "arm64" {
		foreign = elf.EM_X86_64
	}
	path := filepath.Join(dir, "foreign")
	writeELFProgramHeaderFixtureMachine(t, path, foreign, elf.PT_LOAD)
	if got, err := inspectExecutableFormat(path); err != nil || got != executableFormatUnknown {
		t.Fatalf("foreign-architecture ELF = %v, %v; want unknown", got, err)
	}
}

func TestInspectExecutableFormatRequiresKnownHostMachine(t *testing.T) {
	dir := t.TempDir()
	matching := filepath.Join(dir, "matching")
	foreign := filepath.Join(dir, "foreign")
	writeELFProgramHeaderFixtureMachine(t, matching, elf.EM_X86_64, elf.PT_LOAD)
	writeELFProgramHeaderFixtureMachine(t, foreign, elf.EM_AARCH64, elf.PT_LOAD)

	for _, tt := range []struct {
		name             string
		path             string
		expectedMachine  elf.Machine
		knownHostMachine bool
		want             executableFormat
	}{
		{"known host matching ELF", matching, elf.EM_X86_64, true, executableFormatELF},
		{"known host foreign ELF", foreign, elf.EM_X86_64, true, executableFormatUnknown},
		{"unknown host matching ELF", matching, elf.EM_X86_64, false, executableFormatUnknown},
		{"unknown host foreign ELF", foreign, elf.EM_X86_64, false, executableFormatUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := inspectExecutableFormatForMachine(tt.path, tt.expectedMachine, tt.knownHostMachine)
			if err != nil || got != tt.want {
				t.Fatalf("inspectExecutableFormatForMachine(%q, %v, %v) = %v, %v; want %v", tt.path, tt.expectedMachine, tt.knownHostMachine, got, err, tt.want)
			}
		})
	}
}

func TestInspectExecutableFormatRejectsWrongEndianness(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wrong-endian")
	writeELFProgramHeaderFixtureMachineData(t, path, elf.EM_X86_64, elf.ELFDATA2MSB, elf.PT_LOAD)
	if got, err := inspectExecutableFormatForArchitecture(path, elf.EM_X86_64, elf.ELFDATA2LSB, elf.ELFCLASS64, true); err != nil || got != executableFormatUnknown {
		t.Fatalf("wrong-endian ELF = %v, %v; want unknown", got, err)
	}
}

func TestInspectExecutableFormatRejectsWrongClass(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wrong-class")
	data := make([]byte, 52+32)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1})
	binary.LittleEndian.PutUint16(data[16:18], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(data[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint32(data[28:32], 52)
	binary.LittleEndian.PutUint16(data[40:42], 52)
	binary.LittleEndian.PutUint16(data[42:44], 32)
	binary.LittleEndian.PutUint16(data[44:46], 1)
	binary.LittleEndian.PutUint32(data[52:56], uint32(elf.PT_LOAD))
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := inspectExecutableFormatForArchitecture(path, elf.EM_X86_64, elf.ELFDATA2LSB, elf.ELFCLASS64, true); err != nil || got != executableFormatUnknown {
		t.Fatalf("wrong-class ELF = %v, %v; want unknown", got, err)
	}
}

func TestInspectExecutableFormatUsesOpenedDescriptor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	validPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	validData, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, validData, 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("not an ELF"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	machine, known := hostELFMachine()
	got, err := inspectExecutableFormatFile(file, machine, elf.ELFDATANONE, elf.ELFCLASSNONE, known)
	if err != nil || got != executableFormatELF {
		t.Fatalf("opened descriptor classification = %v, %v; want ELF", got, err)
	}
}

func TestInspectExecutableFormatRequiresLoadableSegment(t *testing.T) {
	dir := t.TempDir()
	noteOnly := filepath.Join(dir, "note-only")
	writeELFProgramHeaderFixture(t, noteOnly, elf.PT_NOTE)
	if got, err := inspectExecutableFormat(noteOnly); err != nil || got != executableFormatMalformedELF {
		t.Fatalf("PT_NOTE-only ELF = %v, %v; want malformed ELF", got, err)
	}

	mixed := filepath.Join(dir, "mixed")
	writeELFProgramHeaderFixture(t, mixed, elf.PT_NOTE, elf.PT_LOAD)
	if got, err := inspectExecutableFormat(mixed); err != nil || got != executableFormatELF {
		t.Fatalf("mixed PT_NOTE/PT_LOAD ELF = %v, %v; want ELF", got, err)
	}
}

func TestSUIDFormatEndToEndRejectsNoteOnlyELF(t *testing.T) {
	dir := t.TempDir()
	noteOnly := filepath.Join(dir, "note-only")
	writeELFProgramHeaderFixture(t, noteOnly, elf.PT_NOTE)

	noteDiscovery := inspectCanonicalExecutable(executableDiscovery{CatalogName: "note-only", Found: true, InvocablePath: noteOnly, CanonicalPath: noteOnly})
	noteDiscovery.FileInfo = staticFileInfo{name: "note-only", mode: 0o755 | os.ModeSetuid, uid: 0}
	noteResult := evaluateContext("suid", nil, "", noteDiscovery, hostSnapshot{procStatus: procStatus{NoNewPrivsKnown: true}}, sudoProbeBatch{}, nil)
	if noteResult.State == stateConfirmed {
		t.Fatalf("PT_NOTE-only SUID became confirmed: %#v", noteResult)
	}

	validPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	validData, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	validFixture := filepath.Join(dir, "valid")
	if err := os.WriteFile(validFixture, validData, 0o755); err != nil {
		t.Fatal(err)
	}
	validDiscovery := inspectCanonicalExecutable(executableDiscovery{CatalogName: "valid", Found: true, InvocablePath: validFixture, CanonicalPath: validFixture})
	if validDiscovery.FileInfo == nil || validDiscovery.Format != executableFormatELF {
		t.Fatalf("real ELF discovery = %#v", validDiscovery)
	}
	validDiscovery.FileInfo = staticFileInfo{name: "valid", mode: 0o755 | os.ModeSetuid, uid: 0}
	validDiscovery.Mount = mountStatus{Known: true}
	validResult := evaluateContext("suid", nil, "", validDiscovery, hostSnapshot{procStatus: procStatus{NoNewPrivsKnown: true}}, sudoProbeBatch{}, nil)
	if validResult.State != stateConfirmed {
		t.Fatalf("real ELF SUID control = %#v", validResult)
	}
}

func TestSUIDFormatSafety(t *testing.T) {
	tests := []struct {
		name   string
		format executableFormat
		mode   os.FileMode
		uid    uint32
		want   applicabilityState
		events string
	}{
		{"valid ELF", executableFormatELF, 0o755 | os.ModeSetuid, 0, stateConfirmed, ""},
		{"malformed ELF", executableFormatMalformedELF, 0o755 | os.ModeSetuid, 0, stateUnknown, "ELF header could not be validated"},
		{"interpreter script", executableFormatScript, 0o755 | os.ModeSetuid, 0, stateUnavailable, "interpreter scripts ignore"},
		{"unknown format", executableFormatUnknown, 0o755 | os.ModeSetuid, 0, stateUnknown, "executable format could not be verified"},
		{"SGID-only ELF", executableFormatELF, 0o755 | os.ModeSetgid, 0, stateUnavailable, "does not have setuid bit"},
		{"non-root ELF", executableFormatELF, 0o755 | os.ModeSetuid, 1000, stateUnavailable, "owner UID is 1000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validSUIDEvaluationInput()
			input.Format = tt.format
			input.Mode = tt.mode
			input.OwnerUID = tt.uid
			got := evaluateSUID(input)
			if got.State != tt.want || (tt.events != "" && !warningContains(got.Evidence, tt.events)) {
				t.Fatalf("evaluateSUID() = %#v, want %q containing %q", got, tt.want, tt.events)
			}
		})
	}
}

func TestSUIDEvidenceOrder(t *testing.T) {
	input := validSUIDEvaluationInput()
	input.Mode &^= os.ModeSetuid
	input.OwnerUID = 1000
	input.Mount.NoExec = true
	input.Version = "fixture <= 1"
	want := []string{
		"canonical target does not have setuid bit",
		"canonical target owner UID is 1000, expected 0",
		"filesystem is mounted noexec",
		"version restriction was not verified: fixture <= 1",
	}
	if got := evaluateSUID(input); got.State != stateUnavailable || !reflect.DeepEqual(got.Evidence, want) {
		t.Fatalf("evaluateSUID() = %#v, want unavailable with %v", got, want)
	}
}

func capabilityXattrFixture(revision uint32, permitted, inheritable uint64, effective bool, rootID uint32) []byte {
	size := vfsCapabilityRevision2Size
	if revision == vfsCapabilityRevision3 {
		size = vfsCapabilityRevision3Size
	}
	data := make([]byte, size)
	magic := revision
	if effective {
		magic |= vfsCapabilityEffective
	}
	binary.LittleEndian.PutUint32(data[0:4], magic)
	binary.LittleEndian.PutUint32(data[4:8], uint32(permitted))
	binary.LittleEndian.PutUint32(data[8:12], uint32(inheritable))
	binary.LittleEndian.PutUint32(data[12:16], uint32(permitted>>32))
	binary.LittleEndian.PutUint32(data[16:20], uint32(inheritable>>32))
	if revision == vfsCapabilityRevision3 {
		binary.LittleEndian.PutUint32(data[20:24], rootID)
	}
	return data
}

func TestDecodeFileCapabilities(t *testing.T) {
	highPermitted := uint64(1) << unix.CAP_BPF
	highInheritable := uint64(1) << unix.CAP_CHECKPOINT_RESTORE
	tests := []struct {
		name string
		data []byte
		want fileCapabilities
	}{
		{
			"revision 2 lower words",
			capabilityXattrFixture(vfsCapabilityRevision2, uint64(1)<<unix.CAP_SETUID, uint64(1)<<unix.CAP_NET_RAW, false, 0),
			fileCapabilities{Revision: vfsCapabilityRevision2, Permitted: uint64(1) << unix.CAP_SETUID, Inheritable: uint64(1) << unix.CAP_NET_RAW},
		},
		{
			"revision 2 upper words and effective",
			capabilityXattrFixture(vfsCapabilityRevision2, highPermitted, highInheritable, true, 0),
			fileCapabilities{Revision: vfsCapabilityRevision2, Permitted: highPermitted, Inheritable: highInheritable, Effective: true},
		},
		{
			"revision 3 root ID and combined masks",
			capabilityXattrFixture(vfsCapabilityRevision3, highPermitted|1, highInheritable|2, true, 4242),
			fileCapabilities{Revision: vfsCapabilityRevision3, Permitted: highPermitted | 1, Inheritable: highInheritable | 2, Effective: true, RootID: 4242, HasRootID: true},
		},
		{
			"effective independent of permitted",
			capabilityXattrFixture(vfsCapabilityRevision2, 0, 0, true, 0),
			fileCapabilities{Revision: vfsCapabilityRevision2, Effective: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeFileCapabilities(tt.data)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("decoded capabilities = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestDecodeFileCapabilitiesRejectsMalformedData(t *testing.T) {
	revision2 := capabilityXattrFixture(vfsCapabilityRevision2, 1, 2, false, 0)
	revision3 := capabilityXattrFixture(vfsCapabilityRevision3, 1, 2, false, 3)
	unknown := make([]byte, vfsCapabilityRevision2Size)
	binary.LittleEndian.PutUint32(unknown[:4], 0x04000000)
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"truncated revision 2", revision2[:len(revision2)-1], "has length 19, want 20"},
		{"truncated revision 3", revision3[:len(revision3)-1], "has length 23, want 24"},
		{"empty", nil, "truncated"},
		{"short magic", []byte{1, 2, 3}, "truncated"},
		{"unknown revision", unknown, "unsupported security.capability revision"},
		{"unknown flags", append([]byte{0x03, 0x00, 0x00, 0x02}, revision2[4:]...), "unsupported flags"},
		{"overlong revision 2", append(revision2, 0), "has length 21, want 20"},
		{"overlong revision 3", append(revision3, 0), "has length 25, want 24"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeFileCapabilities(tt.data); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestFileCapabilityInspectionError(t *testing.T) {
	absent := fileCapabilityInspectionError(unix.ENODATA)
	if !absent.Known || absent.Present || absent.Err != nil {
		t.Fatalf("ENODATA classification = %#v", absent)
	}
	failed := fileCapabilityInspectionError(unix.EPERM)
	if failed.Known || failed.Present || failed.Err == nil {
		t.Fatalf("EPERM classification = %#v", failed)
	}
}

func TestParseRequiredCapabilities(t *testing.T) {
	highMask := uint64(1) << unix.CAP_BPF
	tests := []struct {
		name        string
		input       []string
		wantNames   []string
		wantMask    uint64
		wantUnknown []string
		wantKnown   bool
	}{
		{"canonical", []string{"CAP_SETUID"}, []string{"CAP_SETUID"}, uint64(1) << unix.CAP_SETUID, nil, true},
		{"lowercase", []string{"cap_setuid"}, []string{"CAP_SETUID"}, uint64(1) << unix.CAP_SETUID, nil, true},
		{"mixed case", []string{"Cap_Setuid"}, []string{"CAP_SETUID"}, uint64(1) << unix.CAP_SETUID, nil, true},
		{"surrounding whitespace", []string{" CAP_SETUID ", "\tCAP_BPF\n"}, []string{"CAP_BPF", "CAP_SETUID"}, uint64(1)<<unix.CAP_SETUID | uint64(1)<<unix.CAP_BPF, nil, true},
		{"modern high bit", []string{"CAP_BPF"}, []string{"CAP_BPF"}, highMask, nil, true},
		{"multiple", []string{"CAP_SETUID", "CAP_CHOWN"}, []string{"CAP_CHOWN", "CAP_SETUID"}, 1 | uint64(1)<<unix.CAP_SETUID, nil, true},
		{"duplicates", []string{"CAP_SETUID", "cap_setuid"}, []string{"CAP_SETUID"}, uint64(1) << unix.CAP_SETUID, nil, true},
		{"unknown", []string{"CAP_FIXTURE"}, nil, 0, []string{"CAP_FIXTURE"}, false},
		{"known and unknown", []string{"CAP_SETUID", "CAP_FIXTURE"}, []string{"CAP_SETUID"}, uint64(1) << unix.CAP_SETUID, []string{"CAP_FIXTURE"}, false},
		{"empty", []string{}, nil, 0, nil, false},
		{"nil", nil, nil, 0, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRequiredCapabilities(tt.input)
			if !reflect.DeepEqual(got.Names, tt.wantNames) || got.Mask != tt.wantMask || !reflect.DeepEqual(got.Unknown, tt.wantUnknown) || got.Known != tt.wantKnown {
				t.Fatalf("parseRequiredCapabilities(%v) = %#v", tt.input, got)
			}
		})
	}
}

func TestLinuxCapabilityMapIsComplete(t *testing.T) {
	if len(linuxCapabilityBits) != int(unix.CAP_LAST_CAP)+1 {
		t.Fatalf("capability map has %d entries, want %d", len(linuxCapabilityBits), int(unix.CAP_LAST_CAP)+1)
	}
	seen := make(map[uint]string)
	for name, bit := range linuxCapabilityBits {
		if previous, duplicate := seen[bit]; duplicate {
			t.Fatalf("capability bit %d is mapped by %q and %q", bit, previous, name)
		}
		seen[bit] = name
	}
	for bit := uint(0); bit <= uint(unix.CAP_LAST_CAP); bit++ {
		if _, ok := seen[bit]; !ok {
			t.Fatalf("capability bit %d is missing", bit)
		}
	}
	if bit := linuxCapabilityBits["CAP_CHECKPOINT_RESTORE"]; bit <= 31 || uint64(1)<<bit == 0 {
		t.Fatalf("high capability bit = %d", bit)
	}
}

func validCapabilityEvaluationInput() capabilityEvaluationInput {
	required := parseRequiredCapabilities([]string{"CAP_SETUID", "CAP_BPF"})
	return capabilityEvaluationInput{
		FileInspected:    true,
		Regular:          true,
		Executable:       true,
		Mount:            mountStatus{Known: true},
		NoNewPrivsKnown:  true,
		CapBndKnown:      true,
		CapBnd:           required.Mask,
		Required:         required,
		Xattr:            fileCapabilityInspection{Known: true, Present: true, Capabilities: fileCapabilities{Permitted: required.Mask, Effective: true}},
		RequireEffective: true,
	}
}

func TestEvaluateCapabilities(t *testing.T) {
	unsupportedData := make([]byte, vfsCapabilityRevision2Size)
	binary.LittleEndian.PutUint32(unsupportedData[:4], 0x04000000)
	_, unsupportedErr := decodeFileCapabilities(unsupportedData)
	truncated := capabilityXattrFixture(vfsCapabilityRevision2, 1, 0, false, 0)[:10]
	_, truncatedErr := decodeFileCapabilities(truncated)

	tests := []struct {
		name     string
		change   func(*capabilityEvaluationInput)
		want     applicabilityState
		evidence string
	}{
		{"fully satisfied", func(*capabilityEvaluationInput) {}, stateConfirmed, ""},
		{"V3 namespace root ID is conservative", func(input *capabilityEvaluationInput) {
			input.Xattr.Capabilities.Revision = vfsCapabilityRevision3
			input.Xattr.Capabilities.RootID = 4242
			input.Xattr.Capabilities.HasRootID = true
		}, stateUnknown, "V3 file capability namespace root ID compatibility could not be verified"},
		{"V3 missing capability still unavailable", func(input *capabilityEvaluationInput) {
			input.Xattr.Capabilities.Revision = vfsCapabilityRevision3
			input.Xattr.Capabilities.HasRootID = true
			input.Xattr.Capabilities.Permitted &^= uint64(1) << unix.CAP_SETUID
		}, stateUnavailable, "CAP_SETUID is missing from file permitted set"},
		{"required permitted bit absent", func(input *capabilityEvaluationInput) {
			input.Xattr.Capabilities.Permitted &^= uint64(1) << unix.CAP_SETUID
		}, stateUnavailable, "CAP_SETUID is missing from file permitted set"},
		{"multiple required one absent", func(input *capabilityEvaluationInput) {
			input.Required = parseRequiredCapabilities([]string{"CAP_CHOWN", "CAP_SETUID", "CAP_BPF"})
			input.CapBnd = input.Required.Mask
		}, stateUnavailable, "CAP_CHOWN is missing from file permitted set"},
		{"effective required and absent", func(input *capabilityEvaluationInput) { input.Xattr.Capabilities.Effective = false }, stateUnavailable, "effective flag is not set"},
		{"effective not required", func(input *capabilityEvaluationInput) {
			input.RequireEffective = false
			input.Xattr.Capabilities.Effective = false
		}, stateConfirmed, ""},
		{"CapBnd excludes required bit", func(input *capabilityEvaluationInput) { input.CapBnd &^= uint64(1) << unix.CAP_BPF }, stateUnavailable, "CAP_BPF is excluded by CapBnd"},
		{"CapBnd unknown", func(input *capabilityEvaluationInput) { input.CapBndKnown = false }, stateUnknown, "CapBnd could not be determined"},
		{"empty requirement", func(input *capabilityEvaluationInput) { input.Required = parseRequiredCapabilities(nil) }, stateUnknown, "required capability list is empty"},
		{"unknown capability", func(input *capabilityEvaluationInput) {
			input.Required = parseRequiredCapabilities([]string{"CAP_SETUID", "CAP_FIXTURE"})
			input.CapBnd = input.Required.Mask
		}, stateUnknown, "unknown required capability CAP_FIXTURE"},
		{"xattr absent", func(input *capabilityEvaluationInput) { input.Xattr = fileCapabilityInspection{Known: true} }, stateUnavailable, "security.capability is not present"},
		{"xattr inspection failed", func(input *capabilityEvaluationInput) {
			input.Xattr = fileCapabilityInspection{Err: errors.New("permission denied")}
		}, stateUnknown, "permission denied"},
		{"unsupported xattr format", func(input *capabilityEvaluationInput) {
			input.Xattr = fileCapabilityInspection{Present: true, Err: unsupportedErr}
		}, stateUnknown, "unsupported security.capability revision"},
		{"truncated xattr", func(input *capabilityEvaluationInput) {
			input.Xattr = fileCapabilityInspection{Present: true, Err: truncatedErr}
		}, stateUnknown, "has length 10, want 20"},
		{"nosuid", func(input *capabilityEvaluationInput) { input.Mount.NoSUID = true }, stateUnavailable, "mounted nosuid"},
		{"noexec", func(input *capabilityEvaluationInput) { input.Mount.NoExec = true }, stateUnavailable, "mounted noexec"},
		{"NoNewPrivs enabled", func(input *capabilityEvaluationInput) { input.NoNewPrivs = true }, stateUnavailable, "NoNewPrivs is enabled"},
		{"non-initial user namespace", func(input *capabilityEvaluationInput) {
			input.UserNamespaceKnown = true
			input.InitialUserNamespace = false
		}, stateUnavailable, "initial user namespace"},
		{"NoNewPrivs unknown", func(input *capabilityEvaluationInput) { input.NoNewPrivsKnown = false }, stateUnknown, "NoNewPrivs could not be determined"},
		{"mount unknown", func(input *capabilityEvaluationInput) { input.Mount.Known = false }, stateUnknown, "mount flags could not be determined"},
		{"version restriction", func(input *capabilityEvaluationInput) { input.Version = "fixture <= 1" }, stateUnknown, "version restriction was not verified"},
		{"missing bit outranks version", func(input *capabilityEvaluationInput) {
			input.Xattr.Capabilities.Permitted &^= uint64(1) << unix.CAP_SETUID
			input.Version = "fixture <= 1"
		}, stateUnavailable, "CAP_SETUID is missing from file permitted set"},
		{"bounding exclusion outranks unknown xattr", func(input *capabilityEvaluationInput) {
			input.CapBnd &^= uint64(1) << unix.CAP_BPF
			input.Xattr = fileCapabilityInspection{Err: errors.New("inspection unavailable")}
		}, stateUnavailable, "CAP_BPF is excluded by CapBnd"},
		{"file inspection unknown", func(input *capabilityEvaluationInput) { input.FileInspected = false }, stateUnknown, "file information could not be determined"},
		{"non-regular target", func(input *capabilityEvaluationInput) { input.Regular = false }, stateUnavailable, "not a regular file"},
		{"non-executable target", func(input *capabilityEvaluationInput) { input.Executable = false }, stateUnavailable, "not executable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validCapabilityEvaluationInput()
			tt.change(&input)
			got := evaluateCapabilities(input)
			if got.State != tt.want {
				t.Fatalf("state = %q, want %q; evidence %v", got.State, tt.want, got.Evidence)
			}
			if tt.want == stateConfirmed && len(got.Evidence) != 0 {
				t.Fatalf("confirmed result has evidence %v", got.Evidence)
			}
			if tt.want != stateConfirmed && (len(got.Evidence) == 0 || !warningContains(got.Evidence, tt.evidence)) {
				t.Fatalf("evidence = %v, want containing %q", got.Evidence, tt.evidence)
			}
			if again := evaluateCapabilities(input); !reflect.DeepEqual(got, again) {
				t.Fatalf("evidence order changed: first %v, second %v", got.Evidence, again.Evidence)
			}
		})
	}
}

func validSudoEvaluationInput() sudoEvaluationInput {
	return sudoEvaluationInput{
		EffectiveUID:   1000,
		SudoPresent:    true,
		ProbeRequested: true,
		Probe:          sudoProbeResult{Status: sudoProbeRecognized},
	}
}

func TestEvaluateSudo(t *testing.T) {
	tests := []struct {
		name     string
		change   func(*sudoEvaluationInput)
		want     applicabilityState
		evidence string
	}{
		{"sudo absent", func(input *sudoEvaluationInput) { input.SudoPresent = false }, stateUnavailable, "not safely available"},
		{"effective UID zero", func(input *sudoEvaluationInput) { input.EffectiveUID = 0 }, stateConfirmed, "effective UID is 0"},
		{"effective UID zero with version", func(input *sudoEvaluationInput) { input.EffectiveUID = 0; input.Version = "fixture <= 1" }, stateUnknown, "version restriction was not verified"},
		{"non-root without probe", func(input *sudoEvaluationInput) { input.ProbeRequested = false }, stateUnknown, "use -check-sudo"},
		{"successful probe", func(*sudoEvaluationInput) {}, statePotential, "does not prove the full GTFOBins command line"},
		{"successful probe with version", func(input *sudoEvaluationInput) { input.Version = "fixture <= 1" }, stateUnknown, "version restriction was not verified"},
		{"nonzero probe", func(input *sudoEvaluationInput) { input.Probe.Status = sudoProbeNonzero }, stateUnknown, "nonzero result"},
		{"execution error", func(input *sudoEvaluationInput) {
			input.Probe = sudoProbeResult{Status: sudoProbeExecutionError, Err: errors.New("fixture failure")}
		}, stateUnknown, "fixture failure"},
		{"budget exhausted", func(input *sudoEvaluationInput) { input.Probe.Status = sudoProbeBudgetExhausted }, stateUnknown, "global sudo probe budget expired"},
		{"probe result missing", func(input *sudoEvaluationInput) { input.Probe.Status = sudoProbeNotAttempted }, stateUnknown, "no result is available"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validSudoEvaluationInput()
			tt.change(&input)
			got := evaluateSudo(input)
			if got.State != tt.want || !warningContains(got.Evidence, tt.evidence) {
				t.Fatalf("evaluateSudo() = %#v, want %q with evidence containing %q", got, tt.want, tt.evidence)
			}
			if tt.want != stateConfirmed && len(got.Evidence) == 0 {
				t.Fatal("non-confirmed sudo result has no evidence")
			}
			if input.EffectiveUID != 0 && input.Probe.Status == sudoProbeRecognized && got.State == stateConfirmed {
				t.Fatal("successful sudo path probe was classified as confirmed")
			}
			if again := evaluateSudo(input); !reflect.DeepEqual(got, again) {
				t.Fatalf("sudo evidence order changed: first %v, second %v", got.Evidence, again.Evidence)
			}
		})
	}
}

func TestSudoEvidenceOrder(t *testing.T) {
	input := validSudoEvaluationInput()
	input.Version = "fixture <= 1"
	want := []string{
		"sudo policy recognized the canonical executable path",
		"path-level sudo evidence does not prove the full GTFOBins command line is authorized",
		"version restriction was not verified: fixture <= 1",
	}
	if got := evaluateSudo(input); got.State != stateUnknown || !reflect.DeepEqual(got.Evidence, want) {
		t.Fatalf("evaluateSudo() = %#v, want unknown with %v", got, want)
	}
}

func TestNewSudoCommandIsNonInteractiveAndCanonical(t *testing.T) {
	sudoPath := "/fixture/sudo"
	canonicalPath := "/canonical/Case Tool"
	command := newSudoCommand(context.Background(), sudoPath, canonicalPath)
	want := []string{sudoPath, "-n", "-l", canonicalPath}
	if command.Path != sudoPath || !reflect.DeepEqual(command.Args, want) {
		t.Fatalf("sudo command path/args = %q/%v, want %q/%v", command.Path, command.Args, sudoPath, want)
	}
	if command.Stdin != nil || command.Stdout != nil || command.Stderr != nil {
		t.Fatal("sudo command unexpectedly attached process I/O")
	}
}

func fakeSudoPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := writeTestExecutable(t, dir, "sudo")
	t.Setenv("PATH", dir)
	return path
}

func TestProbeSudoPoliciesRunnerOutcomes(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status sudoProbeStatus
	}{
		{"success", nil, sudoProbeRecognized},
		{"nonzero", &exec.ExitError{}, sudoProbeNonzero},
		{"execution failure", errors.New("fixture failure"), sudoProbeExecutionError},
		{"runner context cancellation", context.Canceled, sudoProbeExecutionError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sudoPath := fakeSudoPath(t)
			canonicalPath := "/canonical/Fixture Tool"
			calls := 0
			batch := probeSudoPoliciesWithResolver(context.Background(), true, []executableDiscovery{{CanonicalPath: canonicalPath}}, func(_ context.Context, gotSudo, gotCanonical string) error {
				calls++
				if gotSudo != sudoPath || gotCanonical != canonicalPath {
					t.Fatalf("runner arguments = %q, %q; want %q, %q", gotSudo, gotCanonical, sudoPath, canonicalPath)
				}
				return tt.err
			}, func() (string, error) { return sudoPath, nil })
			if calls != 1 || batch.SudoPath != sudoPath || batch.LookupErr != nil || batch.Results[canonicalPath].Status != tt.status {
				t.Fatalf("probe batch = %#v, calls = %d", batch, calls)
			}
		})
	}
}

func TestProbeSudoPoliciesUsesOnlyCanonicalPath(t *testing.T) {
	fakeSudoPath(t)
	invocablePath := "/invocable/symlink"
	canonicalPath := "/canonical/Exact Case --fixture"
	catalogCommand := "fixture-command | must-never-run"
	discoveries := []executableDiscovery{{InvocablePath: invocablePath, CanonicalPath: canonicalPath}}
	var received string
	probeSudoPoliciesWithResolver(context.Background(), true, discoveries, func(_ context.Context, _, path string) error {
		received = path
		return nil
	}, func() (string, error) { return filepath.Join(t.TempDir(), "sudo"), nil })
	if received != canonicalPath || received == invocablePath || received == catalogCommand {
		t.Fatalf("runner received %q, want canonical path %q only", received, canonicalPath)
	}
}

func TestProbeSudoPoliciesCachesCanonicalPaths(t *testing.T) {
	fakeSudoPath(t)
	discoveries := []executableDiscovery{
		{CatalogName: "catalog-a", InvocablePath: "/alias/a", CanonicalPath: "/canonical/shared"},
		{CatalogName: "catalog-b", InvocablePath: "/alias/b", CanonicalPath: "/canonical/shared"},
		{CatalogName: "catalog-c", CanonicalPath: "/canonical/other"},
		{CatalogName: "missing-canonical"},
	}
	before := slices.Clone(discoveries)
	calls := make(map[string]int)
	runner := func(_ context.Context, _, path string) error {
		calls[path]++
		return nil
	}
	first := probeSudoPoliciesWithResolver(context.Background(), true, discoveries, runner, func() (string, error) { return filepath.Join(t.TempDir(), "sudo"), nil })
	if calls["/canonical/shared"] != 1 || calls["/canonical/other"] != 1 || len(calls) != 2 || len(first.Results) != 2 {
		t.Fatalf("cache calls/results = %v/%v", calls, first.Results)
	}
	if first.Results["/canonical/shared"].Status != sudoProbeRecognized || first.Results["/canonical/other"].Status != sudoProbeRecognized {
		t.Fatalf("cached results = %#v", first.Results)
	}
	if _, ok := first.Results[""]; ok {
		t.Fatal("empty canonical path was probed")
	}
	if !reflect.DeepEqual(discoveries, before) || len(discoveries) != 4 {
		t.Fatal("probe cache deduplicated or modified catalog discoveries")
	}

	secondCalls := 0
	second := probeSudoPoliciesWithResolver(context.Background(), true, discoveries, func(context.Context, string, string) error {
		secondCalls++
		return nil
	}, func() (string, error) { return first.SudoPath, nil })
	if secondCalls != 2 || !reflect.DeepEqual(first.Results, second.Results) {
		t.Fatalf("repeated cache is not deterministic: calls %d, first %v, second %v", secondCalls, first.Results, second.Results)
	}
}

func TestProbeSudoPoliciesGlobalBudget(t *testing.T) {
	t.Run("already cancelled", func(t *testing.T) {
		fakeSudoPath(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		discoveries := []executableDiscovery{
			{CanonicalPath: "/canonical/one"},
			{CanonicalPath: "/canonical/two"},
		}
		calls := 0
		batch := probeSudoPoliciesWithResolver(ctx, true, discoveries, func(context.Context, string, string) error {
			calls++
			return nil
		}, func() (string, error) { return filepath.Join(t.TempDir(), "sudo"), nil })
		if calls != 0 {
			t.Fatalf("runner called %d times after budget expiration", calls)
		}
		for _, discovery := range discoveries {
			result := batch.Results[discovery.CanonicalPath]
			if result.Status != sudoProbeBudgetExhausted {
				t.Fatalf("result for %q = %#v, want budget exhausted", discovery.CanonicalPath, result)
			}
			evaluated := evaluateSudo(sudoEvaluationInput{
				EffectiveUID:   1000,
				SudoPresent:    true,
				ProbeRequested: true,
				Probe:          result,
			})
			if evaluated.State != stateUnknown || !warningContains(evaluated.Evidence, "global sudo probe budget expired") {
				t.Fatalf("budget evaluation = %#v", evaluated)
			}
		}
	})

	t.Run("expiration preserves completed cache and stops new probes", func(t *testing.T) {
		fakeSudoPath(t)
		ctx, cancel := context.WithCancel(context.Background())
		discoveries := []executableDiscovery{
			{CanonicalPath: "/canonical/completed"},
			{CanonicalPath: "/canonical/unstarted"},
			{CanonicalPath: "/canonical/completed"},
			{CanonicalPath: "/canonical/also-unstarted"},
		}
		calls := 0
		batch := probeSudoPoliciesWithResolver(ctx, true, discoveries, func(context.Context, string, string) error {
			calls++
			cancel()
			return nil
		}, func() (string, error) { return filepath.Join(t.TempDir(), "sudo"), nil })
		if calls != 1 {
			t.Fatalf("runner called %d times, want 1", calls)
		}
		if got := batch.Results["/canonical/completed"].Status; got != sudoProbeRecognized {
			t.Fatalf("completed cached result = %v, want recognized", got)
		}
		for _, path := range []string{"/canonical/unstarted", "/canonical/also-unstarted"} {
			if got := batch.Results[path].Status; got != sudoProbeBudgetExhausted {
				t.Fatalf("unstarted result for %q = %v, want budget exhausted", path, got)
			}
		}
	})
}

func TestProbeSudoPoliciesDisabledDoesNothing(t *testing.T) {
	dir := t.TempDir()
	writeTestExecutable(t, dir, "sudo")
	t.Chdir(dir)
	t.Setenv("PATH", ".")
	calls := 0
	discoveries := []executableDiscovery{
		{CatalogName: "sudo-fixture-a", CanonicalPath: "/canonical/fixture-a"},
		{CatalogName: "sudo-fixture-b", CanonicalPath: "/canonical/fixture-b"},
	}
	batch := probeSudoPolicies(context.Background(), false, discoveries, func(context.Context, string, string) error {
		calls++
		return nil
	})
	if calls != 0 || batch.SudoPath != "" || batch.LookupErr != nil || len(batch.Results) != 0 {
		t.Fatalf("disabled probe did work: calls=%d batch=%#v", calls, batch)
	}
}

func TestProbeSudoPoliciesLookupFailures(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		calls := 0
		batch := probeSudoPolicies(context.Background(), true, []executableDiscovery{{CanonicalPath: "/canonical/fixture"}}, func(context.Context, string, string) error {
			calls++
			return nil
		})
		if calls != 0 || batch.SudoPath != "" || batch.LookupErr == nil {
			t.Fatalf("absent sudo result: calls=%d batch=%#v", calls, batch)
		}
	})

	t.Run("current directory rejected", func(t *testing.T) {
		dir := t.TempDir()
		writeTestExecutable(t, dir, "sudo")
		t.Chdir(dir)
		t.Setenv("PATH", ".")
		calls := 0
		batch := probeSudoPolicies(context.Background(), true, []executableDiscovery{{CanonicalPath: "/canonical/fixture"}}, func(context.Context, string, string) error {
			calls++
			return nil
		})
		if calls != 0 || batch.SudoPath != "" || batch.LookupErr == nil || !warningContains([]string{batch.LookupErr.Error()}, "not safely available") {
			t.Fatalf("unsafe sudo result: calls=%d batch=%#v", calls, batch)
		}
	})
}

func TestProbeSudoPoliciesDoesNotUseUntrustedCandidate(t *testing.T) {
	dir := t.TempDir()
	writeTestExecutable(t, dir, "sudo")
	t.Setenv("PATH", dir)
	calls := 0
	batch := probeSudoPolicies(context.Background(), true, []executableDiscovery{{CanonicalPath: "/canonical/fixture"}}, func(context.Context, string, string) error {
		calls++
		return nil
	})
	if calls != 0 || batch.SudoPath != "" || batch.LookupErr == nil {
		t.Fatalf("untrusted sudo was probed: calls=%d batch=%#v", calls, batch)
	}
}

func TestHelpDocumentsCheckSudo(t *testing.T) {
	previous := plainMode
	defer func() { plainMode = previous }()
	for _, plain := range []bool{true, false} {
		plainMode = plain
		output := captureProcessOutput(t, printHelp)
		if !strings.Contains(output, "-check-sudo") || !strings.Contains(output, "Check sudo policy non-interactively; checks may be logged") {
			t.Fatalf("plain=%v help does not document safe sudo probing: %q", plain, output)
		}
	}
}

func TestEvaluateDiscoveryAndUnprivileged(t *testing.T) {
	base := staticDiscovery("Tool", "/Fixture/Bin/Tool", "/Fixture/Bin/Tool", 0o755, mountStatus{Known: true})
	tests := []struct {
		name     string
		change   func(*executableDiscovery)
		version  string
		want     applicabilityState
		evidence string
	}{
		{"usable", func(*executableDiscovery) {}, "", stateConfirmed, ""},
		{"not found", func(value *executableDiscovery) { value.Found = false }, "", stateUnavailable, "not found in PATH"},
		{"inspection failed", func(value *executableDiscovery) { value.FileInfo = nil; value.Mount = mountStatus{} }, "", stateUnknown, "file information could not be determined"},
		{"not regular", func(value *executableDiscovery) {
			value.FileInfo = staticFileInfo{name: "Tool", mode: os.ModeDir | 0o755}
		}, "", stateUnavailable, "not a regular file"},
		{"not executable", func(value *executableDiscovery) { value.Executable = false }, "", stateUnavailable, "not executable"},
		{"mount unknown", func(value *executableDiscovery) { value.Mount = mountStatus{} }, "", stateUnknown, "mount flags could not be determined"},
		{"noexec", func(value *executableDiscovery) { value.Mount.NoExec = true }, "", stateUnavailable, "mounted noexec"},
		{"version", func(*executableDiscovery) {}, "fixture <= 1", stateUnknown, "version restriction was not verified"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			discovery := base
			tt.change(&discovery)
			got := evaluateUnprivileged(discovery, tt.version)
			if got.State != tt.want || (tt.evidence != "" && !warningContains(got.Evidence, tt.evidence)) {
				t.Fatalf("evaluateUnprivileged() = %#v, want %q containing %q", got, tt.want, tt.evidence)
			}
		})
	}
}

func TestEvaluateFindingsIntegratesContexts(t *testing.T) {
	path := "/Fixture/Bin/Tool"
	discovery := staticDiscovery("Tool", path, path, os.ModeSetuid|0o755, mountStatus{Known: true})
	required := uint64(1) << unix.CAP_SETUID
	host := hostSnapshot{
		procStatus:   procStatus{NoNewPrivsKnown: true, CapBndKnown: true, CapBnd: required},
		EffectiveUID: 1000,
		SudoPresent:  true,
	}
	base := finding{Name: "Tool", Techniques: []technique{
		{FunctionKey: "command", ContextKey: "unprivileged", Code: "unprivileged-code"},
		{FunctionKey: "command", ContextKey: "suid", Code: "suid-code"},
		{FunctionKey: "command", ContextKey: "capabilities", ContextList: []string{"CAP_SETUID"}, Code: "capability-code"},
		{FunctionKey: "command", ContextKey: "sudo", Code: "sudo-code"},
		{FunctionKey: "command", ContextKey: "future-context", ContextLabel: "Future", Code: "future-code"},
	}}
	capabilities := map[string]fileCapabilityInspection{
		path: {Known: true, Present: true, Capabilities: fileCapabilities{Permitted: required, Effective: true}},
	}

	evaluated := evaluateFindings([]finding{base}, []executableDiscovery{discovery}, host, sudoProbeBatch{}, capabilities)
	if len(evaluated) != 1 || evaluated[0].InvocablePath != path || evaluated[0].CanonicalPath != path {
		t.Fatalf("evaluated finding = %#v", evaluated)
	}
	want := map[string]applicabilityState{
		"unprivileged":   stateConfirmed,
		"suid":           stateConfirmed,
		"capabilities":   stateConfirmed,
		"sudo":           stateUnknown,
		"future-context": stateUnknown,
	}
	for _, candidate := range evaluated[0].Techniques {
		if candidate.State != want[candidate.ContextKey] {
			t.Fatalf("context %q state = %q, want %q; evidence %v", candidate.ContextKey, candidate.State, want[candidate.ContextKey], candidate.Evidence)
		}
	}
	if !warningContains(techniqueNamed(t, evaluated[0], "command", "future-context").Evidence, "no evaluator") {
		t.Fatal("unknown context lacks evaluator evidence")
	}
	unknownOnNoExec := discovery
	unknownOnNoExec.Mount.NoExec = true
	unknownResult := evaluateFindings([]finding{base}, []executableDiscovery{unknownOnNoExec}, host, sudoProbeBatch{}, capabilities)[0]
	if value := techniqueNamed(t, unknownResult, "command", "future-context"); value.State != stateUnknown {
		t.Fatalf("unknown context was remapped by host state: %#v", value)
	}

	t.Run("SUID unavailable evidence reaches technique", func(t *testing.T) {
		withoutSetuid := discovery
		withoutSetuid.FileInfo = staticFileInfo{name: "Tool", mode: 0o755}
		result := evaluateFindings([]finding{base}, []executableDiscovery{withoutSetuid}, host, sudoProbeBatch{}, capabilities)[0]
		value := techniqueNamed(t, result, "command", "suid")
		if value.State != stateUnavailable || !warningContains(value.Evidence, "does not have setuid bit") {
			t.Fatalf("SUID result = %#v", value)
		}
	})

	t.Run("capability missing and unknown requirements", func(t *testing.T) {
		missing := map[string]fileCapabilityInspection{path: {Known: true}}
		result := evaluateFindings([]finding{base}, []executableDiscovery{discovery}, host, sudoProbeBatch{}, missing)[0]
		if value := techniqueNamed(t, result, "command", "capabilities"); value.State != stateUnavailable || !warningContains(value.Evidence, "not present") {
			t.Fatalf("missing capability result = %#v", value)
		}

		unknown := base
		unknown.Techniques = slices.Clone(base.Techniques)
		for index := range unknown.Techniques {
			if unknown.Techniques[index].ContextKey == "capabilities" {
				unknown.Techniques[index].ContextList = []string{"CAP_FIXTURE"}
			}
		}
		result = evaluateFindings([]finding{unknown}, []executableDiscovery{discovery}, host, sudoProbeBatch{}, capabilities)[0]
		if value := techniqueNamed(t, result, "command", "capabilities"); value.State != stateUnknown || !warningContains(value.Evidence, "CAP_FIXTURE") {
			t.Fatalf("unknown capability result = %#v", value)
		}
	})

	t.Run("sudo recognized version and effective UID zero", func(t *testing.T) {
		requested := host
		requested.SudoProbeRequested = true
		batch := sudoProbeBatch{SudoPath: "/usr/bin/sudo", Results: map[string]sudoProbeResult{path: {Status: sudoProbeRecognized}}}
		result := evaluateFindings([]finding{base}, []executableDiscovery{discovery}, requested, batch, capabilities)[0]
		if value := techniqueNamed(t, result, "command", "sudo"); value.State != statePotential {
			t.Fatalf("recognized sudo result = %#v", value)
		}

		versioned := base
		versioned.Techniques = slices.Clone(base.Techniques)
		for index := range versioned.Techniques {
			if versioned.Techniques[index].ContextKey == "sudo" {
				versioned.Techniques[index].Version = "fixture <= 1"
			}
		}
		result = evaluateFindings([]finding{versioned}, []executableDiscovery{discovery}, requested, batch, capabilities)[0]
		if value := techniqueNamed(t, result, "command", "sudo"); value.State != stateUnknown {
			t.Fatalf("versioned sudo result = %#v", value)
		}

		root := host
		root.EffectiveUID = 0
		result = evaluateFindings([]finding{base}, []executableDiscovery{discovery}, root, sudoProbeBatch{}, capabilities)[0]
		if value := techniqueNamed(t, result, "command", "sudo"); value.State != stateConfirmed {
			t.Fatalf("effective UID zero sudo result = %#v", value)
		}
	})
}

func TestInheritanceAndCompanionUncertainty(t *testing.T) {
	discovery := staticDiscovery("Parent", "/Fixture/Parent", "/Fixture/Parent", 0o755, mountStatus{Known: true})
	host := hostSnapshot{procStatus: procStatus{NoNewPrivsKnown: true, CapBndKnown: true}}
	value := finding{Name: "Parent", Techniques: []technique{{
		FunctionKey: "command",
		ContextKey:  "unprivileged",
		Code:        "target-code",
		Launchers: []launcherStep{{
			Executable: "Parent",
			ContextKey: "unprivileged",
			Code:       "launcher-code",
			Version:    "launcher <= 1",
		}},
	}}}
	result := evaluateFindings([]finding{value}, []executableDiscovery{discovery}, host, sudoProbeBatch{}, nil)[0]
	candidate := result.Techniques[0]
	if candidate.State != stateUnknown || candidate.Code != "target-code" || candidate.Launchers[0].Code != "launcher-code" || !warningContains(candidate.Evidence, "launcher <= 1") {
		t.Fatalf("inheritance evaluation = %#v", candidate)
	}

	value.Techniques[0].Launchers = nil
	value.Techniques[0].Warnings = []string{"companion listener reference is missing"}
	result = evaluateFindings([]finding{value}, []executableDiscovery{discovery}, host, sudoProbeBatch{}, nil)[0]
	candidate = result.Techniques[0]
	if candidate.State != stateUnknown || !reflect.DeepEqual(candidate.Warnings, value.Techniques[0].Warnings) || !warningContains(candidate.Evidence, "unresolved companion prerequisite") {
		t.Fatalf("companion uncertainty = %#v", candidate)
	}
}

func TestCapabilityInspectionCache(t *testing.T) {
	findings := []finding{
		{Name: "A", Techniques: []technique{{ContextKey: "capabilities"}}},
		{Name: "B", Techniques: []technique{{ContextKey: "capabilities"}}},
		{Name: "C", Techniques: []technique{{ContextKey: "unprivileged"}}},
		{Name: "D", Techniques: []technique{{ContextKey: "unprivileged", Launchers: []launcherStep{{ContextKey: "capabilities"}}}}},
	}
	discoveries := []executableDiscovery{
		staticDiscovery("A", "/Alias/A", "/Canonical/Shared", 0o755, mountStatus{Known: true}),
		staticDiscovery("B", "/Alias/B", "/Canonical/Shared", 0o755, mountStatus{Known: true}),
		staticDiscovery("C", "/Canonical/C", "/Canonical/C", 0o755, mountStatus{Known: true}),
		staticDiscovery("D", "/Canonical/D", "/Canonical/D", 0o755, mountStatus{Known: true}),
	}
	calls := make(map[string]int)
	cache := collectCapabilityInspections(findings, discoveries, func(path string) fileCapabilityInspection {
		calls[path]++
		return fileCapabilityInspection{Known: true}
	})
	if len(cache) != 2 || calls["/Canonical/Shared"] != 1 || calls["/Canonical/D"] != 1 || calls["/Canonical/C"] != 0 {
		t.Fatalf("capability cache/calls = %#v/%v", cache, calls)
	}
}

func TestSudoProbeBatchStatus(t *testing.T) {
	tests := []struct {
		name      string
		requested bool
		batch     sudoProbeBatch
		want      string
	}{
		{"not requested", false, sudoProbeBatch{}, "not requested"},
		{"lookup unavailable", true, sudoProbeBatch{LookupErr: errors.New("missing")}, "unavailable"},
		{"not attempted", true, sudoProbeBatch{}, "unavailable"},
		{"completed", true, sudoProbeBatch{SudoPath: "/usr/bin/sudo", Results: map[string]sudoProbeResult{"/tool": {Status: sudoProbeRecognized}}}, "completed"},
		{"partial timeout", true, sudoProbeBatch{SudoPath: "/usr/bin/sudo", Results: map[string]sudoProbeResult{"/tool": {Status: sudoProbeBudgetExhausted}}}, "partial timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sudoProbeBatchStatus(tt.requested, tt.batch); got != tt.want {
				t.Fatalf("sudoProbeBatchStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseOptionsAndHelpBeforeNetwork(t *testing.T) {
	for raw, want := range map[string]sortMode{
		"binary": sortBinary, "b": sortBinary,
		"context": sortContext, "c": sortContext, "ctx": sortContext, "privilege": sortContext,
		"attack": sortAttack, "a": sortAttack, "mitre": sortAttack,
	} {
		value, err := parseOptions([]string{"-sort", raw})
		if err != nil || value.Sort != want {
			t.Fatalf("parseOptions(-sort %s) = %#v, %v", raw, value, err)
		}
	}
	value, err := parseOptions([]string{"-plain", "-all", "-check-sudo", "-search", "Tool"})
	if err != nil || !value.Plain || !value.All || !value.CheckSudo || value.Search != "Tool" {
		t.Fatalf("parsed options = %#v, %v", value, err)
	}
	if _, err := parseOptions([]string{"-sort", "invalid"}); err == nil {
		t.Fatal("invalid sort was accepted")
	}

	for _, args := range [][]string{{"-plain", "-h"}, {"-plain", "-help"}} {
		calls := 0
		output := captureProcessOutput(t, func() {
			if code := runWithCatalogFetcher(args, func(context.Context) (catalog, error) {
				calls++
				return catalog{}, errors.New("catalog fetch must not run")
			}); code != 0 {
				t.Fatalf("help exit = %d", code)
			}
		})
		if calls != 0 {
			t.Fatalf("help fetched the catalog %d times", calls)
		}
		for _, text := range []string{"goGTFO identifies GTFOBins", "never executes GTFOBins techniques", "-all", "-check-sudo", "binary, context, or attack"} {
			if !strings.Contains(output, text) {
				t.Fatalf("help lacks %q: %s", text, output)
			}
		}
		for _, stale := range []string{"LOLBAS", "Windows", "Administrator", "SYSTEM", "Aaron Kidwell", "-driver"} {
			if strings.Contains(output, stale) {
				t.Fatalf("help contains stale runtime wording %q: %s", stale, output)
			}
		}
	}
}

func TestRunExitCodesAndCLIContract(t *testing.T) {
	previousPlainMode := plainMode
	defer func() { plainMode = previousPlainMode }()

	runWith := func(args []string, data catalog, fetchErr error) (int, string, string, int) {
		calls := 0
		code := -1
		stdout, stderr := captureProcessStreams(t, func() {
			code = runWithCatalogFetcher(args, func(context.Context) (catalog, error) {
				calls++
				return data, fetchErr
			})
		})
		return code, stdout, stderr, calls
	}

	t.Run("invalid options never fetch", func(t *testing.T) {
		for _, test := range []struct {
			args      []string
			errorText string
		}{
			{[]string{"-plain", "-sort", "invalid"}, "unknown sort"},
			{[]string{"-plain", "-driver"}, "flag provided but not defined: -driver"},
			{[]string{"-plain", "unexpected"}, "unexpected arguments"},
		} {
			code, _, stderr, calls := runWith(test.args, catalog{}, errors.New("catalog fetch must not run"))
			if code != 2 || calls != 0 || !strings.Contains(stderr, test.errorText) {
				t.Fatalf("run(%v) = code %d, calls %d, stderr %q", test.args, code, calls, stderr)
			}
		}
	})

	t.Run("fetch parse and validation failures", func(t *testing.T) {
		tests := []struct {
			name string
			err  error
		}{
			{"fetch", errors.New("fetch catalog: test failure")},
			{"parse", func() error { _, err := decodeCatalog(strings.NewReader("{")); return err }()},
			{"validation", func() error {
				_, err := decodeCatalog(strings.NewReader(`{"functions":{},"contexts":{"unprivileged":{}},"executables":{"tool":{}}}`))
				return err
			}()},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				code, stdout, stderr, calls := runWith([]string{"-plain"}, catalog{}, test.err)
				if code != 1 || calls != 1 || !strings.Contains(stdout, "[+] Failed") || !strings.Contains(stderr, test.err.Error()) {
					t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout, stderr)
				}
				if bytes.Contains([]byte(stdout), []byte{0x1b}) {
					t.Fatalf("plain failure emitted ESC: %q", stdout)
				}
			})
		}
	})

	t.Run("catalog miss ambiguity and PATH miss", func(t *testing.T) {
		catalogData := phase9Catalog([]string{"Tool", "tool"}, "unprivileged")
		code, _, stderr, calls := runWith([]string{"-plain", "-s", "missing"}, catalogData, nil)
		if code != 1 || calls != 1 || !strings.Contains(stderr, "catalog executable name not found") {
			t.Fatalf("catalog miss: code=%d calls=%d stderr=%q", code, calls, stderr)
		}

		code, _, stderr, calls = runWith([]string{"-plain", "-s", "TOOL"}, catalogData, nil)
		if code != 1 || calls != 1 || !strings.Contains(stderr, "catalog executable name is ambiguous") {
			t.Fatalf("ambiguous search: code=%d calls=%d stderr=%q", code, calls, stderr)
		}

		missingName := "phase9-not-on-path"
		code, _, stderr, calls = runWith([]string{"-plain", "-s", missingName}, phase9Catalog([]string{missingName}, "unprivileged"), nil)
		if code != 1 || calls != 1 || !strings.Contains(stderr, "exists in the GTFOBins catalog but was not found in PATH") {
			t.Fatalf("PATH miss: code=%d calls=%d stderr=%q", code, calls, stderr)
		}
	})

	t.Run("listing filtering all and search", func(t *testing.T) {
		dir := t.TempDir()
		name := "phase9-installed"
		writeTestExecutable(t, dir, name)
		t.Setenv("PATH", dir)
		catalogData := phase9Catalog([]string{name}, "unprivileged", "future-context")

		code, stdout, stderr, calls := runWith([]string{"-plain"}, catalogData, nil)
		if code != 0 || calls != 1 || stderr != "" || !strings.Contains(stdout, "Displayed techniques:  1") || !strings.Contains(stdout, "Hidden unknown:        1") {
			t.Fatalf("default listing: code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout, stderr)
		}

		code, stdout, stderr, calls = runWith([]string{"-plain", "-all"}, catalogData, nil)
		if code != 0 || calls != 1 || stderr != "" || !strings.Contains(stdout, "All contexts:          true") || !strings.Contains(stdout, "Displayed techniques:  2") {
			t.Fatalf("all listing: code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout, stderr)
		}

		code, stdout, stderr, calls = runWith([]string{"-plain", "-s", name}, catalogData, nil)
		if code != 0 || calls != 1 || stderr != "" || !strings.Contains(stdout, "All contexts:          true") || !strings.Contains(stdout, "Context:               future-context") || !strings.Contains(stdout, "State:                 unknown") {
			t.Fatalf("search listing: code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout, stderr)
		}
	})
}

func TestFilteringAndCounts(t *testing.T) {
	values := []finding{
		{Name: "A", CanonicalPath: "/Shared", Techniques: []technique{
			{ContextKey: "unprivileged", State: stateConfirmed},
			{ContextKey: "sudo", State: statePotential},
			{ContextKey: "capabilities", State: stateUnknown},
			{ContextKey: "suid", State: stateUnavailable},
		}},
		{Name: "B", CanonicalPath: "/Shared", Techniques: []technique{{ContextKey: "unprivileged", State: stateConfirmed}}},
	}

	filtered := filterFindings(values, false)
	if filtered.InstalledBinaries != 2 || filtered.DisplayedTechniques != 3 || filtered.HiddenUnknown != 1 || filtered.HiddenUnavailable != 1 || len(filtered.Findings) != 2 {
		t.Fatalf("default filtering = %#v", filtered)
	}
	if len(values[0].Techniques) != 4 {
		t.Fatal("filtering mutated evaluated findings")
	}

	all := filterFindings(values, true)
	if !all.AllContexts || all.DisplayedTechniques != 5 || all.HiddenUnknown != 0 || all.HiddenUnavailable != 0 {
		t.Fatalf("all filtering = %#v", all)
	}
	search := options{Search: "A"}
	searchReport := filterFindings(values[:1], search.Search != "")
	if searchReport.DisplayedTechniques != 4 || !searchReport.AllContexts {
		t.Fatalf("search did not imply all contexts: %#v", searchReport)
	}
}

func TestBinarySorting(t *testing.T) {
	values := []finding{
		{Name: "beta", Techniques: []technique{{ContextKey: "unprivileged", FunctionLabel: "B", MitreIDs: []string{"T2"}, Code: "b"}}},
		{Name: "alpha", Techniques: []technique{
			{ContextKey: "future-z", FunctionLabel: "Z", Code: "z"},
			{ContextKey: "sudo", FunctionLabel: "B", MitreIDs: []string{"T2"}, Code: "b"},
			{ContextKey: "sudo", FunctionLabel: "A", MitreIDs: []string{"T2"}, Code: "a"},
		}},
		{Name: "Alpha", Techniques: []technique{{ContextKey: "unprivileged", FunctionLabel: "A", Code: "a"}}},
	}
	sortBinaryFindings(values)
	if got := []string{values[0].Name, values[1].Name, values[2].Name}; !reflect.DeepEqual(got, []string{"Alpha", "alpha", "beta"}) {
		t.Fatalf("binary order = %v", got)
	}
	if got := []string{values[1].Techniques[0].FunctionLabel, values[1].Techniques[1].FunctionLabel, values[1].Techniques[2].ContextKey}; !reflect.DeepEqual(got, []string{"A", "B", "future-z"}) {
		t.Fatalf("binary technique order = %v", got)
	}
}

func TestContextSortingAndRanks(t *testing.T) {
	findings := []finding{
		{Name: "D", Techniques: []technique{{State: stateUnavailable, ContextKey: "sudo", FunctionLabel: "F"}}},
		{Name: "C", Techniques: []technique{{State: stateUnknown, ContextKey: "future-z", FunctionLabel: "F"}}},
		{Name: "B", Techniques: []technique{{State: stateUnknown, ContextKey: "future-a", FunctionLabel: "F"}}},
		{Name: "A", Techniques: []technique{
			{State: statePotential, ContextKey: "capabilities", FunctionLabel: "F"},
			{State: stateConfirmed, ContextKey: "unprivileged", FunctionLabel: "F"},
			{State: stateConfirmed, ContextKey: "sudo", FunctionLabel: "F"},
		}},
	}
	rows := flattenFindings(findings)
	sortTechniqueRows(rows, sortContext)
	var got []string
	for _, row := range rows {
		got = append(got, string(row.Technique.State)+"/"+row.Technique.ContextKey+"/"+row.Finding.Name)
	}
	want := []string{
		"confirmed/sudo/A",
		"confirmed/unprivileged/A",
		"potential/capabilities/A",
		"unknown/future-a/B",
		"unknown/future-z/C",
		"unavailable/sudo/D",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("context order = %v, want %v", got, want)
	}
}

func TestAttackSortingKeepsOneRowPerTechnique(t *testing.T) {
	findings := []finding{
		{Name: "Empty", Techniques: []technique{{ContextKey: "sudo", FunctionLabel: "F"}}},
		{Name: "MultiB", Techniques: []technique{{ContextKey: "sudo", FunctionLabel: "F", MitreIDs: []string{"T0003", "T0001"}}}},
		{Name: "MultiA", Techniques: []technique{{ContextKey: "sudo", FunctionLabel: "F", MitreIDs: []string{"T0002", "T0001"}}}},
		{Name: "First", Techniques: []technique{{ContextKey: "sudo", FunctionLabel: "F", MitreIDs: []string{"T0000"}}}},
	}
	rows := flattenFindings(findings)
	if len(rows) != 4 {
		t.Fatalf("multi-ATT&CK technique duplicated before sort: %d rows", len(rows))
	}
	sortTechniqueRows(rows, sortAttack)
	var got []string
	for _, row := range rows {
		got = append(got, row.Finding.Name)
	}
	if !reflect.DeepEqual(got, []string{"First", "MultiA", "MultiB", "Empty"}) {
		t.Fatalf("ATT&CK order = %v", got)
	}
	if len(rows[1].Technique.MitreIDs) != 2 {
		t.Fatal("multi-ATT&CK technique became multiple rows")
	}
}

func TestRendererPreservesPlainDataAndSanitizesAtBoundary(t *testing.T) {
	previousPlainMode := plainMode
	defer func() { plainMode = previousPlainMode }()
	falseValue := false
	trueValue := true
	report := reportData{
		EffectiveUID:        1000,
		Sort:                sortBinary,
		SudoProbe:           "not requested",
		InstalledBinaries:   1,
		DisplayedTechniques: 1,
		CatalogWarnings:     1,
		HostWarnings:        []string{"host warning one", "host warning two"},
		Findings: []finding{{
			Name:          "CaseTool\x1b[2J",
			InvocablePath: "/Fixture/Case/Tool",
			Techniques: []technique{{
				FunctionKey:   "command",
				FunctionLabel: "Command",
				ContextKey:    "unprivileged",
				ContextLabel:  "Unprivileged",
				State:         stateConfirmed,
				Code:          "first line\n  second line\n",
				MitreIDs:      []string{"T0002", "T0001"},
				Blind:         &falseValue,
				TTY:           &trueValue,
				Binary:        &falseValue,
			}},
		}},
	}
	before := report.Findings[0].Techniques[0].Code
	plainMode = true
	output := captureProcessOutput(t, func() { renderReport(report) })
	if bytes.Contains([]byte(output), []byte{0x1b}) || strings.ContainsAny(output, "╭│╰─✓") {
		t.Fatalf("plain renderer emitted terminal controls or box drawing: %q", output)
	}
	for _, want := range []string{
		"/Fixture/Case/Tool",
		"Blind:                 false",
		"TTY:                   true",
		"Binary:                false",
		"ATT&CK:                T0001, T0002",
		"Catalog warnings:      1",
		"Host warning:          host warning one",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("plain output lacks %q:\n%s", want, output)
		}
	}
	lines := strings.Split(output, "\n")
	multilinePreserved := false
	for index, line := range lines {
		if strings.HasSuffix(line, "  second line") && index+1 < len(lines) && lines[index+1] != "" && strings.TrimSpace(lines[index+1]) == "" {
			multilinePreserved = true
			break
		}
	}
	if !strings.Contains(output, "Command:               first line\n") || !multilinePreserved {
		t.Fatalf("multiline command was joined, trimmed, or truncated:\n%s", output)
	}
	if report.Findings[0].Techniques[0].Code != before {
		t.Fatal("rendering mutated normalized command data")
	}

	plainMode = false
	colored := captureProcessOutput(t, func() { renderReport(report) })
	if !strings.Contains(colored, colorGreen+"confirmed"+colorReset) || !strings.Contains(colored, colorCyan+colorBold+"[1] CaseTool[2J"+colorReset) {
		t.Fatalf("color was not applied after sanitization: %q", colored)
	}
}

func TestPlainOutputGolden(t *testing.T) {
	previousPlainMode := plainMode
	defer func() { plainMode = previousPlainMode }()
	catalogData := loadFixtureCatalog(t)
	resolved := resolveCatalog(catalogData)
	if len(resolved.Warnings) != 0 {
		t.Fatalf("fixture resolution warnings: %v", resolved.Warnings)
	}

	tool := findingNamed(t, resolved, "fixture-tool")
	tool.Techniques = []technique{
		techniqueNamed(t, tool, "command", "sudo"),
		techniqueNamed(t, tool, "command", "capabilities"),
		techniqueNamed(t, tool, "fixture-unknown", "unprivileged"),
	}
	alias := findingNamed(t, resolved, "fixture-alias")
	alias.Techniques = []technique{techniqueNamed(t, alias, "fixture-unknown", "unprivileged")}
	parent := findingNamed(t, resolved, "fixture-parent")
	parent.Techniques = []technique{techniqueNamed(t, parent, "command", "unprivileged")}
	selected := []finding{tool, alias, parent}

	toolPath := "/Fixture/Bin/fixture-tool"
	discoveries := []executableDiscovery{
		staticDiscovery("fixture-tool", toolPath, toolPath, 0o755, mountStatus{Known: true}),
		staticDiscovery("fixture-alias", "/Fixture/Bin/fixture-alias", toolPath, 0o755, mountStatus{Known: true}),
		staticDiscovery("fixture-parent", "/Fixture/Bin/fixture-parent", "/Fixture/Bin/fixture-parent", 0o755, mountStatus{Known: true}),
	}
	host := hostSnapshot{
		procStatus:         procStatus{NoNewPrivsKnown: true, CapBndKnown: true},
		EffectiveUID:       1000,
		SudoPresent:        true,
		SudoProbeRequested: true,
	}
	sudoBatch := sudoProbeBatch{
		SudoPath: "/usr/bin/sudo",
		Results:  map[string]sudoProbeResult{toolPath: {Status: sudoProbeRecognized}},
	}
	capabilities := map[string]fileCapabilityInspection{
		toolPath: {Known: true, Present: true, Capabilities: fileCapabilities{Effective: true}},
	}
	evaluated := evaluateFindings(selected, discoveries, host, sudoBatch, capabilities)
	report := filterFindings(evaluated, true)
	report.EffectiveUID = host.EffectiveUID
	report.Sort = sortBinary
	report.SudoProbe = sudoProbeBatchStatus(true, sudoBatch)
	report.CatalogWarnings = len(resolved.Warnings)

	plainMode = true
	got := captureProcessOutput(t, func() { renderReport(report) })
	want := `================================================================
  Effective UID:         1000
  Effective UID 0:       false
  Sort:                  binary
  All contexts:          true
  Sudo probe:            completed
  Installed binaries:    3
  Displayed techniques:  5
  Hidden unknown:        0
  Hidden unavailable:    0
  Catalog warnings:      0
================================================================

[1] fixture-alias
  Invocable path:        /Fixture/Bin/fixture-alias
  Canonical target:      /Fixture/Bin/fixture-tool
  Alias chain:           fixture-alias -> fixture-tool
  Executable comment:    Synthetic executable used only by tests.
  -- technique 1 --
  Function:              Unknown fixture function (fixture-unknown)
  Context:               Unprivileged
  Context description:   Synthetic unprivileged context.
  State:                 confirmed
  ATT&CK:                T0003
  Description:           Exercises forward-compatible function decoding.
  Command:               echo fixture
----------------------------------------------------------------

[2] fixture-parent
  Invocable path:        /Fixture/Bin/fixture-parent
  -- technique 1 --
  Function:              Fixture command (command)
  Context:               Unprivileged
  Context description:   Synthetic unprivileged context.
  State:                 unknown
  Evidence:              version restriction was not verified: fixture-version <= 1
  ATT&CK:                T0001, T0002
  Description:           Runs a harmless fixture command.
  Command:               fixture-command --example
  Example comment:       Harmless placeholder example.
  Version restriction:   fixture-version <= 1
  Inheritance chain:     fixture-parent -> fixture-tool
  Launcher 1:            fixture-parent [unprivileged]
  Launcher 1 command:    fixture-command --example
  Companion listener comment: Synthetic shared companion.
  Companion listener command: echo fixture
  Companion connector comment: Synthetic inline companion.
  Companion connector command: echo fixture
  Blind:                 false
  TTY:                   true
  Binary:                false
----------------------------------------------------------------

[3] fixture-tool
  Invocable path:        /Fixture/Bin/fixture-tool
  Executable comment:    Synthetic executable used only by tests.
  -- technique 1 --
  Function:              Fixture command (command)
  Context:               Sudo
  Context description:   Synthetic sudo context.
  State:                 unknown
  Evidence:              sudo policy recognized the canonical executable path
  Evidence:              path-level sudo evidence does not prove the full GTFOBins command line is authorized
  Evidence:              version restriction was not verified: fixture-version <= 1
  ATT&CK:                T0001, T0002
  Description:           Runs a harmless fixture command.
  Command:               fixture-command --sudo-example
  Example comment:       Harmless placeholder example.
  Context comment:       Synthetic context-specific override.
  Version restriction:   fixture-version <= 1
  Companion listener comment: Synthetic shared companion.
  Companion listener command: echo fixture
  Companion connector comment: Synthetic inline companion.
  Companion connector command: echo fixture
  Blind:                 false
  TTY:                   true
  Binary:                false
  -- technique 2 --
  Function:              Fixture command (command)
  Context:               Capabilities
  Context description:   Synthetic capability context.
  State:                 unknown
  Evidence:              unknown required capability CAP_FIXTURE
  Evidence:              version restriction was not verified: fixture-version <= 1
  ATT&CK:                T0001, T0002
  Description:           Runs a harmless fixture command.
  Command:               fixture-command --example
  Example comment:       Harmless placeholder example.
  Version restriction:   fixture-version <= 1
  Context requirements:  CAP_FIXTURE
  Companion listener comment: Synthetic shared companion.
  Companion listener command: echo fixture
  Companion connector comment: Synthetic inline companion.
  Companion connector command: echo fixture
  Blind:                 false
  TTY:                   true
  Binary:                false
  -- technique 3 --
  Function:              Unknown fixture function (fixture-unknown)
  Context:               Unprivileged
  Context description:   Synthetic unprivileged context.
  State:                 confirmed
  ATT&CK:                T0003
  Description:           Exercises forward-compatible function decoding.
  Command:               echo fixture
----------------------------------------------------------------
`
	if got != want {
		t.Fatalf("plain output mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestFetchCatalogSuccessUsesGET(t *testing.T) {
	payload := fixtureCatalogJSON(t)
	methods := make(chan string, 1)

	c, err := fetchFromTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		methods <- r.Method
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(payload)
	})
	if err != nil {
		t.Fatal(err)
	}
	if method := <-methods; method != http.MethodGet {
		t.Fatalf("request method = %q, want GET", method)
	}
	if _, ok := c.Executables["fixture-tool"]; !ok {
		t.Fatal("fixture catalog was not returned")
	}
}

func TestFetchCatalogNonOKReturnsErrorWithoutPrinting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "server-body-must-not-leak\x1b[2J")
	}))
	defer server.Close()

	var fetchErr error
	output := captureProcessOutput(t, func() {
		_, fetchErr = fetchCatalogFrom(context.Background(), server.Client(), server.URL)
	})
	if fetchErr == nil || !strings.Contains(fetchErr.Error(), "HTTP status 503") {
		t.Fatalf("error = %v, want HTTP status 503", fetchErr)
	}
	if strings.Contains(fetchErr.Error(), "server-body") {
		t.Fatalf("server body leaked into error: %v", fetchErr)
	}
	if output != "" {
		t.Fatalf("fetch printed %q instead of returning its error", output)
	}
}

func TestFetchCatalogResponseSizeLimit(t *testing.T) {
	valid := fixtureCatalogJSON(t)
	exact := bytes.Repeat([]byte(" "), maxCatalogResponseSize)
	copy(exact, valid)
	over := bytes.Repeat([]byte(" "), maxCatalogResponseSize+1)

	t.Run("exactly limit", func(t *testing.T) {
		c, err := fetchFromTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(exact)))
			_, _ = w.Write(exact)
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := c.Executables["fixture-tool"]; !ok {
			t.Fatal("exact-limit catalog was not returned")
		}
	})

	t.Run("over limit", func(t *testing.T) {
		_, err := fetchFromTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(over)))
			_, _ = w.Write(over)
		})
		if err == nil || !strings.Contains(err.Error(), "exceeds 5242880-byte limit") {
			t.Fatalf("error = %v, want size-limit error", err)
		}
	})

	t.Run("over limit without content length", func(t *testing.T) {
		_, err := fetchFromTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = w.Write(over)
		})
		if err == nil || !strings.Contains(err.Error(), "exceeds 5242880-byte limit") {
			t.Fatalf("error = %v, want size-limit error", err)
		}
	})
}

func TestFetchCatalogJSONDocumentBoundary(t *testing.T) {
	valid := fixtureCatalogJSON(t)
	tests := []struct {
		name    string
		payload []byte
		wantErr string
	}{
		{"invalid JSON", []byte(`{"functions":`), "decode catalog"},
		{"trailing JSON value", append(append([]byte(nil), valid...), []byte(` {"second":true}`)...), "trailing JSON value"},
		{"trailing whitespace", append(append([]byte(nil), valid...), []byte("\n\t  ")...), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fetchFromTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(tt.payload)
			})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCatalogRequiredSections(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"missing functions", `{"contexts":{"unprivileged":{}},"executables":{"fixture":{}}}`, "functions section is missing"},
		{"empty functions", `{"functions":{},"contexts":{"unprivileged":{}},"executables":{"fixture":{}}}`, "functions section is empty"},
		{"missing contexts", `{"functions":{"command":{}},"executables":{"fixture":{}}}`, "contexts section is missing"},
		{"empty contexts", `{"functions":{"command":{}},"contexts":{},"executables":{"fixture":{}}}`, "contexts section is empty"},
		{"missing executables", `{"functions":{"command":{}},"contexts":{"unprivileged":{}}}`, "executables section is missing"},
		{"empty executables", `{"functions":{"command":{}},"contexts":{"unprivileged":{}},"executables":{}}`, "executables section is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fetchFromTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tt.input)
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestExecutableNameValidation(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"", "name is empty"},
		{"fixture/tool", "contains slash"},
		{".", "dot path"},
		{"..", "dot path"},
		{"fixture\x00tool", "contains NUL"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			err := validateCatalog(validCatalog(tt.name))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}

	if err := validateCatalog(validCatalog("fixture.tool+v1")); err != nil {
		t.Fatalf("harmless punctuation rejected: %v", err)
	}
}

func TestUnknownJSONFieldsAreTolerated(t *testing.T) {
	input := `{
		"functions":{"command":{"future":true}},
		"contexts":{"unprivileged":{"future":true}},
		"executables":{"fixture":{"future":true,"functions":{"command":[{"contexts":{"unprivileged":null},"future":true}]}}},
		"future":true
	}`
	if _, err := fetchFromTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, input)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFetchCatalogPropagatesValidationError(t *testing.T) {
	input := `{"functions":{"command":{}},"contexts":{"unprivileged":{}},"executables":{"fixture/tool":{}}}`
	_, err := fetchFromTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, input)
	})
	if err == nil || !strings.Contains(err.Error(), "validate catalog: invalid executable name") {
		t.Fatalf("error = %v, want wrapped validation error", err)
	}
}

func TestSanitizeTerminalText(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"ASCII", "plain ASCII 123", "plain ASCII 123"},
		{"Unicode", "café 漢字 🙂", "café 漢字 🙂"},
		{"newline", "first\nsecond", "first\nsecond"},
		{"tab", "left\tright", "left\tright"},
		{"escape", "a\x1bb", "ab"},
		{"ANSI sequence", "before\x1b[2Jafter", "before[2Jafter"},
		{"carriage return", "before\rafter", "beforeafter"},
		{"backspace", "before\bafter", "beforeafter"},
		{"DEL", "before\x7fafter", "beforeafter"},
		{"other C0 controls", "\x00\x01\x02\x0b\x0c\x1f", ""},
		{"mixed", "start\x1b[31mred\x1b[0m\r\n\tend\x7f", "start[31mred[0m\n\tend"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTerminalText(tt.input)
			if got != tt.want {
				t.Fatalf("sanitizeTerminalText(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if strings.Contains(got, "\x1b[2J") {
				t.Fatalf("ANSI control sequence survived intact: %q", got)
			}
			for _, r := range got {
				if r != '\n' && r != '\t' && !unicode.IsPrint(r) {
					t.Fatalf("control character U+%04X survived in %q", r, got)
				}
			}
		})
	}
}

func TestDecodeContext(t *testing.T) {
	value, err := decodeContext(json.RawMessage(`null`))
	if err != nil || value != nil {
		t.Fatalf("null context = %#v, %v", value, err)
	}

	value, err = decodeContext(json.RawMessage(`{"code":"fixture-command --example","comment":"fixture","shell":true,"list":["CAP_FIXTURE"]}`))
	if err != nil || value.Code == "" || value.Comment == "" || value.Shell == nil || !*value.Shell || len(value.List) != 1 {
		t.Fatalf("object context = %#v, %v", value, err)
	}
	for _, raw := range []string{`{"shell":false}`, `{}`, `null`} {
		value, err := decodeContext(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("decodeContext(%s): %v", raw, err)
		}
		if raw == `{"shell":false}` && (value == nil || value.Shell == nil || *value.Shell) {
			t.Fatalf("false shell metadata was not preserved: %#v", value)
		}
		if raw != `{"shell":false}` && value != nil && value.Shell != nil {
			t.Fatalf("missing/null shell metadata was not preserved: %#v", value)
		}
	}

	for _, raw := range []string{``, `[]`, `"context"`, `1`, `true`, `{`, `{"code":1}`, `{"shell":"true"}`, `{"shell":1}`, `{"shell":{}}`, `{"shell":[]}`} {
		if _, err := decodeContext(json.RawMessage(raw)); err == nil {
			t.Errorf("decodeContext(%q) succeeded", raw)
		}
	}
}

func TestBooleanContextShellReachesEvaluationAndRendering(t *testing.T) {
	c := basicResolutionCatalog(map[string]executableDef{
		"tool": {Functions: map[string][]exampleDef{
			"command": {{
				Code: "fixture-code",
				Contexts: map[string]json.RawMessage{
					"unprivileged": json.RawMessage(`{"shell":true}`),
					"sudo":         json.RawMessage(`{"shell":false}`),
					"suid":         json.RawMessage(`{}`),
				},
			}},
		}},
	})
	c.Contexts["suid"] = contextMeta{Label: "SUID"}
	result := resolveCatalog(c)
	if len(result.Warnings) != 0 {
		t.Fatalf("boolean shell metadata produced warnings: %v", result.Warnings)
	}
	value := findingNamed(t, result, "tool")
	for _, key := range []string{"unprivileged", "sudo", "suid"} {
		candidate := techniqueNamed(t, value, "command", key)
		if candidate.ContextKey != key {
			t.Fatalf("context %q was not retained: %#v", key, candidate)
		}
	}
	if candidate := techniqueNamed(t, value, "command", "unprivileged"); candidate.ContextShell == nil || !*candidate.ContextShell {
		t.Fatalf("true shell metadata lost: %#v", candidate)
	}
	if candidate := techniqueNamed(t, value, "command", "sudo"); candidate.ContextShell == nil || *candidate.ContextShell {
		t.Fatalf("false shell metadata lost: %#v", candidate)
	}

	tool := value
	tool.Techniques = []technique{techniqueNamed(t, value, "command", "unprivileged"), techniqueNamed(t, value, "command", "sudo")}
	evaluated := evaluateFindings([]finding{tool}, []executableDiscovery{
		staticDiscovery("tool", "/fixture/tool", "/fixture/tool", 0o755, mountStatus{Known: true}),
	}, hostSnapshot{procStatus: procStatus{NoNewPrivsKnown: true, CapBndKnown: true}}, sudoProbeBatch{}, nil)
	report := filterFindings(evaluated, true)
	if report.DisplayedTechniques != 2 {
		t.Fatalf("boolean shell techniques were not rendered: %#v", report)
	}
	previous := plainMode
	defer func() { plainMode = previous }()
	plainMode = true
	output := captureProcessOutput(t, func() { renderReport(report) })
	if !strings.Contains(output, "Context shell:         true") || !strings.Contains(output, "Context shell:         false") {
		t.Fatalf("boolean shell metadata missing from output: %s", output)
	}
}

func TestDecodeCompanion(t *testing.T) {
	reference, err := decodeCompanion(json.RawMessage(`"fixture-listener"`))
	if err != nil || reference.Reference != "fixture-listener" || reference.Inline != nil {
		t.Fatalf("string companion = %#v, %v", reference, err)
	}

	inline, err := decodeCompanion(json.RawMessage(`{"comment":"fixture","code":"echo fixture"}`))
	if err != nil || inline.Reference != "" || inline.Inline == nil || inline.Inline.Comment != "fixture" || inline.Inline.Code != "echo fixture" {
		t.Fatalf("inline companion = %#v, %v", inline, err)
	}

	for _, raw := range []string{`null`, `[]`, `1`, `true`, `"`, `{`, `{"code":1}`} {
		if _, err := decodeCompanion(json.RawMessage(raw)); err == nil {
			t.Errorf("decodeCompanion(%q) succeeded", raw)
		}
	}
}

func loadFixtureCatalog(t *testing.T) catalog {
	t.Helper()
	c, err := decodeCatalog(bytes.NewReader(fixtureCatalogJSON(t)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func basicResolutionCatalog(executables map[string]executableDef) catalog {
	return catalog{
		Functions: map[string]functionMeta{
			"command": {Label: "Command", Description: "Command description"},
			"inherit": {Label: "Inherit"},
		},
		Contexts: map[string]contextMeta{
			"unprivileged": {Label: "Unprivileged"},
			"sudo":         {Label: "Sudo"},
		},
		Executables: executables,
	}
}

func phase9Catalog(names []string, contextKeys ...string) catalog {
	contexts := make(map[string]contextMeta, len(contextKeys))
	exampleContexts := make(map[string]json.RawMessage, len(contextKeys))
	for _, key := range contextKeys {
		contexts[key] = contextMeta{Label: key}
		exampleContexts[key] = json.RawMessage(`{}`)
	}
	executables := make(map[string]executableDef, len(names))
	for _, name := range names {
		executables[name] = executableDef{Functions: map[string][]exampleDef{
			"command": {{Code: "display only", Contexts: exampleContexts}},
		}}
	}
	return catalog{
		Functions:   map[string]functionMeta{"command": {Label: "command"}},
		Contexts:    contexts,
		Executables: executables,
	}
}

func findingNamed(t *testing.T, result resolutionResult, name string) finding {
	t.Helper()
	for _, value := range result.Findings {
		if value.Name == name {
			return value
		}
	}
	t.Fatalf("finding %q not found in %#v", name, result.Findings)
	return finding{}
}

func techniqueNamed(t *testing.T, value finding, functionKey, contextKey string) technique {
	t.Helper()
	for _, candidate := range value.Techniques {
		if candidate.FunctionKey == functionKey && candidate.ContextKey == contextKey {
			return candidate
		}
	}
	t.Fatalf("technique %q/%q not found in %#v", functionKey, contextKey, value.Techniques)
	return technique{}
}

func warningContains(warnings []string, text string) bool {
	return slices.ContainsFunc(warnings, func(warning string) bool { return strings.Contains(warning, text) })
}

func validCatalog(name string) catalog {
	return catalog{
		Functions:   map[string]functionMeta{"command": {}},
		Contexts:    map[string]contextMeta{"unprivileged": {}},
		Executables: map[string]executableDef{name: {}},
	}
}

func fixtureCatalogJSON(t *testing.T) []byte {
	t.Helper()
	payload, err := os.ReadFile("testdata/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func fetchFromTestServer(t *testing.T, handler http.HandlerFunc) (catalog, error) {
	t.Helper()
	server := httptest.NewServer(handler)
	defer server.Close()
	return fetchCatalogFrom(context.Background(), server.Client(), server.URL)
}

func captureProcessOutput(t *testing.T, fn func()) string {
	t.Helper()

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout, oldStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = write, write
	defer func() {
		os.Stdout, os.Stderr = oldStdout, oldStderr
		_ = read.Close()
		_ = write.Close()
	}()

	fn()
	os.Stdout, os.Stderr = oldStdout, oldStderr
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	return string(output)
}

func captureProcessStreams(t *testing.T, fn func()) (string, string) {
	t.Helper()

	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		_ = stdoutRead.Close()
		_ = stdoutWrite.Close()
		t.Fatal(err)
	}
	oldStdout, oldStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWrite, stderrWrite
	defer func() {
		os.Stdout, os.Stderr = oldStdout, oldStderr
		_ = stdoutRead.Close()
		_ = stdoutWrite.Close()
		_ = stderrRead.Close()
		_ = stderrWrite.Close()
	}()

	fn()
	os.Stdout, os.Stderr = oldStdout, oldStderr
	if err := stdoutWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stderrWrite.Close(); err != nil {
		t.Fatal(err)
	}
	stdout, err := io.ReadAll(stdoutRead)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := io.ReadAll(stderrRead)
	if err != nil {
		t.Fatal(err)
	}
	return string(stdout), string(stderr)
}
