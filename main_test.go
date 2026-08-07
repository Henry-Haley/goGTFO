package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
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
	if suid.Code != "fixture-command --example" || suid.ContextShell != "fixture-shell" {
		t.Fatalf("SUID context = %#v", suid)
	}
	capabilities := techniqueNamed(t, tool, "command", "capabilities")
	if !reflect.DeepEqual(capabilities.ContextList, []string{"CAP_FIXTURE"}) {
		t.Fatalf("capability list = %v", capabilities.ContextList)
	}
	unknownContext := techniqueNamed(t, tool, "command", "fixture-context")
	if unknownContext.ContextKey == "unprivileged" || unknownContext.ContextLabel != "Unknown fixture context" {
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
				Sender:    json.RawMessage(`{"comment":"sender-comment","code":"sender-code"}`),
				Receiver:  json.RawMessage(`{"comment":"receiver-comment","code":"receiver-code"}`),
			}},
		}},
	})
	meta := c.Functions["command"]
	meta.Extra = map[string]json.RawMessage{"shared": json.RawMessage(`{"comment":"listener-comment","code":"listener-code"}`)}
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
	meta.Extra = map[string]json.RawMessage{"malformed": json.RawMessage(`{"code":1}`)}
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
						"unprivileged": json.RawMessage(`{"comment":"target-context-comment","shell":"target-shell","list":["TARGET"]}`),
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
						"unprivileged": json.RawMessage(`{"code":"launcher-override","comment":"launcher-context-comment","shell":"launcher-shell","list":["LAUNCH"]}`),
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
	if value.Description != "target-description" || !reflect.DeepEqual(value.MitreIDs, []string{"T1000", "T2000"}) || value.ContextShell != "target-shell" || !reflect.DeepEqual(value.ContextList, []string{"TARGET"}) {
		t.Fatalf("target function/context metadata = %#v", value)
	}
	if len(value.Launchers) != 1 {
		t.Fatalf("launchers = %#v", value.Launchers)
	}
	launcher := value.Launchers[0]
	if launcher.Code != "launcher-override" || launcher.ExampleComment != "launcher-example-comment" || launcher.ContextComment != "launcher-context-comment" || launcher.Version != "launcher-version" || launcher.ContextShell != "launcher-shell" || !reflect.DeepEqual(launcher.ContextList, []string{"LAUNCH"}) {
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

	value, err = decodeContext(json.RawMessage(`{"code":"fixture-command --example","comment":"fixture","shell":"fixture-shell","list":["CAP_FIXTURE"]}`))
	if err != nil || value.Code == "" || value.Comment == "" || value.Shell == "" || len(value.List) != 1 {
		t.Fatalf("object context = %#v, %v", value, err)
	}

	for _, raw := range []string{``, `[]`, `"context"`, `1`, `true`, `{`, `{"code":1}`} {
		if _, err := decodeContext(json.RawMessage(raw)); err == nil {
			t.Errorf("decodeContext(%q) succeeded", raw)
		}
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
