package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
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
			_, err := decodeCatalog(strings.NewReader(tt.input))
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
	if _, err := decodeCatalog(strings.NewReader(input)); err != nil {
		t.Fatal(err)
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

func validCatalog(name string) catalog {
	return catalog{
		Functions:   map[string]functionMeta{"command": {}},
		Contexts:    map[string]contextMeta{"unprivileged": {}},
		Executables: map[string]executableDef{name: {}},
	}
}
