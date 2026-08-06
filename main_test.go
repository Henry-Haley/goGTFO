package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
