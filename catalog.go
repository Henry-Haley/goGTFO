package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
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

func decodeCatalog(r io.Reader) (catalog, error) {
	var c catalog
	if err := json.NewDecoder(r).Decode(&c); err != nil {
		return catalog{}, fmt.Errorf("decode catalog: %w", err)
	}
	if err := validateCatalog(c); err != nil {
		return catalog{}, err
	}
	return c, nil
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
