//go:build linux

package main

import (
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func FuzzProcStatusSemantics(f *testing.F) {
	f.Add("NoNewPrivs: 0\nCapBnd: ff\n")
	f.Add("NoNewPrivs: 0\nNoNewPrivs: 1\nCapBnd: ff\n")
	f.Add("NoNewPrivs: 0\nCapBnd: ff\n" + strings.Repeat("x", 128*1024))
	f.Fuzz(func(t *testing.T, input string) {
		status, _ := parseProcStatus(strings.NewReader(input))
		noNewPrivsValid, capBndValid := 0, 0
		for _, line := range strings.Split(input, "\n") {
			name, raw, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			fields := strings.Fields(raw)
			switch strings.TrimSpace(name) {
			case "NoNewPrivs":
				if len(fields) == 1 {
					if value, err := strconv.ParseUint(fields[0], 10, 64); err == nil && value <= 1 {
						noNewPrivsValid++
					}
				}
			case "CapBnd":
				if len(fields) == 1 {
					if _, err := strconv.ParseUint(fields[0], 16, 64); err == nil {
						capBndValid++
					}
				}
			}
		}
		if status.NoNewPrivsKnown && noNewPrivsValid != 1 {
			t.Fatalf("NoNewPrivs trusted with %d valid fields", noNewPrivsValid)
		}
		if status.CapBndKnown && capBndValid != 1 {
			t.Fatalf("CapBnd trusted with %d valid fields", capBndValid)
		}
	})
}

func FuzzCapabilityDecoding(f *testing.F) {
	f.Add(capabilityXattrFixture(vfsCapabilityRevision2, 1, 2, true, 0))
	f.Add(capabilityXattrFixture(vfsCapabilityRevision3, 1, 2, true, 4242))
	f.Add([]byte{0x03, 0, 0, 2})
	f.Fuzz(func(t *testing.T, input []byte) {
		decoded, err := decodeFileCapabilities(input)
		if err != nil {
			return
		}
		if decoded.Revision != vfsCapabilityRevision2 && decoded.Revision != vfsCapabilityRevision3 {
			t.Fatalf("decoded unsupported revision %#x", decoded.Revision)
		}
		want := vfsCapabilityRevision2Size
		if decoded.Revision == vfsCapabilityRevision3 {
			want = vfsCapabilityRevision3Size
		}
		if len(input) != want || binary.LittleEndian.Uint32(input[:4])&^vfsCapabilityKnownFlags != 0 {
			t.Fatalf("accepted malformed capability payload length=%d", len(input))
		}
	})
}

func FuzzCatalogDecoding(f *testing.F) {
	f.Add(`{"functions":{"f":{}},"contexts":{"c":{}},"executables":{"x":{"functions":{}}}}`)
	f.Add(`{"functions":{"f":{}},"contexts":{"c":{}},"executables":{"x":{"functions":{"f":[{"contexts":{"c":{"shell":true}}}]}}}}`)
	f.Fuzz(func(t *testing.T, input string) {
		catalog, err := decodeCatalog(strings.NewReader(input))
		if err != nil {
			return
		}
		resolved := resolveCatalog(catalog)
		for _, finding := range resolved.Findings {
			if _, ok := catalog.Executables[finding.Name]; !ok {
				t.Fatalf("fabricated finding %q", finding.Name)
			}
		}
	})
}

func FuzzCompanionResolution(f *testing.F) {
	f.Add(`"ref"`)
	f.Add(`{"code":"inline"}`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, raw string) {
		function := functionMeta{Extra: map[string]json.RawMessage{
			"listener": json.RawMessage(`{"ref":{"code":"listener"}}`),
		}}
		example := exampleDef{Listener: json.RawMessage(raw)}
		companions, _ := resolveCompanions(function, example, "tool", "shell", "suid")
		for _, companion := range companions {
			if companion.Role != "listener" {
				t.Fatalf("invalid companion resolution %#v", companion)
			}
		}
	})
}

func FuzzELFClassification(f *testing.F) {
	f.Add([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	f.Add([]byte("#!/bin/sh\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		path := t.TempDir() + "/candidate"
		if err := os.WriteFile(path, input, 0o700); err != nil {
			t.Fatal(err)
		}
		machine, data, class, known := hostELFFormat()
		format, _ := inspectExecutableFormatForArchitecture(path, machine, data, class, known)
		if format != executableFormatELF {
			return
		}
		file, err := elf.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		loadable := false
		for _, program := range file.Progs {
			loadable = loadable || program.Type == elf.PT_LOAD
		}
		if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN || !loadable || file.Machine != machine || file.Data != data || file.Class != class {
			t.Fatalf("non-native ELF classified as native: type=%v machine=%v data=%v class=%v", file.Type, file.Machine, file.Data, file.Class)
		}
	})
}

func FuzzOptionParsing(f *testing.F) {
	f.Add([]byte("-plain -sort context"))
	f.Add([]byte("-search bash -all"))
	f.Fuzz(func(t *testing.T, input []byte) {
		args := strings.Fields(string(input))
		value, err := parseOptions(args)
		if err == nil && value.Sort != sortBinary && value.Sort != sortContext && value.Sort != sortAttack {
			t.Fatalf("invalid sort accepted: %q", value.Sort)
		}
	})
}

func FuzzCapabilityDiscoveryIsolation(f *testing.F) {
	required := uint64(1) << unix.CAP_SETUID
	f.Add(required, uint64(0), true, true, true, false)
	f.Add(uint64(0), required, true, true, false, true)
	f.Fuzz(func(t *testing.T, aMask, bMask uint64, aKnown, bKnown, aEffective, bEffective bool) {
		host := hostSnapshot{procStatus: procStatus{NoNewPrivsKnown: true, CapBndKnown: true, CapBnd: required}}
		makeDiscovery := func(name string, mask uint64, known, effective bool) executableDiscovery {
			value := staticDiscovery(name, "/fuzz/"+name, "/fuzz/shared", 0o755, mountStatus{Known: true})
			value.CapabilitiesInspected = true
			value.Capabilities = fileCapabilityInspection{
				Known: known, Present: known,
				Capabilities: fileCapabilities{Permitted: mask, Effective: effective},
			}
			return value
		}
		makeFinding := func(name string) finding {
			return finding{Name: name, Techniques: []technique{{FunctionKey: "command", ContextKey: "capabilities", ContextList: []string{"CAP_SETUID"}}}}
		}
		findings := []finding{makeFinding("A"), makeFinding("B")}
		discoveries := []executableDiscovery{makeDiscovery("A", aMask, aKnown, aEffective), makeDiscovery("B", bMask, bKnown, bEffective)}
		first := evaluateFindings(findings, discoveries, host, sudoProbeBatch{}, map[string]fileCapabilityInspection{"/fuzz/shared": {Known: true, Present: true, Capabilities: fileCapabilities{Permitted: required, Effective: true}}})
		if len(first) != 2 {
			t.Fatalf("first evaluation returned %d findings", len(first))
		}
		firstA := first[0].Techniques[0]

		// Change only B's descriptor-bound evidence. A's result must be identical.
		discoveries[1].Capabilities = fileCapabilityInspection{Known: !bKnown, Present: !bKnown, Capabilities: fileCapabilities{Permitted: ^required, Effective: !bEffective}}
		second := evaluateFindings(findings, discoveries, host, sudoProbeBatch{}, nil)
		if len(second) != 2 {
			t.Fatalf("second evaluation returned %d findings", len(second))
		}
		secondA := second[0].Techniques[0]
		if firstA.State != secondA.State || !reflect.DeepEqual(firstA.Evidence, secondA.Evidence) {
			t.Fatalf("A changed when B changed: before=%#v after=%#v", firstA, secondA)
		}
	})
}
