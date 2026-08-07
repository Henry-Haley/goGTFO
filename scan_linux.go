//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	errCatalogNameNotFound  = errors.New("catalog executable name not found")
	errCatalogNameAmbiguous = errors.New("catalog executable name is ambiguous")
)

type procStatus struct {
	NoNewPrivs      bool
	NoNewPrivsKnown bool
	CapBnd          uint64
	CapBndKnown     bool
}

type hostSnapshot struct {
	procStatus
	RealUID            int
	EffectiveUID       int
	SudoPresent        bool
	SudoProbeRequested bool
	Warnings           []string
}

type mountStatus struct {
	Known  bool
	NoExec bool
	NoSUID bool
}

type executableDiscovery struct {
	CatalogName   string
	Found         bool
	InvocablePath string
	CanonicalPath string
	FileInfo      os.FileInfo
	Executable    bool
	Mount         mountStatus
	Usable        bool
	Warning       string
}

type catalogSearchResult struct {
	Name       string
	Candidates []string
}

func parseProcStatus(r io.Reader) (procStatus, []string) {
	var status procStatus
	var warnings []string
	var sawNoNewPrivs, sawCapBnd bool

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		name, raw, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(raw)
		switch strings.TrimSpace(name) {
		case "NoNewPrivs":
			sawNoNewPrivs = true
			if len(fields) != 1 {
				status.NoNewPrivsKnown = false
				warnings = append(warnings, "NoNewPrivs is malformed")
				continue
			}
			value, err := strconv.ParseUint(fields[0], 10, 64)
			if err != nil || value > 1 {
				status.NoNewPrivsKnown = false
				warnings = append(warnings, "NoNewPrivs is malformed")
				continue
			}
			status.NoNewPrivs = value == 1
			status.NoNewPrivsKnown = true
		case "CapBnd":
			sawCapBnd = true
			if len(fields) != 1 {
				status.CapBndKnown = false
				warnings = append(warnings, "CapBnd is malformed")
				continue
			}
			value, err := strconv.ParseUint(fields[0], 16, 64)
			if err != nil {
				status.CapBndKnown = false
				warnings = append(warnings, "CapBnd is malformed")
				continue
			}
			status.CapBnd = value
			status.CapBndKnown = true
		}
	}

	if !sawNoNewPrivs {
		warnings = append(warnings, "NoNewPrivs is missing")
	}
	if !sawCapBnd {
		warnings = append(warnings, "CapBnd is missing")
	}
	if err := scanner.Err(); err != nil {
		warnings = append(warnings, fmt.Sprintf("read process status: %v", err))
	}
	return status, warnings
}

func captureHostSnapshot(sudoProbeRequested bool) hostSnapshot {
	return captureHostSnapshotAt("/proc/self/status", sudoProbeRequested)
}

func captureHostSnapshotAt(statusPath string, sudoProbeRequested bool) hostSnapshot {
	snapshot := hostSnapshot{
		RealUID:            os.Getuid(),
		EffectiveUID:       os.Geteuid(),
		SudoProbeRequested: sudoProbeRequested,
	}

	statusFile, err := os.Open(statusPath)
	if err != nil {
		snapshot.Warnings = append(snapshot.Warnings, fmt.Sprintf("open process status: %v", err))
	} else {
		status, warnings := parseProcStatus(statusFile)
		snapshot.procStatus = status
		snapshot.Warnings = append(snapshot.Warnings, warnings...)
		if err := statusFile.Close(); err != nil {
			snapshot.Warnings = append(snapshot.Warnings, fmt.Sprintf("close process status: %v", err))
		}
	}

	if _, err := exec.LookPath("sudo"); err == nil {
		snapshot.SudoPresent = true
	} else if errors.Is(err, exec.ErrDot) {
		snapshot.Warnings = append(snapshot.Warnings, "sudo was rejected because PATH resolved it through the current directory")
	}
	return snapshot
}

func searchCatalogName(executables map[string]executableDef, query string) (catalogSearchResult, error) {
	base := filepath.Base(query)
	var result catalogSearchResult
	if _, ok := executables[base]; ok {
		result.Name = base
		return result, nil
	}

	for _, name := range slices.Sorted(maps.Keys(executables)) {
		if strings.EqualFold(name, base) {
			result.Candidates = append(result.Candidates, name)
		}
	}
	switch len(result.Candidates) {
	case 0:
		return result, fmt.Errorf("%w: %q", errCatalogNameNotFound, base)
	case 1:
		result.Name = result.Candidates[0]
		result.Candidates = nil
		return result, nil
	default:
		return result, fmt.Errorf("%w: %q", errCatalogNameAmbiguous, base)
	}
}

func discoverExecutables(executables map[string]executableDef) []executableDiscovery {
	results := make([]executableDiscovery, 0, len(executables))
	for _, name := range slices.Sorted(maps.Keys(executables)) {
		results = append(results, discoverExecutable(name))
	}
	return results
}

func discoverExecutable(name string) executableDiscovery {
	result := executableDiscovery{CatalogName: name}
	path, err := exec.LookPath(name)
	if err != nil {
		if errors.Is(err, exec.ErrDot) {
			result.Warning = fmt.Sprintf("catalog executable %q was rejected because PATH resolved it through the current directory", name)
		} else {
			result.Warning = fmt.Sprintf("look up catalog executable %q in PATH: %v", name, err)
		}
		return result
	}

	result.Found = true
	result.InvocablePath = path
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		result.Warning = fmt.Sprintf("resolve symlinks for catalog executable %q: %v", name, err)
		return result
	}
	result.CanonicalPath = canonical
	return inspectCanonicalExecutable(result)
}

func inspectCanonicalExecutable(result executableDiscovery) executableDiscovery {
	info, err := os.Stat(result.CanonicalPath)
	if err != nil {
		result.Warning = fmt.Sprintf("stat canonical target for catalog executable %q: %v", result.CatalogName, err)
		return result
	}
	result.FileInfo = info
	if !info.Mode().IsRegular() {
		result.Warning = fmt.Sprintf("canonical target for catalog executable %q is not a regular file", result.CatalogName)
		return result
	}
	if info.Mode().Perm()&0111 == 0 {
		result.Warning = fmt.Sprintf("canonical target for catalog executable %q is not executable", result.CatalogName)
		return result
	}
	result.Executable = true

	result.Mount, err = inspectMount(result.CanonicalPath)
	if err != nil {
		result.Warning = fmt.Sprintf("inspect filesystem flags for catalog executable %q: %v", result.CatalogName, err)
		return result
	}
	result.Usable = discoveryUsable(result.Executable, result.Mount)
	if result.Mount.NoExec {
		result.Warning = fmt.Sprintf("catalog executable %q is on a noexec filesystem", result.CatalogName)
	}
	return result
}

func inspectMount(path string) (mountStatus, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return mountStatus{}, err
	}
	return interpretMountFlags(stat.Flags), nil
}

func interpretMountFlags(flags int64) mountStatus {
	return mountStatus{
		Known:  true,
		NoExec: flags&unix.ST_NOEXEC != 0,
		NoSUID: flags&unix.ST_NOSUID != 0,
	}
}

func discoveryUsable(executable bool, mount mountStatus) bool {
	return executable && mount.Known && !mount.NoExec
}
