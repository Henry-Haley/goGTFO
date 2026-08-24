//go:build linux

package main

import (
	"bufio"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	errCatalogNameNotFound  = errors.New("catalog executable name not found")
	errCatalogNameAmbiguous = errors.New("catalog executable name is ambiguous")
)

type applicabilityState string

const (
	stateConfirmed   applicabilityState = "confirmed"
	statePotential   applicabilityState = "potential"
	stateUnknown     applicabilityState = "unknown"
	stateUnavailable applicabilityState = "unavailable"

	securityCapabilityXattr           = "security.capability"
	vfsCapabilityRevisionMask  uint32 = 0xff000000
	vfsCapabilityRevision2     uint32 = 0x02000000
	vfsCapabilityRevision3     uint32 = 0x03000000
	vfsCapabilityEffective     uint32 = 0x00000001
	vfsCapabilityKnownFlags    uint32 = vfsCapabilityRevisionMask | vfsCapabilityEffective
	vfsCapabilityRevision2Size        = 20
	vfsCapabilityRevision3Size        = 24
	sudoProbeBudget                   = 20 * time.Second
	// USER_NS_INIT_INO from linux/uapi/linux/nsfs.h identifies the initial
	// user namespace in procfs nsfs metadata.
	initialUserNamespaceInode uint64 = 0xeffffffd
)

type applicabilityResult struct {
	State    applicabilityState
	Evidence []string
}

type sudoProbeStatus uint8

const (
	sudoProbeNotAttempted sudoProbeStatus = iota
	sudoProbeRecognized
	sudoProbeNonzero
	sudoProbeExecutionError
	sudoProbeBudgetExhausted
)

type sudoProbeResult struct {
	Status sudoProbeStatus
	Err    error
}

type sudoProbeBatch struct {
	SudoPath  string
	LookupErr error
	Results   map[string]sudoProbeResult
}

type sudoEvaluationInput struct {
	EffectiveUID   int
	SudoPresent    bool
	ProbeRequested bool
	Probe          sudoProbeResult
	Version        string
}

type sudoRunner func(context.Context, string, string) error

type suidEvaluationInput struct {
	FileInspected        bool
	Regular              bool
	Format               executableFormat
	Mode                 os.FileMode
	OwnerUIDKnown        bool
	OwnerUID             uint32
	Mount                mountStatus
	NoNewPrivsKnown      bool
	NoNewPrivs           bool
	UserNamespaceKnown   bool
	InitialUserNamespace bool
	Version              string
}

type executableFormat uint8

const (
	executableFormatUnknown executableFormat = iota
	executableFormatELF
	executableFormatScript
	executableFormatMalformedELF
)

type fileCapabilities struct {
	Revision    uint32
	Permitted   uint64
	Inheritable uint64
	Effective   bool
	RootID      uint32
	HasRootID   bool
}

type fileCapabilityInspection struct {
	Known        bool
	Present      bool
	Capabilities fileCapabilities
	Err          error
}

type requiredCapabilities struct {
	Names   []string
	Mask    uint64
	Unknown []string
	Known   bool
}

type capabilityEvaluationInput struct {
	FileInspected        bool
	Regular              bool
	Executable           bool
	Mount                mountStatus
	NoNewPrivsKnown      bool
	NoNewPrivs           bool
	UserNamespaceKnown   bool
	InitialUserNamespace bool
	CapBndKnown          bool
	CapBnd               uint64
	Required             requiredCapabilities
	Xattr                fileCapabilityInspection
	RequireEffective     bool
	Version              string
}

var linuxCapabilityBits = map[string]uint{
	"CAP_CHOWN":              unix.CAP_CHOWN,
	"CAP_DAC_OVERRIDE":       unix.CAP_DAC_OVERRIDE,
	"CAP_DAC_READ_SEARCH":    unix.CAP_DAC_READ_SEARCH,
	"CAP_FOWNER":             unix.CAP_FOWNER,
	"CAP_FSETID":             unix.CAP_FSETID,
	"CAP_KILL":               unix.CAP_KILL,
	"CAP_SETGID":             unix.CAP_SETGID,
	"CAP_SETUID":             unix.CAP_SETUID,
	"CAP_SETPCAP":            unix.CAP_SETPCAP,
	"CAP_LINUX_IMMUTABLE":    unix.CAP_LINUX_IMMUTABLE,
	"CAP_NET_BIND_SERVICE":   unix.CAP_NET_BIND_SERVICE,
	"CAP_NET_BROADCAST":      unix.CAP_NET_BROADCAST,
	"CAP_NET_ADMIN":          unix.CAP_NET_ADMIN,
	"CAP_NET_RAW":            unix.CAP_NET_RAW,
	"CAP_IPC_LOCK":           unix.CAP_IPC_LOCK,
	"CAP_IPC_OWNER":          unix.CAP_IPC_OWNER,
	"CAP_SYS_MODULE":         unix.CAP_SYS_MODULE,
	"CAP_SYS_RAWIO":          unix.CAP_SYS_RAWIO,
	"CAP_SYS_CHROOT":         unix.CAP_SYS_CHROOT,
	"CAP_SYS_PTRACE":         unix.CAP_SYS_PTRACE,
	"CAP_SYS_PACCT":          unix.CAP_SYS_PACCT,
	"CAP_SYS_ADMIN":          unix.CAP_SYS_ADMIN,
	"CAP_SYS_BOOT":           unix.CAP_SYS_BOOT,
	"CAP_SYS_NICE":           unix.CAP_SYS_NICE,
	"CAP_SYS_RESOURCE":       unix.CAP_SYS_RESOURCE,
	"CAP_SYS_TIME":           unix.CAP_SYS_TIME,
	"CAP_SYS_TTY_CONFIG":     unix.CAP_SYS_TTY_CONFIG,
	"CAP_MKNOD":              unix.CAP_MKNOD,
	"CAP_LEASE":              unix.CAP_LEASE,
	"CAP_AUDIT_WRITE":        unix.CAP_AUDIT_WRITE,
	"CAP_AUDIT_CONTROL":      unix.CAP_AUDIT_CONTROL,
	"CAP_SETFCAP":            unix.CAP_SETFCAP,
	"CAP_MAC_OVERRIDE":       unix.CAP_MAC_OVERRIDE,
	"CAP_MAC_ADMIN":          unix.CAP_MAC_ADMIN,
	"CAP_SYSLOG":             unix.CAP_SYSLOG,
	"CAP_WAKE_ALARM":         unix.CAP_WAKE_ALARM,
	"CAP_BLOCK_SUSPEND":      unix.CAP_BLOCK_SUSPEND,
	"CAP_AUDIT_READ":         unix.CAP_AUDIT_READ,
	"CAP_PERFMON":            unix.CAP_PERFMON,
	"CAP_BPF":                unix.CAP_BPF,
	"CAP_CHECKPOINT_RESTORE": unix.CAP_CHECKPOINT_RESTORE,
}

type procStatus struct {
	NoNewPrivs      bool
	NoNewPrivsKnown bool
	CapBnd          uint64
	CapBndKnown     bool
}

type hostSnapshot struct {
	procStatus
	RealUID              int
	EffectiveUID         int
	UserNamespaceKnown   bool
	InitialUserNamespace bool
	SudoPresent          bool
	SudoProbeRequested   bool
	Warnings             []string
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
	Format        executableFormat
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
	var duplicateNoNewPrivs, duplicateCapBnd bool

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		name, raw, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(raw)
		switch strings.TrimSpace(name) {
		case "NoNewPrivs":
			if sawNoNewPrivs {
				status.NoNewPrivs = false
				status.NoNewPrivsKnown = false
				if !duplicateNoNewPrivs {
					warnings = append(warnings, "NoNewPrivs is duplicated")
				}
				duplicateNoNewPrivs = true
				continue
			}
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
			if sawCapBnd {
				status.CapBnd = 0
				status.CapBndKnown = false
				if !duplicateCapBnd {
					warnings = append(warnings, "CapBnd is duplicated")
				}
				duplicateCapBnd = true
				continue
			}
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
		status.NoNewPrivs = false
		status.NoNewPrivsKnown = false
		status.CapBnd = 0
		status.CapBndKnown = false
		warnings = append(warnings, fmt.Sprintf("read process status: %v", err))
	}
	return status, warnings
}

func captureHostSnapshot(sudoProbeRequested bool) hostSnapshot {
	return captureHostSnapshotAt("/proc/self/status", sudoProbeRequested)
}

func captureHostSnapshotAt(statusPath string, sudoProbeRequested bool) hostSnapshot {
	return captureHostSnapshotAtWithSudoResolver(statusPath, sudoProbeRequested, locateTrustedSudo)
}

func captureHostSnapshotAtWithSudoResolver(statusPath string, sudoProbeRequested bool, resolve func() (string, error)) hostSnapshot {
	snapshot := hostSnapshot{
		RealUID:            os.Getuid(),
		EffectiveUID:       os.Geteuid(),
		SudoProbeRequested: sudoProbeRequested,
	}
	if err := trustedUserNamespace(); err == nil {
		snapshot.UserNamespaceKnown = true
		snapshot.InitialUserNamespace = true
	} else {
		snapshot.UserNamespaceKnown = true
		snapshot.Warnings = append(snapshot.Warnings, fmt.Sprintf("initial user namespace unavailable: %v", err))
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

	if _, err := resolve(); err == nil && snapshot.InitialUserNamespace {
		snapshot.SudoPresent = true
	} else {
		if err != nil {
			snapshot.Warnings = append(snapshot.Warnings, err.Error())
		}
	}
	return snapshot
}

func locateTrustedSudo() (string, error) {
	if err := trustedUserNamespace(); err != nil {
		return "", fmt.Errorf("sudo trust requires the initial user namespace: %w", err)
	}
	seen := make(map[string]bool)
	for _, rawDir := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if rawDir == "" || !filepath.IsAbs(rawDir) {
			continue
		}
		dir, err := filepath.EvalSymlinks(rawDir)
		if err != nil || seen[dir] {
			continue
		}
		seen[dir] = true
		if err := trustedDirectory(dir); err != nil {
			continue
		}

		candidate := filepath.Join(dir, "sudo")
		canonical, err := filepath.EvalSymlinks(candidate)
		if err != nil || !filepath.IsAbs(canonical) {
			continue
		}
		if err := trustedDirectory(filepath.Dir(canonical)); err != nil || trustedFile(canonical) != nil {
			continue
		}
		return canonical, nil
	}
	return "", errors.New("sudo was not safely available in PATH")
}

func trustedUserNamespace() error {
	return trustedUserNamespaceAt("/proc/self/ns/user")
}

func trustedUserNamespaceAt(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open user namespace: %w", err)
	}
	defer file.Close()

	namespaceType, err := unix.IoctlRetInt(int(file.Fd()), unix.NS_GET_NSTYPE)
	if err != nil {
		return fmt.Errorf("inspect user namespace type: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat user namespace: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return errors.New("user namespace inode is unavailable")
	}
	return trustedUserNamespaceIdentity(namespaceType, stat.Ino)
}

func trustedUserNamespaceIdentity(namespaceType int, inode uint64) error {
	if namespaceType != unix.CLONE_NEWUSER {
		return errors.New("namespace descriptor is not a user namespace")
	}
	if inode != initialUserNamespaceInode {
		return errors.New("user namespace is not the initial namespace")
	}
	return nil
}

func trustedDirectory(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%q is not a directory", current)
		}
		uid, ok := canonicalOwnerUID(info)
		if !ok || uid != 0 {
			return fmt.Errorf("%q is not root-owned", current)
		}
		if info.Mode().Perm()&022 != 0 {
			return fmt.Errorf("%q is writable by group or other", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func trustedFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}
	uid, ok := canonicalOwnerUID(info)
	if !ok || uid != 0 {
		return fmt.Errorf("%q is not root-owned", path)
	}
	if info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("%q is not executable", path)
	}
	if info.Mode().Perm()&022 != 0 {
		return fmt.Errorf("%q is writable by group or other", path)
	}
	return nil
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
	fd, err := unix.Open(result.CanonicalPath, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		result.Warning = fmt.Sprintf("stat canonical target for catalog executable %q: %v", result.CatalogName, err)
		return result
	}
	anchor := os.NewFile(uintptr(fd), result.CanonicalPath)
	defer anchor.Close()
	info, err := anchor.Stat()
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
	readable, err := os.Open(filepath.Join("/proc/self/fd", strconv.Itoa(fd)))
	if err != nil {
		result.Warning = fmt.Sprintf("open canonical executable for catalog executable %q: %v", result.CatalogName, err)
		return result
	}
	defer readable.Close()
	expectedMachine, expectedData, expectedClass, knownHostMachine := hostELFFormat()
	result.Format, err = inspectExecutableFormatFile(readable, expectedMachine, expectedData, expectedClass, knownHostMachine)
	if err != nil {
		result.Warning = fmt.Sprintf("inspect executable format for catalog executable %q: %v", result.CatalogName, err)
	}

	result.Mount, err = inspectMountFile(anchor)
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

func inspectExecutableFormat(path string) (executableFormat, error) {
	expectedMachine, expectedData, expectedClass, knownHostMachine := hostELFFormat()
	return inspectExecutableFormatForArchitecture(path, expectedMachine, expectedData, expectedClass, knownHostMachine)
}

func inspectExecutableFormatForMachine(path string, expectedMachine elf.Machine, knownHostMachine bool) (executableFormat, error) {
	return inspectExecutableFormatForArchitecture(path, expectedMachine, elf.ELFDATANONE, elf.ELFCLASSNONE, knownHostMachine)
}

func inspectExecutableFormatForArchitecture(path string, expectedMachine elf.Machine, expectedData elf.Data, expectedClass elf.Class, knownHostMachine bool) (executableFormat, error) {
	file, err := os.Open(path)
	if err != nil {
		return executableFormatUnknown, err
	}
	defer file.Close()
	return inspectExecutableFormatFile(file, expectedMachine, expectedData, expectedClass, knownHostMachine)
}

func inspectExecutableFormatFile(file *os.File, expectedMachine elf.Machine, expectedData elf.Data, expectedClass elf.Class, knownHostMachine bool) (executableFormat, error) {
	var header [4]byte
	n, err := io.ReadFull(file, header[:])
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return executableFormatUnknown, err
	}
	if n >= 2 && header[0] == '#' && header[1] == '!' {
		return executableFormatScript, nil
	}
	if n == len(header) && header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		parsed, err := elf.NewFile(file)
		if err != nil {
			return executableFormatMalformedELF, nil
		}
		defer parsed.Close()
		hasLoadableSegment := false
		for _, program := range parsed.Progs {
			if program.Type == elf.PT_LOAD {
				hasLoadableSegment = true
				break
			}
		}
		if (parsed.Type != elf.ET_EXEC && parsed.Type != elf.ET_DYN) || !hasLoadableSegment {
			return executableFormatMalformedELF, nil
		}
		if !knownHostMachine || parsed.Machine != expectedMachine || (expectedData != elf.ELFDATANONE && parsed.Data != expectedData) || (expectedClass != elf.ELFCLASSNONE && parsed.Class != expectedClass) {
			return executableFormatUnknown, nil
		}
		return executableFormatELF, nil
	}
	return executableFormatUnknown, nil
}

func hostELFMachine() (elf.Machine, bool) {
	machine, _, _, known := hostELFFormat()
	return machine, known
}

func hostELFFormat() (elf.Machine, elf.Data, elf.Class, bool) {
	switch runtime.GOARCH {
	case "386":
		return elf.EM_386, elf.ELFDATA2LSB, elf.ELFCLASS32, true
	case "amd64":
		return elf.EM_X86_64, elf.ELFDATA2LSB, elf.ELFCLASS64, true
	case "arm":
		return elf.EM_ARM, elf.ELFDATA2LSB, elf.ELFCLASS32, true
	case "arm64":
		return elf.EM_AARCH64, elf.ELFDATA2LSB, elf.ELFCLASS64, true
	case "loong64":
		return elf.EM_LOONGARCH, elf.ELFDATA2LSB, elf.ELFCLASS64, true
	case "mips":
		return elf.EM_MIPS, elf.ELFDATA2MSB, elf.ELFCLASS32, true
	case "mipsle":
		return elf.EM_MIPS, elf.ELFDATA2LSB, elf.ELFCLASS32, true
	case "mips64":
		return elf.EM_MIPS, elf.ELFDATA2MSB, elf.ELFCLASS64, true
	case "mips64le":
		return elf.EM_MIPS, elf.ELFDATA2LSB, elf.ELFCLASS64, true
	case "ppc64":
		return elf.EM_PPC64, elf.ELFDATA2MSB, elf.ELFCLASS64, true
	case "ppc64le":
		return elf.EM_PPC64, elf.ELFDATA2LSB, elf.ELFCLASS64, true
	case "riscv64":
		return elf.EM_RISCV, elf.ELFDATA2LSB, elf.ELFCLASS64, true
	case "s390x":
		return elf.EM_S390, elf.ELFDATA2MSB, elf.ELFCLASS64, true
	default:
		return 0, elf.ELFDATANONE, elf.ELFCLASSNONE, false
	}
}

func inspectMount(path string) (mountStatus, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return mountStatus{}, err
	}
	return interpretMountFlags(int64(stat.Flags)), nil
}

func inspectMountFile(file *os.File) (mountStatus, error) {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &stat); err != nil {
		return mountStatus{}, err
	}
	return interpretMountFlags(int64(stat.Flags)), nil
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

func evaluateDiscovery(discovery executableDiscovery) applicabilityResult {
	states := []applicabilityState{stateConfirmed}
	var evidence []string

	if !discovery.Found {
		states = append(states, stateUnavailable)
		evidence = append(evidence, "catalog executable was not found in PATH")
		return applicabilityResult{State: composeApplicability(states...), Evidence: evidence}
	}
	if discovery.FileInfo == nil {
		states = append(states, stateUnknown)
		evidence = append(evidence, "canonical target file information could not be determined")
	} else if !discovery.FileInfo.Mode().IsRegular() {
		states = append(states, stateUnavailable)
		evidence = append(evidence, "canonical target is not a regular file")
	}
	if discovery.FileInfo != nil && !discovery.Executable {
		states = append(states, stateUnavailable)
		evidence = append(evidence, "canonical target is not executable")
	}
	if !discovery.Mount.Known {
		states = append(states, stateUnknown)
		evidence = append(evidence, "filesystem mount flags could not be determined")
	} else if discovery.Mount.NoExec {
		states = append(states, stateUnavailable)
		evidence = append(evidence, "filesystem is mounted noexec")
	}

	return applicabilityResult{State: composeApplicability(states...), Evidence: evidence}
}

func evaluateUnprivileged(discovery executableDiscovery, version string) applicabilityResult {
	result := evaluateDiscovery(discovery)
	if version == "" {
		return result
	}
	return composeApplicabilityResults(result, applicabilityResult{
		State:    stateUnknown,
		Evidence: []string{"version restriction was not verified: " + version},
	})
}

func composeApplicability(states ...applicabilityState) applicabilityState {
	if len(states) == 0 {
		return stateUnknown
	}

	result := stateConfirmed
	for _, state := range states {
		switch state {
		case stateUnavailable:
			return stateUnavailable
		case stateUnknown:
			result = stateUnknown
		case statePotential:
			if result == stateConfirmed {
				result = statePotential
			}
		case stateConfirmed:
		default:
			result = stateUnknown
		}
	}
	return result
}

func composeApplicabilityResults(results ...applicabilityResult) applicabilityResult {
	states := make([]applicabilityState, 0, len(results))
	seen := make(map[string]bool)
	var evidence []string
	for _, result := range results {
		states = append(states, result.State)
		for _, item := range result.Evidence {
			if item == "" || seen[item] {
				continue
			}
			seen[item] = true
			evidence = append(evidence, item)
		}
	}
	return applicabilityResult{State: composeApplicability(states...), Evidence: evidence}
}

func canonicalOwnerUID(info os.FileInfo) (uint32, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, false
	}
	return stat.Uid, true
}

func evaluateSUID(input suidEvaluationInput) applicabilityResult {
	states := []applicabilityState{stateConfirmed}
	var evidence []string

	if !input.FileInspected {
		states = append(states, stateUnknown)
		evidence = append(evidence, "canonical target file information could not be determined")
	} else {
		switch input.Format {
		case executableFormatScript:
			states = append(states, stateUnavailable)
			evidence = append(evidence, "interpreter scripts ignore the setuid bit on Linux")
		case executableFormatMalformedELF:
			states = append(states, stateUnknown)
			evidence = append(evidence, "ELF header could not be validated as a loadable executable")
		case executableFormatUnknown:
			states = append(states, stateUnknown)
			evidence = append(evidence, "executable format could not be verified")
		}
		if !input.Regular {
			states = append(states, stateUnavailable)
			evidence = append(evidence, "canonical target is not a regular file")
		}
		if input.Mode&os.ModeSetuid == 0 {
			states = append(states, stateUnavailable)
			evidence = append(evidence, "canonical target does not have setuid bit")
		}
	}
	if input.UserNamespaceKnown && !input.InitialUserNamespace {
		states = append(states, stateUnavailable)
		evidence = append(evidence, "SUID applicability requires the initial user namespace")
	}

	if !input.OwnerUIDKnown {
		states = append(states, stateUnknown)
		evidence = append(evidence, "canonical target owner UID could not be determined")
	} else if input.OwnerUID != 0 {
		states = append(states, stateUnavailable)
		evidence = append(evidence, fmt.Sprintf("canonical target owner UID is %d, expected 0", input.OwnerUID))
	}

	if !input.Mount.Known {
		states = append(states, stateUnknown)
		evidence = append(evidence, "filesystem mount flags could not be determined")
	} else {
		if input.Mount.NoSUID {
			states = append(states, stateUnavailable)
			evidence = append(evidence, "filesystem is mounted nosuid")
		}
		if input.Mount.NoExec {
			states = append(states, stateUnavailable)
			evidence = append(evidence, "filesystem is mounted noexec")
		}
	}

	if !input.NoNewPrivsKnown {
		states = append(states, stateUnknown)
		evidence = append(evidence, "NoNewPrivs could not be determined")
	} else if input.NoNewPrivs {
		states = append(states, stateUnavailable)
		evidence = append(evidence, "NoNewPrivs is enabled")
	}

	if input.Version != "" {
		states = append(states, stateUnknown)
		evidence = append(evidence, "version restriction was not verified: "+input.Version)
	}

	return applicabilityResult{State: composeApplicability(states...), Evidence: evidence}
}

func decodeFileCapabilities(data []byte) (fileCapabilities, error) {
	if len(data) < 4 {
		return fileCapabilities{}, fmt.Errorf("security.capability is truncated: length %d", len(data))
	}

	magic := binary.LittleEndian.Uint32(data[:4])
	revision := magic & vfsCapabilityRevisionMask
	if magic&^vfsCapabilityKnownFlags != 0 {
		return fileCapabilities{}, fmt.Errorf("security.capability has unsupported flags 0x%08x", magic&^vfsCapabilityKnownFlags)
	}
	wantLength := 0
	switch revision {
	case vfsCapabilityRevision2:
		wantLength = vfsCapabilityRevision2Size
	case vfsCapabilityRevision3:
		wantLength = vfsCapabilityRevision3Size
	default:
		return fileCapabilities{}, fmt.Errorf("unsupported security.capability revision 0x%08x", revision)
	}
	if len(data) != wantLength {
		return fileCapabilities{}, fmt.Errorf("security.capability revision 0x%08x has length %d, want %d", revision, len(data), wantLength)
	}

	capabilities := fileCapabilities{
		Revision:    revision,
		Permitted:   uint64(binary.LittleEndian.Uint32(data[4:8])) | uint64(binary.LittleEndian.Uint32(data[12:16]))<<32,
		Inheritable: uint64(binary.LittleEndian.Uint32(data[8:12])) | uint64(binary.LittleEndian.Uint32(data[16:20]))<<32,
		Effective:   magic&vfsCapabilityEffective != 0,
	}
	if revision == vfsCapabilityRevision3 {
		capabilities.RootID = binary.LittleEndian.Uint32(data[20:24])
		capabilities.HasRootID = true
	}
	return capabilities, nil
}

func inspectFileCapabilities(path string) fileCapabilityInspection {
	for range 2 {
		size, err := unix.Getxattr(path, securityCapabilityXattr, nil)
		if err != nil {
			return fileCapabilityInspectionError(err)
		}

		data := make([]byte, size)
		read, err := unix.Getxattr(path, securityCapabilityXattr, data)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			return fileCapabilityInspectionError(err)
		}
		if read < 0 || read > len(data) {
			return fileCapabilityInspection{Present: true, Err: fmt.Errorf("read security.capability: invalid length %d", read)}
		}

		capabilities, err := decodeFileCapabilities(data[:read])
		if err != nil {
			return fileCapabilityInspection{Present: true, Err: err}
		}
		return fileCapabilityInspection{Known: true, Present: true, Capabilities: capabilities}
	}
	return fileCapabilityInspection{Present: true, Err: errors.New("security.capability changed while reading")}
}

func fileCapabilityInspectionError(err error) fileCapabilityInspection {
	if errors.Is(err, unix.ENODATA) {
		return fileCapabilityInspection{Known: true}
	}
	return fileCapabilityInspection{Err: fmt.Errorf("inspect security.capability: %w", err)}
}

func parseRequiredCapabilities(names []string) requiredCapabilities {
	var result requiredCapabilities
	unknown := make(map[string]bool)
	for _, name := range names {
		canonical := strings.ToUpper(strings.TrimSpace(name))
		bit, ok := linuxCapabilityBits[canonical]
		if !ok {
			unknown[canonical] = true
			continue
		}
		result.Mask |= uint64(1) << bit
	}
	result.Names = capabilityNamesForMask(result.Mask)
	result.Unknown = slices.Sorted(maps.Keys(unknown))
	result.Known = len(result.Names) > 0 && len(result.Unknown) == 0
	return result
}

func capabilityNamesForMask(mask uint64) []string {
	var names []string
	for name, bit := range linuxCapabilityBits {
		if mask&(uint64(1)<<bit) != 0 {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func evaluateCapabilities(input capabilityEvaluationInput) applicabilityResult {
	states := []applicabilityState{stateConfirmed}
	var evidence []string

	if !input.FileInspected {
		states = append(states, stateUnknown)
		evidence = append(evidence, "canonical target file information could not be determined")
	} else {
		if !input.Regular {
			states = append(states, stateUnavailable)
			evidence = append(evidence, "canonical target is not a regular file")
		}
		if !input.Executable {
			states = append(states, stateUnavailable)
			evidence = append(evidence, "canonical target is not executable")
		}
	}
	if input.UserNamespaceKnown && !input.InitialUserNamespace {
		states = append(states, stateUnavailable)
		evidence = append(evidence, "capability applicability requires the initial user namespace")
	}

	if !input.Mount.Known {
		states = append(states, stateUnknown)
		evidence = append(evidence, "filesystem mount flags could not be determined")
	} else {
		if input.Mount.NoSUID {
			states = append(states, stateUnavailable)
			evidence = append(evidence, "filesystem is mounted nosuid")
		}
		if input.Mount.NoExec {
			states = append(states, stateUnavailable)
			evidence = append(evidence, "filesystem is mounted noexec")
		}
	}

	if !input.NoNewPrivsKnown {
		states = append(states, stateUnknown)
		evidence = append(evidence, "NoNewPrivs could not be determined")
	} else if input.NoNewPrivs {
		states = append(states, stateUnavailable)
		evidence = append(evidence, "NoNewPrivs is enabled")
	}

	if !input.Required.Known {
		states = append(states, stateUnknown)
		if len(input.Required.Names) == 0 && len(input.Required.Unknown) == 0 {
			evidence = append(evidence, "required capability list is empty")
		}
		for _, name := range input.Required.Unknown {
			evidence = append(evidence, "unknown required capability "+name)
		}
	}

	if !input.Xattr.Known {
		states = append(states, stateUnknown)
		message := "security.capability could not be inspected"
		if input.Xattr.Err != nil {
			message += ": " + input.Xattr.Err.Error()
		}
		evidence = append(evidence, message)
	} else if !input.Xattr.Present {
		states = append(states, stateUnavailable)
		evidence = append(evidence, "security.capability is not present")
	} else {
		missing := input.Required.Mask &^ input.Xattr.Capabilities.Permitted
		for _, name := range capabilityNamesForMask(missing) {
			states = append(states, stateUnavailable)
			evidence = append(evidence, "required capability "+name+" is missing from file permitted set")
		}
		if input.RequireEffective && !input.Xattr.Capabilities.Effective {
			states = append(states, stateUnavailable)
			evidence = append(evidence, "file capability effective flag is not set")
		}
		if input.Xattr.Capabilities.Revision == vfsCapabilityRevision3 && input.Xattr.Capabilities.HasRootID {
			states = append(states, stateUnknown)
			evidence = append(evidence, "V3 file capability namespace root ID compatibility could not be verified")
		}
	}

	if !input.CapBndKnown {
		states = append(states, stateUnknown)
		evidence = append(evidence, "CapBnd could not be determined")
	} else {
		missing := input.Required.Mask &^ input.CapBnd
		for _, name := range capabilityNamesForMask(missing) {
			states = append(states, stateUnavailable)
			evidence = append(evidence, "required capability "+name+" is excluded by CapBnd")
		}
	}

	if input.Version != "" {
		states = append(states, stateUnknown)
		evidence = append(evidence, "version restriction was not verified: "+input.Version)
	}

	return applicabilityResult{State: composeApplicability(states...), Evidence: evidence}
}

func evaluateSudo(input sudoEvaluationInput) applicabilityResult {
	states := []applicabilityState{stateConfirmed}
	var evidence []string

	switch {
	case !input.SudoPresent:
		states = append(states, stateUnavailable)
		evidence = append(evidence, "sudo is not safely available in PATH")
	case input.EffectiveUID == 0:
		evidence = append(evidence, "effective UID is 0; sudo may be unnecessary")
	case !input.ProbeRequested:
		states = append(states, stateUnknown)
		evidence = append(evidence, "sudo is available, but policy was not checked; use -check-sudo for path-level evidence")
	default:
		switch input.Probe.Status {
		case sudoProbeRecognized:
			states = append(states, statePotential)
			evidence = append(evidence,
				"sudo policy recognized the canonical executable path",
				"path-level sudo evidence does not prove the full GTFOBins command line is authorized",
			)
		case sudoProbeNonzero:
			states = append(states, stateUnknown)
			evidence = append(evidence, "sudo policy probe returned a nonzero result; authorization could not be determined")
		case sudoProbeExecutionError:
			states = append(states, stateUnknown)
			message := "sudo policy probe could not be executed"
			if input.Probe.Err != nil {
				message += ": " + input.Probe.Err.Error()
			}
			evidence = append(evidence, message)
		case sudoProbeBudgetExhausted:
			states = append(states, stateUnknown)
			evidence = append(evidence, "global sudo probe budget expired before this path could be checked")
		default:
			states = append(states, stateUnknown)
			evidence = append(evidence, "sudo policy probe was requested but no result is available")
		}
	}

	if input.Version != "" {
		states = append(states, stateUnknown)
		evidence = append(evidence, "version restriction was not verified: "+input.Version)
	}

	return applicabilityResult{State: composeApplicability(states...), Evidence: evidence}
}

func evaluateContext(contextKey string, contextList []string, version string, discovery executableDiscovery, host hostSnapshot, sudoBatch sudoProbeBatch, capabilities map[string]fileCapabilityInspection) applicabilityResult {
	common := evaluateDiscovery(discovery)
	fileInspected := discovery.FileInfo != nil
	regular := fileInspected && discovery.FileInfo.Mode().IsRegular()
	var mode os.FileMode
	if fileInspected {
		mode = discovery.FileInfo.Mode()
	}

	switch contextKey {
	case "unprivileged":
		return evaluateUnprivileged(discovery, version)
	case "suid":
		ownerUID, ownerKnown := canonicalOwnerUID(discovery.FileInfo)
		return composeApplicabilityResults(common, evaluateSUID(suidEvaluationInput{
			FileInspected:        fileInspected,
			Regular:              regular,
			Format:               discovery.Format,
			Mode:                 mode,
			OwnerUIDKnown:        ownerKnown,
			OwnerUID:             ownerUID,
			Mount:                discovery.Mount,
			NoNewPrivsKnown:      host.NoNewPrivsKnown,
			NoNewPrivs:           host.NoNewPrivs,
			UserNamespaceKnown:   host.UserNamespaceKnown,
			InitialUserNamespace: host.InitialUserNamespace,
			Version:              version,
		}))
	case "capabilities":
		// GTFOBins has no structured field proving that a technique works without
		// effective file capabilities, so the first release requires the flag.
		return composeApplicabilityResults(common, evaluateCapabilities(capabilityEvaluationInput{
			FileInspected:        fileInspected,
			Regular:              regular,
			Executable:           discovery.Executable,
			Mount:                discovery.Mount,
			NoNewPrivsKnown:      host.NoNewPrivsKnown,
			NoNewPrivs:           host.NoNewPrivs,
			UserNamespaceKnown:   host.UserNamespaceKnown,
			InitialUserNamespace: host.InitialUserNamespace,
			CapBndKnown:          host.CapBndKnown,
			CapBnd:               host.CapBnd,
			Required:             parseRequiredCapabilities(contextList),
			Xattr:                capabilities[discovery.CanonicalPath],
			RequireEffective:     true,
			Version:              version,
		}))
	case "sudo":
		present := host.SudoPresent || sudoBatch.SudoPath != ""
		probe := sudoBatch.Results[discovery.CanonicalPath]
		if host.SudoProbeRequested && host.SudoPresent && sudoBatch.LookupErr != nil {
			probe = sudoProbeResult{Status: sudoProbeExecutionError, Err: sudoBatch.LookupErr}
		}
		return composeApplicabilityResults(common, evaluateSudo(sudoEvaluationInput{
			EffectiveUID:   host.EffectiveUID,
			SudoPresent:    present,
			ProbeRequested: host.SudoProbeRequested,
			Probe:          probe,
			Version:        version,
		}))
	default:
		result := applicabilityResult{
			State:    stateUnknown,
			Evidence: []string{fmt.Sprintf("goGTFO has no evaluator for catalog context %q", contextKey)},
		}
		if version != "" {
			result = composeApplicabilityResults(result, applicabilityResult{
				State:    stateUnknown,
				Evidence: []string{"version restriction was not verified: " + version},
			})
		}
		return result
	}
}

func evaluateTechnique(value technique, discovery executableDiscovery, host hostSnapshot, sudoBatch sudoProbeBatch, capabilities map[string]fileCapabilityInspection) technique {
	value.MitreIDs = slices.Clone(value.MitreIDs)
	slices.Sort(value.MitreIDs)
	value.MitreIDs = slices.Compact(value.MitreIDs)
	value.Warnings = slices.Clone(value.Warnings)

	result := evaluateContext(value.ContextKey, value.ContextList, value.Version, discovery, host, sudoBatch, capabilities)
	for _, launcher := range value.Launchers {
		result = composeApplicabilityResults(result, evaluateContext(launcher.ContextKey, launcher.ContextList, launcher.Version, discovery, host, sudoBatch, capabilities))
	}
	for _, warning := range value.Warnings {
		result = composeApplicabilityResults(result, applicabilityResult{
			State:    stateUnknown,
			Evidence: []string{"unresolved companion prerequisite: " + warning},
		})
	}
	value.State = result.State
	value.Evidence = result.Evidence
	return value
}

func evaluateFindings(resolved []finding, discoveries []executableDiscovery, host hostSnapshot, sudoBatch sudoProbeBatch, capabilities map[string]fileCapabilityInspection) []finding {
	byName := make(map[string]executableDiscovery, len(discoveries))
	for _, discovery := range discoveries {
		byName[discovery.CatalogName] = discovery
	}

	var evaluated []finding
	for _, value := range resolved {
		discovery, ok := byName[value.Name]
		if !ok || !discovery.Found {
			continue
		}
		value.AliasChain = slices.Clone(value.AliasChain)
		value.Warnings = slices.Clone(value.Warnings)
		value.InvocablePath = discovery.InvocablePath
		value.CanonicalPath = discovery.CanonicalPath
		if discovery.Warning != "" {
			value.DiscoveryWarnings = []string{discovery.Warning}
		}
		techniques := value.Techniques
		value.Techniques = make([]technique, len(techniques))
		for index, candidate := range techniques {
			value.Techniques[index] = evaluateTechnique(candidate, discovery, host, sudoBatch, capabilities)
		}
		evaluated = append(evaluated, value)
	}
	return evaluated
}

func findingNeedsContext(value finding, contextKey string) bool {
	for _, candidate := range value.Techniques {
		if candidate.ContextKey == contextKey {
			return true
		}
		for _, launcher := range candidate.Launchers {
			if launcher.ContextKey == contextKey {
				return true
			}
		}
	}
	return false
}

func collectCapabilityInspections(findings []finding, discoveries []executableDiscovery, inspect func(string) fileCapabilityInspection) map[string]fileCapabilityInspection {
	needed := make(map[string]bool)
	for _, value := range findings {
		if findingNeedsContext(value, "capabilities") {
			needed[value.Name] = true
		}
	}

	result := make(map[string]fileCapabilityInspection)
	for _, discovery := range discoveries {
		path := discovery.CanonicalPath
		if !discovery.Found || !discovery.Executable || path == "" || !needed[discovery.CatalogName] {
			continue
		}
		if _, cached := result[path]; !cached {
			result[path] = inspect(path)
		}
	}
	return result
}

func sudoRelevantDiscoveries(findings []finding, discoveries []executableDiscovery) []executableDiscovery {
	needed := make(map[string]bool)
	for _, value := range findings {
		if findingNeedsContext(value, "sudo") {
			needed[value.Name] = true
		}
	}
	result := make([]executableDiscovery, 0, len(discoveries))
	for _, discovery := range discoveries {
		if discovery.Found && needed[discovery.CatalogName] {
			result = append(result, discovery)
		}
	}
	return result
}

func sudoProbeBatchStatus(requested bool, batch sudoProbeBatch) string {
	if !requested {
		return "not requested"
	}
	if batch.LookupErr != nil || batch.SudoPath == "" {
		return "unavailable"
	}
	for _, result := range batch.Results {
		if result.Status == sudoProbeBudgetExhausted {
			return "partial timeout"
		}
	}
	return "completed"
}

func probeSudoPolicies(parent context.Context, requested bool, discoveries []executableDiscovery, runner sudoRunner) sudoProbeBatch {
	return probeSudoPoliciesWithResolver(parent, requested, discoveries, runner, locateTrustedSudo)
}

func probeSudoPoliciesWithResolver(parent context.Context, requested bool, discoveries []executableDiscovery, runner sudoRunner, resolve func() (string, error)) sudoProbeBatch {
	if !requested {
		return sudoProbeBatch{}
	}

	sudoPath, err := resolve()
	if err != nil {
		return sudoProbeBatch{LookupErr: fmt.Errorf("locate sudo: %w", err)}
	}

	ctx, cancel := context.WithTimeout(parent, sudoProbeBudget)
	defer cancel()
	batch := sudoProbeBatch{
		SudoPath: sudoPath,
		Results:  make(map[string]sudoProbeResult),
	}
	for _, discovery := range discoveries {
		path := discovery.CanonicalPath
		if path == "" {
			continue
		}
		if _, cached := batch.Results[path]; cached {
			continue
		}
		if ctx.Err() != nil {
			batch.Results[path] = sudoProbeResult{Status: sudoProbeBudgetExhausted, Err: ctx.Err()}
			continue
		}

		err := runner(ctx, sudoPath, path)
		switch {
		case err == nil:
			batch.Results[path] = sudoProbeResult{Status: sudoProbeRecognized}
		case ctx.Err() != nil:
			batch.Results[path] = sudoProbeResult{Status: sudoProbeBudgetExhausted, Err: ctx.Err()}
		default:
			var exitError *exec.ExitError
			if errors.As(err, &exitError) {
				batch.Results[path] = sudoProbeResult{Status: sudoProbeNonzero}
			} else {
				batch.Results[path] = sudoProbeResult{Status: sudoProbeExecutionError, Err: err}
			}
		}
	}
	return batch
}

func newSudoCommand(ctx context.Context, sudoPath, canonicalPath string) *exec.Cmd {
	return exec.CommandContext(ctx, sudoPath, "-n", "-l", canonicalPath)
}

func runSudoProbe(ctx context.Context, sudoPath, canonicalPath string) error {
	return newSudoCommand(ctx, sudoPath, canonicalPath).Run()
}
