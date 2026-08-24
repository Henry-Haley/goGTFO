//go:build linux

package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorCyan   = "\033[96m"
	colorOrange = "\033[38;5;208m"
	colorGreen  = "\033[92m"
	colorYellow = "\033[93m"
)

var plainMode bool

type sortMode string

const (
	sortBinary  sortMode = "binary"
	sortContext sortMode = "context"
	sortAttack  sortMode = "attack"
)

type options struct {
	Help      bool
	Plain     bool
	Search    string
	Sort      sortMode
	All       bool
	CheckSudo bool
}

type reportData struct {
	Findings            []finding
	EffectiveUID        int
	Sort                sortMode
	AllContexts         bool
	SudoProbe           string
	InstalledBinaries   int
	DisplayedTechniques int
	HiddenUnknown       int
	HiddenUnavailable   int
	CatalogWarnings     int
	HostWarnings        []string
}

type techniqueRow struct {
	Finding   *finding
	Technique technique
}

type loadingBox struct {
	message string
	drawn   bool
}

func parseOptions(args []string) (options, error) {
	var value options
	var rawSort string
	flags := flag.NewFlagSet("goGTFO", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&value.Help, "h", false, "show help")
	flags.BoolVar(&value.Help, "help", false, "show help")
	flags.BoolVar(&value.Plain, "plain", false, "ASCII-only output for basic terminals")
	flags.StringVar(&value.Search, "s", "", "search for one catalog executable")
	flags.StringVar(&value.Search, "search", "", "search for one catalog executable")
	flags.StringVar(&rawSort, "sort", "binary", "sort by binary, context, or attack")
	flags.BoolVar(&value.All, "all", false, "show unknown and unavailable contexts")
	flags.BoolVar(&value.CheckSudo, "check-sudo", false, "check sudo policy non-interactively; checks may be logged")
	if err := flags.Parse(args); err != nil {
		return value, err
	}
	if flags.NArg() != 0 {
		return value, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	mode, err := parseSortMode(rawSort)
	if err != nil {
		return value, err
	}
	value.Sort = mode
	value.Search = strings.TrimSpace(value.Search)
	return value, nil
}

func parseSortMode(raw string) (sortMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "binary", "b":
		return sortBinary, nil
	case "context", "c", "ctx", "privilege":
		return sortContext, nil
	case "attack", "a", "mitre":
		return sortAttack, nil
	default:
		return "", fmt.Errorf("unknown sort %q (use binary, context, or attack)", raw)
	}
}

func helpExeName() string {
	if len(os.Args) > 0 {
		if name := filepath.Base(os.Args[0]); name != "" && name != "." {
			return name
		}
	}
	return "goGTFO"
}

func printBanner() {
	if plainMode {
		fmt.Println("goGTFO")
		fmt.Println("Maintainer: Henry Haley")
		fmt.Println(strings.Repeat("-", 48))
		fmt.Println()
		return
	}
	fmt.Printf("\n%s%sgoGTFO%s\n", colorCyan, colorBold, colorReset)
	fmt.Printf("%sMaintainer: Henry Haley%s\n\n", colorGreen, colorReset)
}

func printHelp() {
	printBanner()
	exe := inlineTerminalText(helpExeName())
	fmt.Printf(`goGTFO identifies GTFOBins executables available through PATH and evaluates
their documented Linux contexts. It never executes GTFOBins techniques.

Usage:
  %s [flags]

Flags:
  -h, -help          Show this help
  -plain             ASCII structural output with no terminal control sequences
  -s, -search name   Show one catalog executable and all context states
  -sort mode         Sort by binary, context, or attack (default "binary")
  -all               Show unknown and unavailable contexts
  -check-sudo        Check sudo policy non-interactively; checks may be logged

Sort aliases:
  binary:  b
  context: c, ctx, privilege
  attack:  a, mitre

Examples:
  %s
  %s -s bash
  %s -plain -all
  %s -sort context
  %s -sort attack

`, exe, exe, exe, exe, exe, exe)
}

func newLoadingBox(message string) *loadingBox {
	return &loadingBox{message: message}
}

func (l *loadingBox) start() {
	if plainMode {
		fmt.Printf("[*] %s\n", l.message)
		return
	}
	l.draw(false)
}

func loadingLine(done bool, message string) string {
	prefix := "..."
	if done {
		prefix = "✓"
	}
	line := fmt.Sprintf("  %s %s", prefix, message)
	if len(line) > 40 {
		line = line[:37] + "..."
	}
	return line + strings.Repeat(" ", 40-len(line))
}

func (l *loadingBox) draw(done bool) {
	line := loadingLine(done, l.message)
	if done {
		line = colorGreen + line + colorReset
	}
	if l.drawn {
		fmt.Print("\033[3A")
	}
	l.drawn = true
	fmt.Printf("\033[2K\r  %s╭──────────────────────────────────────────╮%s\n", colorCyan, colorReset)
	fmt.Printf("\033[2K\r  %s│%s%s%s│%s\n", colorCyan, colorReset, line, colorCyan, colorReset)
	fmt.Printf("\033[2K\r  %s╰──────────────────────────────────────────╯%s\n", colorCyan, colorReset)
}

func (l *loadingBox) setMessage(message string) {
	l.message = message
	if plainMode {
		fmt.Printf("[*] %s\n", message)
		return
	}
	l.draw(false)
}

func (l *loadingBox) finish(message string) {
	if plainMode {
		fmt.Printf("[+] %s\n\n", message)
		return
	}
	l.message = message
	l.draw(true)
	fmt.Println()
}

func run(args []string) int {
	return runWithCatalogFetcher(args, fetchCatalog)
}

func runWithCatalogFetcher(args []string, fetch func(context.Context) (catalog, error)) int {
	value, err := parseOptions(args)
	plainMode = value.Plain
	if err != nil {
		fmt.Fprintln(os.Stderr, inlineTerminalText(err.Error()))
		printHelp()
		return 2
	}
	if value.Help {
		printHelp()
		return 0
	}
	return runCatalog(context.Background(), value, fetch)
}

func runCatalog(ctx context.Context, value options, fetch func(context.Context) (catalog, error)) int {
	printBanner()
	loader := newLoadingBox("Fetching GTFOBins catalog...")
	loader.start()

	catalogData, err := fetch(ctx)
	if err != nil {
		loader.finish("Failed")
		fmt.Fprintln(os.Stderr, inlineTerminalText(err.Error()))
		return 1
	}

	loader.setMessage("Resolving catalog relationships...")
	resolved := resolveCatalog(catalogData)
	selectedFindings := resolved.Findings
	selectedExecutables := catalogData.Executables
	if value.Search != "" {
		search, err := searchCatalogName(catalogData.Executables, value.Search)
		if err != nil {
			loader.finish("Not found")
			fmt.Fprintln(os.Stderr, inlineTerminalText(err.Error()))
			return 1
		}
		selectedFindings = findingsNamed(resolved.Findings, search.Name)
		selectedExecutables = map[string]executableDef{search.Name: catalogData.Executables[search.Name]}
	}

	loader.setMessage("Discovering PATH executables...")
	discoveries := discoverExecutables(selectedExecutables)
	if value.Search != "" && (len(discoveries) == 0 || !discoveries[0].Found) {
		loader.finish("Not found in PATH")
		fmt.Fprintf(os.Stderr, "%s exists in the GTFOBins catalog but was not found in PATH.\n", inlineTerminalText(value.Search))
		return 1
	}

	loader.setMessage("Capturing Linux host state...")
	host := captureHostSnapshot(value.CheckSudo)

	if value.CheckSudo {
		loader.setMessage("Checking sudo policy...")
	}
	sudoBatch := probeSudoPolicies(ctx, value.CheckSudo, sudoRelevantDiscoveries(selectedFindings, discoveries), runSudoProbe)

	loader.setMessage("Checking Linux contexts...")
	capabilities := collectCapabilityInspections(selectedFindings, discoveries, inspectFileCapabilities)
	evaluated := evaluateFindings(selectedFindings, discoveries, host, sudoBatch, capabilities)

	loader.setMessage("Preparing output...")
	showAll := value.All || value.Search != ""
	report := filterFindings(evaluated, showAll)
	report.EffectiveUID = host.EffectiveUID
	report.Sort = value.Sort
	report.AllContexts = showAll
	report.SudoProbe = sudoProbeBatchStatus(value.CheckSudo, sudoBatch)
	report.CatalogWarnings = len(resolved.Warnings)
	report.HostWarnings = slices.Clone(host.Warnings)
	loader.finish(fmt.Sprintf("Prepared %d techniques", report.DisplayedTechniques))

	renderReport(report)
	return 0
}

func findingsNamed(values []finding, name string) []finding {
	for _, value := range values {
		if value.Name == name {
			return []finding{value}
		}
	}
	return nil
}

func filterFindings(values []finding, showAll bool) reportData {
	report := reportData{AllContexts: showAll, InstalledBinaries: len(values)}
	for _, value := range values {
		techniques := make([]technique, 0, len(value.Techniques))
		for _, candidate := range value.Techniques {
			show := showAll || candidate.State == stateConfirmed || candidate.State == statePotential
			if !show {
				switch candidate.State {
				case stateUnavailable:
					report.HiddenUnavailable++
				default:
					report.HiddenUnknown++
				}
				continue
			}
			techniques = append(techniques, candidate)
			report.DisplayedTechniques++
		}
		if len(techniques) == 0 {
			continue
		}
		value.Techniques = techniques
		report.Findings = append(report.Findings, value)
	}
	return report
}

func compareCatalogNames(a, b string) int {
	if folded := cmp.Compare(strings.ToLower(a), strings.ToLower(b)); folded != 0 {
		return folded
	}
	return cmp.Compare(a, b)
}

func stateRank(state applicabilityState) int {
	switch state {
	case stateConfirmed:
		return 0
	case statePotential:
		return 1
	case stateUnknown:
		return 2
	case stateUnavailable:
		return 3
	default:
		return 4
	}
}

func contextRank(key string) (int, string) {
	switch key {
	case "sudo":
		return 0, ""
	case "suid":
		return 1, ""
	case "capabilities":
		return 2, ""
	case "unprivileged":
		return 3, ""
	default:
		return 4, key
	}
}

func compareContexts(a, b string) int {
	aRank, aUnknown := contextRank(a)
	bRank, bUnknown := contextRank(b)
	if rank := cmp.Compare(aRank, bRank); rank != 0 {
		return rank
	}
	return cmp.Compare(aUnknown, bUnknown)
}

func sortedAttackIDs(ids []string) []string {
	result := slices.Clone(ids)
	slices.Sort(result)
	return slices.Compact(result)
}

func compareAttackIDs(a, b []string) int {
	a = sortedAttackIDs(a)
	b = sortedAttackIDs(b)
	if len(a) == 0 && len(b) != 0 {
		return 1
	}
	if len(a) != 0 && len(b) == 0 {
		return -1
	}
	return slices.Compare(a, b)
}

func firstAttackID(ids []string) string {
	ids = sortedAttackIDs(ids)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func sortBinaryFindings(values []finding) {
	slices.SortStableFunc(values, func(a, b finding) int {
		return compareCatalogNames(a.Name, b.Name)
	})
	for index := range values {
		slices.SortStableFunc(values[index].Techniques, func(a, b technique) int {
			if order := compareContexts(a.ContextKey, b.ContextKey); order != 0 {
				return order
			}
			if order := cmp.Compare(a.FunctionLabel, b.FunctionLabel); order != 0 {
				return order
			}
			if order := cmp.Compare(firstAttackID(a.MitreIDs), firstAttackID(b.MitreIDs)); order != 0 {
				return order
			}
			return cmp.Compare(a.Code, b.Code)
		})
	}
}

func flattenFindings(values []finding) []techniqueRow {
	var rows []techniqueRow
	for index := range values {
		for _, candidate := range values[index].Techniques {
			rows = append(rows, techniqueRow{Finding: &values[index], Technique: candidate})
		}
	}
	return rows
}

func sortTechniqueRows(rows []techniqueRow, mode sortMode) {
	slices.SortStableFunc(rows, func(a, b techniqueRow) int {
		if mode == sortContext {
			if order := cmp.Compare(stateRank(a.Technique.State), stateRank(b.Technique.State)); order != 0 {
				return order
			}
			if order := compareContexts(a.Technique.ContextKey, b.Technique.ContextKey); order != 0 {
				return order
			}
			if order := compareCatalogNames(a.Finding.Name, b.Finding.Name); order != 0 {
				return order
			}
			if order := cmp.Compare(a.Technique.FunctionLabel, b.Technique.FunctionLabel); order != 0 {
				return order
			}
			return cmp.Compare(a.Technique.Code, b.Technique.Code)
		}
		if order := compareAttackIDs(a.Technique.MitreIDs, b.Technique.MitreIDs); order != 0 {
			return order
		}
		if order := compareCatalogNames(a.Finding.Name, b.Finding.Name); order != 0 {
			return order
		}
		if order := compareContexts(a.Technique.ContextKey, b.Technique.ContextKey); order != 0 {
			return order
		}
		return cmp.Compare(a.Technique.FunctionLabel, b.Technique.FunctionLabel)
	})
}

func inlineTerminalText(value string) string {
	value = sanitizeTerminalText(value)
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.ReplaceAll(value, "\t", " ")
}

func printField(label, value string) {
	lines := strings.Split(sanitizeTerminalText(value), "\n")
	fmt.Printf("  %-22s %s\n", label+":", lines[0])
	for _, line := range lines[1:] {
		fmt.Printf("  %-22s %s\n", "", line)
	}
}

func printHeader(report reportData) {
	line := strings.Repeat("=", 64)
	if plainMode {
		fmt.Println(line)
	} else {
		fmt.Printf("%s%s%s\n", colorDim, line, colorReset)
	}
	printField("Effective UID", fmt.Sprint(report.EffectiveUID))
	printField("Effective UID 0", fmt.Sprint(report.EffectiveUID == 0))
	printField("Sort", string(report.Sort))
	printField("All contexts", fmt.Sprint(report.AllContexts))
	printField("Sudo probe", report.SudoProbe)
	printField("Installed binaries", fmt.Sprint(report.InstalledBinaries))
	printField("Displayed techniques", fmt.Sprint(report.DisplayedTechniques))
	printField("Hidden unknown", fmt.Sprint(report.HiddenUnknown))
	printField("Hidden unavailable", fmt.Sprint(report.HiddenUnavailable))
	printField("Catalog warnings", fmt.Sprint(report.CatalogWarnings))
	for _, warning := range report.HostWarnings {
		printField("Host warning", warning)
	}
	if plainMode {
		fmt.Println(line)
	} else {
		fmt.Printf("%s%s%s\n", colorDim, line, colorReset)
	}
	fmt.Println()
}

func stateDisplay(state applicabilityState) string {
	value := inlineTerminalText(string(state))
	if plainMode {
		return value
	}
	switch state {
	case stateConfirmed:
		return colorGreen + value + colorReset
	case statePotential:
		return colorOrange + value + colorReset
	case stateUnknown:
		return colorYellow + value + colorReset
	default:
		return colorDim + value + colorReset
	}
}

func printStateField(state applicabilityState) {
	if plainMode {
		printField("State", string(state))
		return
	}
	fmt.Printf("  %-22s %s\n", "State:", stateDisplay(state))
}

func functionDisplay(value technique) string {
	label := value.FunctionLabel
	if strings.TrimSpace(label) == "" {
		label = value.FunctionKey
	}
	if !strings.EqualFold(strings.TrimSpace(label), strings.TrimSpace(value.FunctionKey)) {
		return label + " (" + value.FunctionKey + ")"
	}
	return label
}

func contextDisplay(value technique) string {
	label := value.ContextLabel
	if strings.TrimSpace(label) == "" {
		label = value.ContextKey
	}
	if !strings.EqualFold(strings.TrimSpace(label), strings.TrimSpace(value.ContextKey)) {
		return label + " (" + value.ContextKey + ")"
	}
	return label
}

func renderFindingHeader(index int, value finding) {
	name := inlineTerminalText(value.Name)
	if plainMode {
		fmt.Printf("[%d] %s\n", index, name)
	} else {
		fmt.Printf("%s%s[%d] %s%s\n", colorCyan, colorBold, index, name, colorReset)
	}
	printField("Invocable path", value.InvocablePath)
	if value.CanonicalPath != "" && value.CanonicalPath != value.InvocablePath {
		printField("Canonical target", value.CanonicalPath)
	}
	if len(value.AliasChain) != 0 {
		printField("Alias chain", strings.Join(value.AliasChain, " -> "))
	}
	if value.Comment != "" {
		printField("Executable comment", value.Comment)
	}
	for _, warning := range value.Warnings {
		printField("Entry warning", warning)
	}
	for _, warning := range value.DiscoveryWarnings {
		printField("Discovery warning", warning)
	}
}

func renderOptionalBool(label string, value *bool) {
	if value != nil {
		printField(label, fmt.Sprint(*value))
	}
}

func renderTechnique(index int, value technique) {
	fmt.Printf("  -- technique %d --\n", index)
	printField("Function", functionDisplay(value))
	printField("Context", contextDisplay(value))
	if value.ContextDescription != "" {
		printField("Context description", value.ContextDescription)
	}
	printStateField(value.State)
	for _, evidence := range value.Evidence {
		printField("Evidence", evidence)
	}
	if ids := sortedAttackIDs(value.MitreIDs); len(ids) != 0 {
		printField("ATT&CK", strings.Join(ids, ", "))
	}
	if value.Description != "" {
		printField("Description", value.Description)
	}
	if value.Code != "" {
		printField("Command", value.Code)
	}
	if value.ExampleComment != "" {
		printField("Example comment", value.ExampleComment)
	}
	if value.ContextComment != "" {
		printField("Context comment", value.ContextComment)
	}
	if value.Version != "" {
		printField("Version restriction", value.Version)
	}
	if value.ContextShell != "" {
		printField("Context shell", value.ContextShell)
	}
	if len(value.ContextList) != 0 {
		printField("Context requirements", strings.Join(value.ContextList, ", "))
	}
	if len(value.InheritanceChain) != 0 {
		printField("Inheritance chain", strings.Join(value.InheritanceChain, " -> "))
	}
	for launcherIndex, launcher := range value.Launchers {
		prefix := fmt.Sprintf("Launcher %d", launcherIndex+1)
		printField(prefix, launcher.Executable+" ["+launcher.ContextKey+"]")
		if launcher.Code != "" {
			printField(prefix+" command", launcher.Code)
		}
		if launcher.ExampleComment != "" {
			printField(prefix+" comment", launcher.ExampleComment)
		}
		if launcher.ContextComment != "" {
			printField(prefix+" context", launcher.ContextComment)
		}
		if launcher.Version != "" {
			printField(prefix+" version", launcher.Version)
		}
		if launcher.ContextShell != "" {
			printField(prefix+" shell", launcher.ContextShell)
		}
		if len(launcher.ContextList) != 0 {
			printField(prefix+" requirements", strings.Join(launcher.ContextList, ", "))
		}
		renderOptionalBool(prefix+" blind", launcher.Blind)
		renderOptionalBool(prefix+" TTY", launcher.TTY)
		renderOptionalBool(prefix+" binary", launcher.Binary)
	}
	for _, companion := range value.Companions {
		label := "Companion " + companion.Role
		if companion.Comment != "" {
			printField(label+" comment", companion.Comment)
		}
		if companion.Code != "" {
			printField(label+" command", companion.Code)
		}
	}
	renderOptionalBool("Blind", value.Blind)
	renderOptionalBool("TTY", value.TTY)
	renderOptionalBool("Binary", value.Binary)
	for _, warning := range value.Warnings {
		printField("Technique warning", warning)
	}
}

func renderReport(report reportData) {
	printHeader(report)
	if report.DisplayedTechniques == 0 {
		fmt.Println("No techniques matched the current display filter.")
		return
	}

	if report.Sort == sortBinary {
		sortBinaryFindings(report.Findings)
		for index, value := range report.Findings {
			if index != 0 {
				fmt.Println()
			}
			renderFindingHeader(index+1, value)
			for techniqueIndex, candidate := range value.Techniques {
				renderTechnique(techniqueIndex+1, candidate)
			}
			fmt.Println(strings.Repeat("-", 64))
		}
		return
	}

	rows := flattenFindings(report.Findings)
	sortTechniqueRows(rows, report.Sort)
	for index, row := range rows {
		if index != 0 {
			fmt.Println()
		}
		renderFindingHeader(index+1, *row.Finding)
		renderTechnique(1, row.Technique)
		fmt.Println(strings.Repeat("-", 64))
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}
