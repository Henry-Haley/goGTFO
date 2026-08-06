# goGTFO Linux / GTFOBins Conversion Plan

## Document purpose

This is the implementation specification for converting goGTFO from its synchronized Windows/LOLBAS and LOLDrivers baseline into a Linux/GTFOBins scanner. It is intended to be handed directly to an implementation agent and followed phase by phase.

The plan is deliberately detailed because it defines the product's truth model, security boundaries, data handling, file layout, implementation order, tests, and release gates. An implementation is not complete merely because it builds or prints GTFOBins entries; it must accurately distinguish what the host confirms from what remains conditional.

## Instructions to the implementation agent

1. Read this entire document and the existing repository before changing code.
2. Preserve unrelated user changes and inspect `git status` before every phase.
3. Execute the phases in order. Do not combine phases if doing so makes an acceptance gate impossible to verify.
4. Mark a phase's checklist items complete only after its verification commands and acceptance gate pass.
5. Keep the implementation Linux-only. Do not create a platform abstraction or preserve Windows behavior unless this plan is explicitly amended.
6. Do not execute any command, payload, listener, sender, receiver, or shell snippet obtained from GTFOBins. Catalog commands are display-only data.
7. Do not invoke a shell with catalog-controlled data. Use Go APIs and direct `exec.CommandContext` argument arrays only for the narrowly defined host checks in this plan.
8. Do not add dependencies unless the standard library and the existing `golang.org/x/sys` dependency cannot do the job. No YAML parser is needed because GTFOBins publishes JSON.
9. Keep the repository buildable and tests passing at the end of every phase that changes Go code.
10. If the live API differs materially from the contract documented here, stop and update this plan before inventing compatibility behavior.
11. Do not silently weaken a security check to make a test pass. Represent uncertainty explicitly.
12. Finish with a Ponytail review focused on deletion, unnecessary abstractions, dependencies, duplicate models, and speculative flags.

## Target outcome

The converted program will:

- Run as a Linux command-line application.
- Fetch the current GTFOBins JSON catalog from `https://gtfobins.org/api.json`.
- Detect catalog executables available through the current process's `PATH`.
- Display documented GTFOBins functions, MITRE ATT&CK mappings, contexts, command examples, remarks, version requirements, and companion commands.
- Assess unprivileged, SUID, Linux file-capability, and sudo contexts without claiming certainty the host cannot prove.
- Preserve the current search, sorting, colored output, and plain-terminal experience where those behaviors remain useful.
- Never execute a GTFOBins technique.
- Remain small: standard library plus the already-present `golang.org/x/sys` module.
- Contain no LOLDrivers endpoint, local driver scan, or `-driver` mode.

## Product truth model

GTFOBins contexts are conditions, not hierarchical roles. A Linux user is not simply equivalent to a Windows standard user, administrator, or SYSTEM account. Each displayed technique must carry one of these states:

| State | Meaning |
|---|---|
| `confirmed` | Every machine-checkable prerequisite for this context was positively observed and no structured version restriction remains unverified. Runtime behavior can still be affected by LSM policy, program configuration, services, environment, or other remarks printed with the technique. |
| `potential` | Positive evidence exists, but it does not prove the complete command line or runtime prerequisites. The main expected use is sudo policy evidence. |
| `unknown` | The program did not check the prerequisite, the check could not safely decide it, or the catalog contains a free-text version restriction. |
| `unavailable` | A required executable, file property, capability, mount property, or other machine-checkable prerequisite is positively absent. |

The program must never convert `unknown` into `confirmed` for convenience. User-facing copy must say "documented technique," "applicable context," or "confirmed prerequisite," not "guaranteed runnable."

## Scope

### Included in the first complete release

- Linux only.
- Live GTFOBins JSON catalog.
- Safe catalog validation and terminal-text sanitization.
- PATH-based executable discovery.
- Alias resolution.
- Inherited-function resolution.
- Context-specific command overrides.
- Companion command resolution for listeners, connectors, senders, and receivers.
- Effective-UID reporting.
- SUID, root ownership, `nosuid`, `noexec`, and `NoNewPrivs` checks.
- Linux file-capability decoding and capability bounding-set checks.
- Optional, non-interactive sudo policy probing.
- Explicit handling of free-text version restrictions.
- Search by catalog executable name.
- Sort by binary, context, or ATT&CK technique.
- Colored and plain output.
- Unit tests using a synthetic catalog fixture.
- Linux CI and reproducible build commands.
- Updated README and disclaimer.

### Explicit non-goals

- Windows, LOLBAS, or LOLDrivers compatibility.
- macOS, BSD, or other Unix support.
- Recursive full-filesystem executable discovery.
- Automatically running `find`, `getcap -r`, package managers, `--version`, or catalog examples.
- Proving that AppArmor, SELinux, seccomp, containers, services, pagers, TTYs, network access, or program-specific configuration permit a technique.
- Parsing `/etc/sudoers` or files under `/etc/sudoers.d` directly.
- Prompting for a sudo password or refreshing sudo credentials.
- Offline catalog caching in the first release.
- Vendoring the full GTFOBins dataset.
- A plugin system, provider interface, catalog interface, dependency-injection framework, or generic cross-platform scanner abstraction.
- A TUI, web UI, JSON output, database, telemetry, or background service.
- Automated release publishing or GoReleaser.

These are not placeholders that require scaffolding. Add them later only when a concrete requirement exists.

## Current repository assessment

The synchronized upstream baseline is a Windows scanner with both LOLBAS and LOLDrivers functionality and no tests.

### Existing code to replace

- The LOLBAS JSON models in `main.go`.
- Windows documented-path translation using `%WINDIR%`, `%ProgramFiles%`, `%USERPROFILE%`, and WindowsApps.
- User/administrator/SYSTEM privilege classification.
- `.exe` suffix normalization.
- Case-insensitive path deduplication.
- LOLBAS-specific help, labels, status messages, and disclaimers.
- The fetch URL and result-building loop.
- LOLDrivers models: `lolDriverSample`, `lolDriverCommand`, `lolDriverEntry`, `localDriver`, and `driverMatch`.
- LOLDrivers catalog fetching in `fetchLOLDriversCatalog` from `https://www.loldrivers.io/api/drivers.json`.
- Local `.sys` discovery and SHA-256 work in `driverSearchRoots`, `hashFileSHA256`, `collectLocalDrivers`, and `findVulnerableDrivers`.
- Loaded-driver inspection in `normalizeDriverName`, `loadedDriverNames`, and `annotateLoadedState`, including the `sc.exe` and `driverquery` child processes.
- Driver-mode orchestration and rendering in `runDriverMode`, `printDriverResults`, `statusDisplay`, `boolDisplay`, `firstNonEmpty`, `firstSampleDescription`, and `firstCommand`.
- The `driverFlag` declaration, `-driver` validation/dispatch, help text, tests, and documentation. The flag will not be retained.

### Existing code to reuse with targeted edits

- Flag parsing structure.
- Banner and loading presentation.
- Plain output mode.
- Color constants.
- General grouped and flat result printing.
- Binary and ATT&CK sorting structure.
- Search flow and no-result flow.

### Existing code and artifacts to delete

- `internal/privileges/privileges_windows.go`
- `internal/privileges/privileges_stub.go`
- `internal/signverify/signverify_windows.go`
- `internal/signverify/signverify_stub.go`
- `internal/mitre/names.go`
- The tracked `goLoL.exe` binary.
- The stale Windows screenshot and its README reference unless a Linux screenshot is produced during documentation work.

`internal/signverify` and `IsElevated` have no callers. They are deletion work, not porting work.

## Fixed design decisions

These decisions should not be revisited during implementation unless evidence makes them impossible:

1. **Retarget instead of dual-platform support.** The command becomes Linux-only.
2. **Use the new repository identity.** The repository and Go module are `github.com/Henry-Haley/goGTFO`; the former decision to retain `github.com/aaron-kidwell/goLoL` no longer applies.
3. **Use Go 1.26.5.** The `go.mod` directive and CI toolchain must both specify Go 1.26.5.
4. **Build the binary as `goGTFO`.** This matches the module name and `go install github.com/Henry-Haley/goGTFO@latest`; remove `.exe` from Linux documentation and build outputs.
5. **Remove LOLDrivers completely.** No LOLDrivers model, endpoint, `.sys` discovery, hash/match logic, loaded-driver inspection, rendering, help, test, documentation, or `-driver` flag survives the conversion.
6. **Use the official JSON API.** Do not scrape HTML and do not parse the source YAML repository.
7. **Fetch live on each run.** Match the original application's always-current behavior; add caching only after a real offline requirement appears.
8. **Use PATH discovery by default.** It is fast, predictable, and matches executables the current shell can invoke.
9. **Do not recursively scan `/`.** Off-PATH SUID/capability discovery is a later opt-in feature, not part of the initial implementation.
10. **Do not automatically inspect program versions.** Version commands are inconsistent and may have side effects. Preserve version text and downgrade applicability to `unknown`.
11. **Do not prompt for sudo.** Optional sudo checks use `sudo -n` and have a global timeout.
12. **Do not parse catalog snippets.** Shell syntax is too varied to safely derive executable arguments or prerequisites.
13. **Do not rewrite alias commands.** Display the official target command and clearly identify the alias chain.
14. **Use no new library for capability inspection.** Use `golang.org/x/sys/unix`, which is already in `go.mod`.
15. **Use a synthetic test fixture.** Do not commit a snapshot of the GPL-licensed live API.
16. **Unknown API fields remain forward-compatible.** Decode required fields and ignore unknown fields; do not use `DisallowUnknownFields`.

### Build and installation identity

```bash
go install github.com/Henry-Haley/goGTFO@latest
git clone https://github.com/Henry-Haley/goGTFO.git
cd goGTFO
go build -o goGTFO .
```

## Official data sources

- JSON catalog: `https://gtfobins.org/api.json`
- Project site: `https://gtfobins.org/`
- Source and schema documentation: `https://github.com/GTFOBins/GTFOBins.github.io`
- Contribution/schema guide: `https://github.com/GTFOBins/GTFOBins.github.io/blob/master/CONTRIBUTING.md`
- Linux capability semantics: `https://man7.org/linux/man-pages/man7/capabilities.7.html`

At the time this plan was written, the API exposed 478 executables and 822 examples. Those counts are observations, not validation constants. The program must not fail merely because the catalog grows.

## GTFOBins API contract

### Top-level document

The JSON object contains:

- `functions`: map from function key to shared function metadata.
- `contexts`: map from context key to shared context metadata.
- `executables`: map from executable/catalog name to its entry.

All three maps must exist and be non-empty. A missing or empty top-level map is a fatal catalog error.

### Function metadata

Required or useful fields:

- `label`: display label such as `Shell` or `File read`.
- `description`: shared description.
- `mitre`: zero or more ATT&CK IDs.
- `extra`: function-specific shared companion definitions and explanatory data.

Known function keys currently include:

- `shell`
- `command`
- `reverse-shell`
- `bind-shell`
- `file-write`
- `file-read`
- `upload`
- `download`
- `library-load`
- `privilege-escalation`
- `inherit`

Unknown future function keys should still be displayed using the key as a fallback label.

### Context metadata

Required or useful fields:

- `label`
- `description`
- `extra`

Known context keys are:

- `unprivileged`
- `sudo`
- `suid`
- `capabilities`

Unknown future contexts must be retained and shown as `unknown`; they must not be silently treated as unprivileged.

### Executable entry

An executable entry is one of:

- An alias entry with `alias` naming another executable.
- A concrete entry with optional `comment` and a `functions` map.

The map key is the catalog name used for discovery. Catalog names are case-sensitive; for example, an uppercase name must be passed to `exec.LookPath` exactly as published.

Validate every catalog name before path lookup:

- It must not be empty.
- It must not contain NUL.
- It must not contain `/`.
- It must not equal `.` or `..`.

Do not over-restrict names to a guessed regular expression; future legitimate executable names may contain punctuation.

### Function examples

Each function maps to a list of examples. Relevant fields include:

- `code`
- `comment`
- `version`
- `contexts`
- `from` for inheritance
- `blind`
- `tty`
- `binary`
- `listener`
- `connector`
- `sender`
- `receiver`

`contexts` maps context keys to either:

- `null`, meaning the example's top-level code and metadata apply; or
- an object with context-specific overrides such as `code`, `comment`, `shell`, and `list`.

Context-specific `code` replaces top-level `code`; it does not append to it. Context-specific comments should be displayed in addition to the example comment when both exist.

### Companion definitions

Fields such as `listener`, `connector`, `sender`, and `receiver` may be:

- A string key referencing shared metadata under the current function's `extra` object; or
- An inline object containing `comment` and optional `code`.

Resolve both forms. An unresolved reference is a catalog warning attached to that technique, not a reason to execute or synthesize a command.

### Aliases

Alias resolution rules:

1. Discovery uses the alias name, not the target name.
2. Function data comes from the final concrete target.
3. The finding retains the original detected catalog name and path.
4. Output displays the alias chain, for example `c89 -> gcc`.
5. Official command text is not automatically rewritten from the target name to the alias name.
6. Resolve recursively with a visited-name set.
7. A cycle is a catalog error for the affected entry.
8. A missing target is a catalog error for the affected entry.
9. One invalid alias should be reported and skipped without discarding unrelated valid entries.

### Inherited functions

Inheritance is not the same as an alias. An executable may invoke another program or embedded interface and thereby inherit that program's functions.

Resolution rules:

1. Preserve and display the inheritance launcher code from the `inherit` example.
2. Resolve the `from` executable recursively.
3. Display the inherited target function, target command, context, and ATT&CK IDs.
4. Retain the chain, for example `apt -> less -> shell`.
5. Do not concatenate launcher and target snippets into a new shell command.
6. A context is applicable only if the launcher example and inherited target example both support it.
7. The final applicability state is the least certain state in the chain.
8. Carry all comments and version restrictions from both sides of the chain.
9. Detect cycles with a visited pair of executable and function.
10. Deduplicate identical resolved techniques by catalog name, function, context, code, and inheritance chain.

## Target internal model

Keep all Go files in `package main`. There is no need for an interface or internal package boundary for a single command.

The names below are guidance; exact field ordering is unimportant. Preserve the separation between remote catalog data and normalized findings.

```go
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
    Alias     string                       `json:"alias"`
    Comment   string                       `json:"comment"`
    Functions map[string][]exampleDef      `json:"functions"`
}

type exampleDef struct {
    Code       string                     `json:"code"`
    Comment    string                     `json:"comment"`
    Version    string                     `json:"version"`
    From       string                     `json:"from"`
    Contexts   map[string]json.RawMessage `json:"contexts"`
    Blind      *bool                      `json:"blind"`
    TTY        *bool                      `json:"tty"`
    Binary     *bool                      `json:"binary"`
    Listener   json.RawMessage            `json:"listener"`
    Connector  json.RawMessage            `json:"connector"`
    Sender     json.RawMessage            `json:"sender"`
    Receiver   json.RawMessage            `json:"receiver"`
}
```

Use `json.RawMessage` for polymorphic or context-specific fields and decode them in small helper functions. Do not create a general tagged-union framework.

Normalize remote data into output-oriented findings:

```go
type applicabilityState string

const (
    stateConfirmed   applicabilityState = "confirmed"
    statePotential   applicabilityState = "potential"
    stateUnknown     applicabilityState = "unknown"
    stateUnavailable applicabilityState = "unavailable"
)

type finding struct {
    Name       string
    Path       string
    Canonical  string
    AliasChain []string
    Comment    string
    Techniques []technique
    Warnings   []string
}

type technique struct {
    FunctionKey   string
    FunctionLabel string
    Description   string
    MitreIDs      []string
    ContextKey    string
    ContextLabel  string
    Code          string
    Comments      []string
    Version       string
    Companion     *companionCommand
    InheritedFrom []string
    State         applicabilityState
    Evidence      []string
}
```

Do not store ANSI escape sequences inside normalized data. Apply color only during rendering.

## Catalog fetch and trust-boundary requirements

The live catalog is remote, untrusted input even though it comes from the official project.

Implement a dedicated fetch function with these rules:

1. Use an `http.Client` with a 15-second overall timeout.
2. Use a constant HTTPS URL.
3. Require HTTP 200.
4. Limit the response body to 5 MiB plus one byte using `io.LimitReader`.
5. Reject a body larger than 5 MiB with a clear error.
6. Decode one JSON value and reject trailing non-whitespace JSON values.
7. Validate required top-level maps.
8. Validate executable names before lookup.
9. Collect entry-level alias/inheritance warnings without hiding unrelated entries.
10. Never interpolate catalog data into a shell, URL, file path, or child-process command.

Do not require an exact `Content-Type`; static hosting and proxies may vary it.

### Terminal control-character sanitization

Every catalog-controlled string must be sanitized before terminal output. This includes names, labels, descriptions, comments, version text, code, MITRE IDs, and companion text.

Sanitization must:

- Preserve printable Unicode.
- Preserve newline and tab where they are useful for command formatting.
- Remove or visibly replace ESC, C0 control characters other than newline/tab, and DEL.
- Prevent the catalog from injecting ANSI control sequences into either colored or plain output.
- Leave locally generated ANSI color sequences untouched because color is applied after sanitization.

Add direct tests containing `\x1b[2J`, carriage returns, backspaces, and DEL.

## Linux executable discovery

### Default discovery algorithm

For each valid catalog name:

1. Call `exec.LookPath(name)` using the exact catalog key.
2. Ignore `exec.ErrDot`; do not accept an executable found only through a relative current-directory PATH entry.
3. Record the absolute path returned by `LookPath`.
4. Resolve symlinks with `filepath.EvalSymlinks` for security-property checks.
5. Preserve the user-invocable path separately for display.
6. `os.Stat` the canonical target and confirm it is a regular executable file.
7. Query filesystem flags with `unix.Statfs`.
8. If the mount is `noexec`, mark the executable unavailable and explain why.

Do not lowercase catalog names or paths. Do not strip `.exe`. Do not deduplicate different catalog names merely because they resolve to the same canonical target; aliases and multi-call binaries may intentionally share a file.

### Search behavior

Search lookup order:

1. Exact catalog-key match.
2. Case-insensitive catalog-key match when it produces exactly one result.
3. If multiple case-insensitive matches exist, report ambiguity and list them.
4. Accept a query with a directory prefix by applying `filepath.Base` first.
5. Do not add or remove suffixes.

Search mode must distinguish:

- No such catalog entry.
- Catalog entry exists but the executable is not in PATH.
- Executable exists but no context is confirmed.

Unlike the default listing, search mode should show all documented contexts and their states so that the user can see why a context is unavailable or unknown.

## Linux host evidence

Create a small host snapshot once per run. Do not repeatedly read process-wide state for each binary.

The snapshot should include:

- Real UID from `os.Getuid()`.
- Effective UID from `os.Geteuid()`.
- `NoNewPrivs` from `/proc/self/status`.
- Capability bounding set (`CapBnd`) from `/proc/self/status`.
- Whether `sudo` is present in PATH.
- Whether sudo probing was requested.

Report `effective UID 0`, not "host root," because UID 0 may be inside a user namespace or container.

### `/proc/self/status` parsing

Parse the file line by line and recognize:

- `NoNewPrivs:` as decimal `0` or `1`.
- `CapBnd:` as a hexadecimal capability mask.

If `/proc` is unavailable or a field is missing:

- Continue scanning.
- Record the affected prerequisite as unknown.
- Do not assume `NoNewPrivs=0` or an unlimited bounding set.

The parser should be a pure function over `io.Reader` so it can be unit tested.

## Context evaluation

### Unprivileged

An unprivileged context is `confirmed` when:

- The executable was found and is executable.
- Its filesystem is not mounted `noexec`.
- The example has no free-text version restriction.

If `version` is non-empty, the state is `unknown`, with evidence stating that the installed version was not executed or verified.

### SUID

Evaluate the canonical target, not the symlink.

The SUID context is `confirmed` only when all of these are true:

- The target is a regular file.
- The target owner UID is 0.
- `os.FileMode` contains `os.ModeSetuid`.
- The filesystem is not mounted `nosuid`.
- The filesystem is not mounted `noexec`.
- `NoNewPrivs` is known to be 0.
- The example has no free-text version restriction.

Outcomes:

- Missing root ownership or setuid bit: `unavailable`.
- `nosuid`, `noexec`, or `NoNewPrivs=1`: `unavailable` with explicit evidence.
- Failed ownership, mount, or `NoNewPrivs` inspection: `unknown`.
- Non-empty version restriction: `unknown` even when file properties match.

Display the GTFOBins `shell` context remark when provided. Do not try to identify whether `/bin/sh` drops privileges for a particular distribution.

### Linux file capabilities

Read the canonical target's `security.capability` extended attribute with `unix.Getxattr`.

Requirements:

1. Support Linux VFS capability revisions 2 and 3.
2. Decode `magic_etc`, permitted masks, inheritable masks, the effective flag, and revision-3 root ID using `encoding/binary` little-endian reads.
3. Reject truncated or unknown formats as `unknown`, not `unavailable`.
4. Normalize catalog capability names case-insensitively to canonical `CAP_*` names.
5. Maintain a direct map from Linux capability names through the current kernel-defined range to numeric bit positions. Use `x/sys/unix` constants where available.
6. If GTFOBins introduces a capability name the program does not know, mark the context `unknown` and print the name.
7. Treat an empty or missing required `list` for a capabilities context as `unknown`; do not interpret it as "any capability."

A capabilities context is `confirmed` only when:

- Every required capability is present in the file's permitted set.
- The file capability effective flag is set when the technique requires privileges after exec.
- Every required capability is present in the current process capability bounding set.
- The filesystem is neither `nosuid` nor `noexec`.
- `NoNewPrivs=0`.
- No free-text version restriction exists.

Missing required bits, `nosuid`, `noexec`, an excluding bounding set, or `NoNewPrivs=1` makes the context `unavailable`. Failed inspection or an unsupported xattr format makes it `unknown`.

Implement capability-byte decoding and context evaluation as pure functions so unit tests do not require privileged files or `setcap`.

### Sudo

Sudo is the least statically knowable context. Do not parse sudoers files and do not claim that an allowed executable path proves the complete GTFOBins command line is allowed.

Default behavior without `-check-sudo`:

- `sudo` absent from PATH: `unavailable`.
- Effective UID 0: privilege prerequisite `confirmed`, with a note that sudo may be unnecessary; retain any version restriction.
- Non-root and sudo present: `unknown`, with instructions to use `-check-sudo`.

Behavior with `-check-sudo`:

1. Never prompt. Use `sudo -n -l <canonical-path>` through `exec.CommandContext` without a shell.
2. Cache the result by canonical path; do not probe once per technique.
3. Run probes sequentially.
4. Apply a 20-second global budget to all sudo probes.
5. Stop probing when the budget expires and leave remaining results `unknown`.
6. Exit status 0 provides `potential` evidence that sudo policy recognizes the path.
7. Any nonzero exit remains `unknown`; it may mean a password is required, permission is denied, policy is unavailable, or another error occurred.
8. Never classify a sudo technique as `confirmed` solely from a path probe because sudoers may restrict arguments and GTFOBins snippets may contain pipelines, environment variables, or nested commands.
9. Tell the user that sudo policy checks may be logged by the host.

Do not parse or execute GTFOBins code to construct sudo probe arguments.

### Unknown future contexts

An unknown context is always `unknown`. Display its catalog label/description if available and explain that this application version has no evaluator for it.

## Technique filtering

### Default listing

Show:

- `confirmed` techniques.
- `potential` techniques.

Hide `unknown` and `unavailable` rows from the main listing, but print a summary count and direct the user to `-all` or `-s <name>`.

### `-all`

Show every documented context for executables found in PATH, including `unknown` and `unavailable`, with evidence.

### Search mode

Search implies full context detail for the selected catalog entry, equivalent to `-all` for that entry.

### Version-restricted examples

A non-empty `version` field caps the final state at `unknown`. Always display the exact sanitized version text in `-all` and search modes.

### Overall state composition

When alias, inheritance, context, mount, version, or companion requirements combine, use the least certain result:

1. Any positively failed mandatory prerequisite yields `unavailable`.
2. Otherwise, any uninspected or undecidable mandatory prerequisite yields `unknown`.
3. Otherwise, sudo path-only evidence yields `potential`.
4. Only fully checked structured prerequisites yield `confirmed`.

Keep this logic in one pure function and test it as a table. Do not scatter state promotion/demotion rules through rendering code.

## CLI contract

Retain familiar flags and introduce only the two necessary inspection flags.

| Flag | Behavior |
|---|---|
| `-h`, `-help` | Show help and exit 0. |
| `-plain` | ASCII-only output with no color, Unicode borders, or cursor control. |
| `-s`, `-search <name>` | Show one catalog executable and every context state. |
| `-sort <mode>` | Sort by `binary`, `context`, or `attack`. |
| `-all` | Include unknown and unavailable contexts for installed executables. |
| `-check-sudo` | Run optional, non-interactive, time-bounded sudo policy probes. |

Sort aliases:

- `b` for `binary`
- `c`, `ctx`, and the old `privilege` alias for `context`
- `a` and `mitre` for `attack`

Keep `privilege` only as a compatibility alias; help text should advertise `context`.

Do not add URL, cache, output-format, deep-scan, concurrency, or config-file flags in the first release.

### Exit behavior

- Successful listing, including a listing with zero confirmed results: exit 0.
- Help: exit 0.
- Invalid flags or sort mode: exit 2.
- Catalog fetch/parse/validation failure: exit 1.
- Search name absent from the catalog: exit 1.
- Search name present but not found in PATH: exit 1 after printing that distinction.

## Output contract

### Header

Display:

- Effective UID.
- Whether effective UID is 0.
- Sort mode.
- Whether all contexts are shown.
- Sudo probe status: not requested, completed, partial timeout, or unavailable.
- Installed catalog executable count.
- Displayed technique count.
- Hidden unknown count.
- Hidden unavailable count.
- Catalog warnings count.

### Per-executable fields

- Catalog name.
- Invocable path.
- Canonical target when different.
- Alias chain when present.
- Executable comment when present.
- Entry warnings when present.

### Per-technique fields

- Function label and key when the label differs materially.
- Context label.
- Applicability state.
- Evidence explaining the state.
- ATT&CK IDs.
- Shared function description.
- Use command/example code.
- Example comment.
- Context-specific comment.
- Version restriction.
- Inheritance chain and launcher commands.
- Companion comment and command.
- `blind`, `tty`, or binary-data limitations when explicitly supplied.

### Rendering rules

- Render normalized plain data; add color at the final print boundary.
- Use stable colors for states rather than treating contexts as privilege tiers.
- Suggested colors: green confirmed, orange potential, yellow unknown, dim unavailable.
- Plain mode must replace Unicode symbols and borders with ASCII.
- Multiline commands must remain readable and indented consistently.
- Never truncate command code. Loader text may still be truncated to its fixed display width.
- Sort all map-derived data before printing.

### Deterministic sorting

Binary mode:

1. Catalog name, case-insensitive.
2. Catalog name, case-sensitive tie-breaker.
3. Context rank.
4. Function label.
5. First ATT&CK ID.
6. Command text.

Context mode:

1. State rank: confirmed, potential, unknown, unavailable.
2. Context rank: sudo, suid, capabilities, unprivileged, unknown contexts alphabetically.
3. Catalog name.
4. Function label.
5. Command text.

ATT&CK mode:

1. First ATT&CK ID; empty IDs last.
2. Remaining ATT&CK ID list.
3. Catalog name.
4. Context rank.
5. Function label.

Do not duplicate a multi-MITRE technique into multiple output rows. Display all IDs on the row and use the first sorted ID as its primary sort key.

## Target repository layout

Keep the layout intentionally small:

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml
├── testdata/
│   └── catalog.json
├── catalog.go
├── go.mod
├── go.sum
├── main.go
├── main_test.go
├── plan.md
├── README.md
└── scan_linux.go
```

Responsibilities:

- `main.go`: build tag, flags, orchestration, normalized output rendering, sorting, help, and banner.
- `catalog.go`: remote JSON models, fetch, validation, sanitization, alias resolution, inheritance resolution, companion resolution, and normalized technique construction.
- `scan_linux.go`: Linux host snapshot, PATH discovery, file/mount inspection, capability decoding, context evaluation, and optional sudo probing.
- `main_test.go`: unit and small integration-style tests for all pure logic and `httptest` catalog fetching.
- `testdata/catalog.json`: small synthetic fixture covering every structural edge case without copying GTFOBins payloads.

Do not split output, flags, models, and helpers into additional packages unless the resulting files become unreasonably difficult to navigate during implementation.

## Implementation phases

## Phase 0: Establish the baseline and toolchain

### Tasks

- [ ] Run `git status --short --branch` and record any pre-existing changes.
- [ ] Run `where.exe go` and `go version`; record the selected executable path and confirm it reports exactly `go version go1.26.5 windows/amd64` for this Phase 0 baseline.
- [ ] Run the committed Windows executable with `-plain -h` only to capture the current CLI reference if needed.
- [ ] Record that the current source has no runnable tests.
- [ ] Confirm the current official API responds and inspect its top-level keys without committing the response.
- [ ] Do not install tools or change system configuration merely to satisfy this phase; report a missing Go toolchain as a blocker.

### Verification

```bash
go version
git status --short --branch
curl -fsSL https://gtfobins.org/api.json | head -c 80
```

### Acceptance gate

- The implementation environment uses Go 1.26.5, matching `go.mod` exactly.
- Repository changes are understood before edits begin.
- No live GTFOBins data has been committed.
- No command obtained from GTFOBins has been executed.

## Phase 1: Remove Windows-only and dead code

### Tasks

- [ ] Add `//go:build linux` to the command source so the Linux-only target is explicit.
- [ ] Remove `runtime`, `syscall`, and `unsafe` imports used only for Windows console handling.
- [ ] Delete `enableVirtualTerminal` and its call sites.
- [ ] Delete the unused `internal/signverify` directory.
- [ ] Temporarily retain `internal/privileges` and `internal/mitre` because the existing orchestration still calls them; delete them atomically when Phase 8 replaces those callers.
- [ ] Delete the LOLDrivers models `lolDriverSample`, `lolDriverCommand`, `lolDriverEntry`, `localDriver`, and `driverMatch`.
- [ ] Delete `fetchLOLDriversCatalog` and the `https://www.loldrivers.io/api/drivers.json` endpoint.
- [ ] Delete `.sys` discovery and hashing through `driverSearchRoots`, `hashFileSHA256`, `collectLocalDrivers`, and `findVulnerableDrivers`, then remove the now-unused `crypto/sha256` import.
- [ ] Delete loaded-driver inspection through `normalizeDriverName`, `loadedDriverNames`, and `annotateLoadedState`, including every `sc.exe` and `driverquery` child-process path.
- [ ] Delete `runDriverMode`, `printDriverResults`, `statusDisplay`, `boolDisplay`, `firstNonEmpty`, `firstSampleDescription`, and `firstCommand` when they have no non-driver callers.
- [ ] Delete `driverFlag`, `-driver` validation and dispatch, and all `-driver` help text. Do not replace the flag.
- [ ] Delete the tracked `goLoL.exe`.
- [ ] Add `/goGTFO` and `/goGTFO.exe` to `.gitignore`.
- [ ] Remove the stale screenshot or leave it only until the README phase if temporary broken documentation would hinder review.
- [ ] Confirm the module path remains `github.com/Henry-Haley/goGTFO`; no `github.com/aaron-kidwell/goLoL` source import may remain.
- [ ] Keep `golang.org/x/sys`; it will be used through `x/sys/unix`.

### Verification

```bash
gofmt -w .
go test ./...
go vet ./...
go build -o goGTFO .
```

### Acceptance gate

- Windows console symbols no longer prevent Linux compilation.
- Linux compilation succeeds through the existing non-Windows privilege stub, even though the old LOLBAS behavior is still temporarily present and must not be treated as functional Linux output.
- No LOLDrivers endpoint, model, `.sys` scan, hash/match path, loaded-driver inspection, driver renderer, or `-driver` flag remains.
- No caller is left referencing a package deleted in this phase.

## Phase 2: Add the synthetic catalog fixture and remote models

### Fixture requirements

Create `testdata/catalog.json` with invented executable names and harmless placeholder commands. It must include:

- [ ] One normal executable with unprivileged, sudo, SUID, and capabilities contexts.
- [ ] One alias.
- [ ] One two-hop alias.
- [ ] One inheritance example.
- [ ] One two-hop inheritance chain.
- [ ] One context with `null` metadata.
- [ ] One context-specific code override.
- [ ] One context-specific comment.
- [ ] One capability list.
- [ ] One version-restricted example.
- [ ] One function with multiple MITRE IDs.
- [ ] One string companion reference.
- [ ] One inline companion object.
- [ ] One unknown function.
- [ ] One unknown context.
- [ ] One executable-level comment.
- [ ] Explicit `blind`, `tty`, and `binary` values.

Do not use real GTFOBins commands in the fixture.

### Code tasks

- [ ] Add remote catalog structs in `catalog.go`.
- [ ] Decode the synthetic fixture.
- [ ] Validate required top-level maps.
- [ ] Validate executable names.
- [ ] Add helper decoding for null/object contexts.
- [ ] Add helper decoding for string/object companion definitions.
- [ ] Preserve unknown fields by ignoring them.
- [ ] Add tests for successful decode and structural failures.

### Verification

```bash
gofmt -w .
go test ./...
go vet ./...
```

### Acceptance gate

- Every documented API shape can be represented without `map[string]any` spreading through the program.
- The synthetic fixture exercises all polymorphic fields.
- Malformed required structure produces useful errors.

## Phase 3: Implement secure live catalog fetching

### Tasks

- [ ] Add the fixed catalog URL constant.
- [ ] Add a 15-second `http.Client` timeout.
- [ ] Require status 200.
- [ ] Enforce the 5 MiB body limit.
- [ ] Reject trailing JSON values.
- [ ] Validate the decoded catalog.
- [ ] Return errors to the caller; do not print inside the fetch function.
- [ ] Add `httptest.Server` tests for success, non-200, oversized body, invalid JSON, trailing JSON, and missing maps.
- [ ] Add terminal text sanitization and direct control-character tests.

### Verification

```bash
go test ./...
go vet ./...
```

### Acceptance gate

- Remote data is bounded, validated, sanitized at output, and never executed.
- Tests do not depend on the live network.

## Phase 4: Implement alias, companion, and inheritance resolution

### Tasks

- [ ] Resolve aliases recursively while preserving the detected alias name.
- [ ] Detect alias cycles and missing targets.
- [ ] Resolve string and inline companion definitions.
- [ ] Resolve inherited functions recursively.
- [ ] Intersect launcher and target contexts.
- [ ] Preserve launcher code separately from target code.
- [ ] Carry comments, versions, ATT&CK IDs, and inheritance chains.
- [ ] Detect inheritance cycles.
- [ ] Deduplicate normalized techniques deterministically.
- [ ] Treat one invalid entry as a warning/skip for that entry rather than a total catalog failure.
- [ ] Add table tests for every resolution rule.

### Verification

```bash
go test ./...
go vet ./...
```

### Acceptance gate

- Aliases and inheritance produce stable normalized techniques.
- No official command text is synthesized or rewritten.
- Cycles cannot recurse indefinitely.

## Phase 5: Implement Linux discovery and host snapshot

### Tasks

- [ ] Add `scan_linux.go` using `golang.org/x/sys/unix`.
- [ ] Capture real and effective UID once.
- [ ] Parse `NoNewPrivs` and `CapBnd` from `/proc/self/status` once.
- [ ] Find each exact catalog name with `exec.LookPath`.
- [ ] Reject `exec.ErrDot` results.
- [ ] Resolve symlinks for security checks.
- [ ] Preserve invocable and canonical paths.
- [ ] Stat the canonical target.
- [ ] Read `Statfs` flags for `noexec` and `nosuid`.
- [ ] Keep distinct catalog names even when canonical paths match.
- [ ] Implement exact and unambiguous case-insensitive search.
- [ ] Add tests for the pure `/proc` parser, name search, path-result normalization, and mount-flag evaluation.

### Verification

```bash
go test ./...
go vet ./...
go build -o goGTFO .
```

### Acceptance gate

- A Linux build can identify installed fixture-selected command names without recursive filesystem scanning.
- Case sensitivity and symlink behavior are explicit and tested.
- `noexec` is not ignored.

## Phase 6: Implement SUID and capability evaluation

### Tasks

- [ ] Add a pure SUID predicate over mode, owner UID, mount flags, and process state.
- [ ] Decode capability xattr revisions 2 and 3.
- [ ] Add the Linux capability-name-to-bit map.
- [ ] Parse required capability lists from context overrides.
- [ ] Compare file permitted/effective bits with required bits.
- [ ] Compare required bits with `CapBnd`.
- [ ] Apply `nosuid`, `noexec`, and `NoNewPrivs` rules.
- [ ] Return evidence strings with each decision.
- [ ] Mark unknown formats and unknown capability names as unknown.
- [ ] Add byte-fixture tests for valid revision 2, valid revision 3, truncated data, unknown revision, missing required bits, bounding-set exclusion, and effective-flag absence.
- [ ] Add a complete state-composition table test.

### Verification

```bash
go test ./...
go vet ./...
```

### Acceptance gate

- SUID and capability tests require no root privileges or host mutation.
- Every negative or unknown decision explains itself.
- `nosuid`, `noexec`, bounding sets, and `NoNewPrivs` affect results correctly.

## Phase 7: Implement optional sudo probing

### Tasks

- [ ] Add `-check-sudo` flag plumbing without changing default no-prompt behavior.
- [ ] Locate sudo with `exec.LookPath`.
- [ ] Cache one result per canonical path.
- [ ] Invoke `sudo -n -l <canonical-path>` with `exec.CommandContext`, never a shell.
- [ ] Apply the 20-second global budget.
- [ ] Stop cleanly on budget exhaustion.
- [ ] Classify exit 0 as potential, not confirmed.
- [ ] Classify all nonzero outcomes as unknown without brittle stderr parsing.
- [ ] State in help/output that probes may be logged.
- [ ] Test the classification and caching through an injected command-runner function, not by invoking the developer's real sudo policy.

The injected runner should be a function field or function parameter, not a general command-execution interface.

### Verification

```bash
go test ./...
go vet ./...
```

### Acceptance gate

- Tests never touch real sudo.
- Default runs never prompt or probe.
- Sudo path evidence is never overstated as proof that a GTFOBins snippet is allowed.

## Phase 8: Replace the LOLBAS orchestration and output model

### Tasks

- [ ] Remove all remaining LOLBAS structs, terminology, path logic, and privilege functions.
- [ ] Delete `internal/privileges` after its final callers are removed.
- [ ] Delete `internal/mitre` after ATT&CK IDs and labels come from normalized GTFOBins function metadata.
- [ ] Parse flags before network work.
- [ ] Fetch and validate the catalog.
- [ ] Capture host state.
- [ ] Resolve installed executable entries.
- [ ] Normalize alias/inheritance/function/context examples.
- [ ] Evaluate applicability.
- [ ] Filter according to default, `-all`, and search rules.
- [ ] Implement deterministic sorting.
- [ ] Adapt the existing grouped and flat renderers to the new fields.
- [ ] Apply color at render time only.
- [ ] Preserve plain output behavior.
- [ ] Indent multiline commands without truncating them.
- [ ] Add header and hidden-state summaries.
- [ ] Update loader messages to say GTFOBins and Linux context checks.
- [ ] Ensure no output path lowercasing occurs.
- [ ] Add a plain-output golden test using the synthetic fixture and a fake host snapshot.

### Verification

```bash
gofmt -w .
go test ./...
go vet ./...
go build -trimpath -ldflags="-s -w" -o goGTFO .
./goGTFO -plain -h
```

### Acceptance gate

- No LOLBAS or Windows privilege terminology remains in runtime output.
- Output is deterministic under the synthetic fixture.
- Commands are displayed exactly after sanitization and indentation, never executed.

## Phase 9: Complete CLI behavior and error handling

### Tasks

- [ ] Implement all documented flags and aliases.
- [ ] Implement documented exit codes.
- [ ] Distinguish catalog-missing from PATH-missing search results.
- [ ] Show all contexts in search mode.
- [ ] Validate sort mode before fetching the network catalog.
- [ ] Print operational errors to stderr.
- [ ] Avoid partial colored loader artifacts after a failure.
- [ ] Ensure `-plain` contains no ESC bytes or Unicode borders.
- [ ] Test invalid sort, exact search, case-insensitive search, ambiguity, absent catalog name, absent PATH binary, `-all`, hidden-state summaries, and rejection of the removed `-driver` flag.

### Verification

```bash
go test ./...
go vet ./...
./goGTFO -plain -h
```

### Acceptance gate

- CLI behavior matches this plan.
- Flag errors require no network access.
- Plain output is safe for basic reverse shells and log capture.

## Phase 10: Documentation, CI, and cleanup

### README tasks

- [ ] Rewrite the summary for Linux and GTFOBins.
- [ ] Explain the four applicability states.
- [ ] Explain that GTFOBins entries are not vulnerabilities and commands are never executed by the scanner.
- [ ] Document PATH-only discovery and its limitations.
- [ ] Document `nosuid`, `noexec`, `NoNewPrivs`, and capability bounding-set handling.
- [ ] Explain why sudo remains potential/unknown.
- [ ] Document every flag and exit behavior.
- [ ] Provide build and install examples using `github.com/Henry-Haley/goGTFO`, the `goGTFO` repository directory, and the `goGTFO` binary.
- [ ] Attribute GTFOBins and link its project and source.
- [ ] Note that live network access is required.
- [ ] Remove Windows installation, `.exe`, SYSTEM, Administrators, LOLBAS, LOLDrivers, `.sys`, and `-driver` examples, including the old LOLDrivers endpoint and local-driver-scan descriptions.
- [ ] Remove the stale screenshot; add a Linux screenshot only if it can be generated from harmless output.
- [ ] Preserve the authorized-use disclaimer.

### CI tasks

Add one small GitHub Actions workflow that:

- [ ] Uses Go 1.26.5 exactly, matching `go.mod`.
- [ ] Runs `go test ./...`.
- [ ] Runs `go vet ./...`.
- [ ] Builds Linux amd64.
- [ ] Cross-builds Linux arm64.
- [ ] Does not call the live GTFOBins API.
- [ ] Does not add third-party lint or release actions beyond official checkout/setup-go actions.

### Cleanup tasks

- [ ] Run `rg -n -i 'lolbas|loldriver|windows|administrator|system32|\.exe|\.sys|windir|programfiles|wintrust|authenticode|driverquery|sc\.exe'` and inspect every remaining match.
- [ ] Run `rg -n --glob '!plan.md' 'github\.com/aaron-kidwell/goLoL|aaron-kidwell/goLoL'` and require no matches outside this historical specification.
- [ ] Run `rg -n 'os/exec|exec\.Command|CommandContext'` and confirm every child process is the planned non-interactive sudo probe or test fake.
- [ ] Confirm no remote code path reaches command execution.
- [ ] Confirm `.gitignore` covers local binaries.
- [ ] Confirm `git status` contains only intended changes.
- [ ] Perform the Ponytail review and remove unnecessary abstractions, flags, duplicate helpers, and dependencies.

### Verification

```bash
gofmt -w .
go test ./...
go vet ./...
GOOS=linux GOARCH=amd64 go build -trimpath -o goGTFO-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -trimpath -o goGTFO-linux-arm64 .
git diff --check
git status --short
```

### Acceptance gate

- CI passes without live network access.
- Documentation describes actual behavior and limitations.
- No stale Windows, LOLBAS, or LOLDrivers implementation, documentation, endpoint, local scan, flag, or build artifact remains.
- The final diff contains no speculative framework.

## Required test matrix

### Catalog and trust boundary

- [ ] Valid synthetic catalog.
- [ ] Missing top-level maps.
- [ ] Empty top-level maps.
- [ ] Invalid JSON.
- [ ] Trailing second JSON value.
- [ ] Non-200 HTTP response.
- [ ] Oversized response.
- [ ] Empty, slash-containing, dot, dot-dot, and NUL-containing executable names.
- [ ] Unknown fields tolerated.
- [ ] Unknown functions retained.
- [ ] Unknown contexts retained as unknown.
- [ ] Terminal escape/control characters neutralized.

### Resolution

- [ ] Direct entry.
- [ ] One-hop alias.
- [ ] Multi-hop alias.
- [ ] Alias cycle.
- [ ] Missing alias target.
- [ ] One-hop inheritance.
- [ ] Multi-hop inheritance.
- [ ] Inheritance cycle.
- [ ] Context intersection.
- [ ] Context-specific command replacement.
- [ ] String companion lookup.
- [ ] Inline companion object.
- [ ] Missing companion reference warning.
- [ ] Technique deduplication.

### Linux state

- [ ] UID and EUID reporting.
- [ ] Valid and missing `/proc/self/status` fields.
- [ ] `NoNewPrivs` 0 and 1.
- [ ] Capability bounding-set parsing.
- [ ] `noexec` executable path.
- [ ] `nosuid` SUID/capability path.
- [ ] Root-owned SUID file.
- [ ] Non-root-owned setuid file.
- [ ] Root-owned file without setuid.
- [ ] Capability xattr revisions 2 and 3.
- [ ] Truncated/unknown capability xattr.
- [ ] Missing required file capability.
- [ ] Required capability outside bounding set.
- [ ] Unknown capability name.
- [ ] Empty capability requirement list.

### Applicability

- [ ] Confirmed unprivileged.
- [ ] Version-restricted unprivileged becomes unknown.
- [ ] Confirmed SUID.
- [ ] Confirmed capabilities.
- [ ] Unchecked sudo unknown.
- [ ] Successful sudo path probe potential.
- [ ] Failed sudo path probe unknown.
- [ ] Effective UID 0 behavior.
- [ ] Least-certain inherited state wins.
- [ ] Mandatory failure wins over unknown.

### CLI and output

- [ ] Help performs no network work.
- [ ] Invalid flags perform no network work.
- [ ] The removed `-driver` flag is absent from help and rejected as an unknown flag without network work.
- [ ] Binary, context, and ATT&CK sorting.
- [ ] Deterministic map ordering.
- [ ] Exact and case-insensitive search.
- [ ] Ambiguous search.
- [ ] Catalog miss versus PATH miss.
- [ ] Default filtering.
- [ ] `-all` filtering.
- [ ] Search shows all contexts.
- [ ] Plain output contains no ESC bytes.
- [ ] Multiline commands are not truncated.
- [ ] Multi-MITRE examples remain one row.
- [ ] Header counts match rendered results.

## Manual smoke-test matrix

Run these only after all automated tests pass. Do not execute any displayed GTFOBins command.

### Ubuntu or Debian-family host

```bash
./goGTFO -plain -h
./goGTFO -plain -s bash
./goGTFO -plain -s definitely-not-a-real-catalog-entry
./goGTFO -plain -sort context
./goGTFO -plain -sort attack
./goGTFO -plain -all -s bash
```

Confirm:

- [ ] The live catalog fetch succeeds.
- [ ] Installed paths are Linux paths.
- [ ] Search output clearly shows context states and evidence.
- [ ] No command is executed.
- [ ] No sudo prompt appears.

### Kali or another security-focused distribution

Repeat the harmless listing commands above and compare only structural behavior. Different installed-binary counts are expected.

### Optional sudo probe

Run only on a disposable or authorized test host where policy-list checks may be logged:

```bash
./goGTFO -plain -check-sudo -s bash
```

Confirm:

- [ ] No password prompt appears.
- [ ] A nonzero sudo result remains unknown.
- [ ] A successful path check is labeled potential, not confirmed.

## Final acceptance criteria

The conversion is complete only when all of these are true:

### Functional

- [ ] The project builds as a Linux binary named `goGTFO`.
- [ ] It fetches and parses the live official GTFOBins API.
- [ ] It detects exact catalog names in PATH.
- [ ] It resolves aliases, inheritance, context overrides, and companions.
- [ ] It displays functions, contexts, ATT&CK IDs, commands, comments, and versions.
- [ ] Search, sorting, plain mode, `-all`, and optional sudo probing work as documented.

### Correctness

- [ ] Linux paths are never lowercased.
- [ ] SUID requires root ownership, setuid, executable mount, suid-enabled mount, and `NoNewPrivs=0`.
- [ ] Capabilities require valid xattr data, required bits, effective use, bounding-set inclusion, suitable mount flags, and `NoNewPrivs=0`.
- [ ] Free-text version restrictions are never auto-confirmed.
- [ ] Sudo path checks never claim full command authorization.
- [ ] Unknown future contexts remain unknown.

### Safety

- [ ] Catalog responses are bounded and structurally validated.
- [ ] Remote terminal control characters are neutralized.
- [ ] No GTFOBins snippet can reach shell or process execution.
- [ ] Default operation never prompts for credentials.
- [ ] Sudo probing is direct, non-interactive, cached, and time-bounded.
- [ ] No recursive filesystem scan occurs.
- [ ] No LOLDrivers endpoint or local driver scan exists in the completed application.

### Quality

- [ ] `gofmt`, `go test ./...`, `go vet ./...`, and both Linux builds pass.
- [ ] Tests are deterministic and do not require network, root, setuid, capabilities, or real sudo access.
- [ ] README behavior matches code behavior.
- [ ] CI does not use the live catalog.
- [ ] The worktree contains no compiled binary.
- [ ] The Ponytail review finds no unnecessary dependency, interface, provider layer, cache, configuration system, or duplicated model.

## Estimated work

For one engineer familiar with Go and Linux:

| Workstream | Estimate |
|---|---:|
| Cleanup and Linux build boundary | 0.5 day |
| Catalog models, fetch validation, fixture, and sanitization | 0.75–1 day |
| Alias, inheritance, companion, and normalized-model work | 0.75–1 day |
| PATH, process, mount, SUID, and capability evidence | 1–1.5 days |
| Sudo probe and applicability integration | 0.5–0.75 day |
| Output/CLI conversion | 0.75–1 day |
| Tests, documentation, CI, and cleanup | 1–1.5 days |
| **Credible complete implementation** | **5–7.25 engineering days** |

Allow 7–10 elapsed working days for review findings, distro-specific corrections, and release validation. This excludes any later deep filesystem scanning, offline cache, JSON output, or dual-platform support.

## Deferred work trigger list

Do not implement these during the conversion. Revisit only when the stated trigger exists.

| Deferred feature | Add only when |
|---|---|
| Recursive/off-PATH scan | Users demonstrate important SUID or capability findings missed by PATH-only discovery. |
| Offline catalog cache | Real target environments regularly lack network access and a freshness policy is agreed. |
| JSON output | A concrete automation consumer and schema requirements exist. |
| Version probing | Safe per-executable version strategies and false-positive policy are defined. |
| Direct sudoers interpretation | A reliable library/API and precise authorization semantics are available. |
| Windows/LOLBAS/LOLDrivers mode | Maintaining one binary for both platforms becomes a real product requirement. |
| macOS/BSD | A catalog and platform-specific privilege model are selected. |
| Release automation | Manual tagged builds become a recurring burden. |
| Additional packages | Standard library plus `x/sys/unix` is proven insufficient. |

## Completion handoff

At completion, the implementation agent should report:

1. Files added, changed, and deleted.
2. Any deviation from this plan and the evidence that required it.
3. Applicability semantics actually implemented.
4. Test, vet, amd64 build, and arm64 build results.
5. Manual Ubuntu/Kali smoke-test results, if available.
6. Known limitations that remain intentionally unknown rather than overstated.
7. The result of the final Ponytail review and anything it removed or deferred.
