# goGTFO

> **Development status:** goGTFO is under active conversion and is not yet release-ready or suitable for use as a stable security tool.

goGTFO is a Linux host scanner under active development that identifies installed GTFOBins executables and evaluates documented techniques against the host's unprivileged, SUID, file-capability, and sudo contexts, with MITRE ATT&CK mappings and example commands.

goGTFO is a Linux-focused adaptation of [goLoL](https://github.com/aaron-kidwell/goLoL), originally created by Aaron Kidwell.

Maintainer: Henry Haley

## Current development status

- Phase 0 established the repository, conversion specification, Go 1.26.5 toolchain, and baseline.
- Phase 1 established a Linux-only build and removed Windows console handling and LOLDrivers functionality.
- The GTFOBins catalog model, live fetching, executable discovery, applicability evaluation, final output, tests, CI, and releases are still being implemented.
- The `linux-gtfobins-port` branch is a development branch and must not yet be treated as a stable security tool.

Any remaining legacy LOLBAS paths are temporary conversion scaffolding, not supported goGTFO functionality.

## Planned functionality

- Live retrieval of the official GTFOBins catalog.
- PATH-based executable discovery.
- Unprivileged-context findings.
- SUID applicability analysis.
- Linux file-capability analysis.
- Sudo-policy evidence.
- Alias and inheritance handling.
- MITRE ATT&CK mappings.
- Human-readable and structured output.
- Explicit applicability states distinguishing `confirmed`, `potential`, `unknown`, and `unavailable` techniques.
- Display-only handling of commands supplied by the GTFOBins catalog; catalog commands will never be executed.

## Safety model

goGTFO displays documented catalog techniques but does not execute them. It is intended only for authorized assessment, lab, and educational use and must be run only on systems you own or have explicit permission to assess.

goGTFO is not an OPSEC-safe tool. A displayed technique is not a guarantee that the command will succeed because host policy, configuration, versions, and runtime conditions may still prevent it.

## Requirements

- Linux.
- Go 1.26.5.
- Network access for future live GTFOBins catalog retrieval.

## Development build

There are no stable releases or packaged binaries yet. To build the current development branch:

```bash
git clone https://github.com/Henry-Haley/goGTFO.git
cd goGTFO
git switch linux-gtfobins-port
go test ./...
go build -o goGTFO .
```

The resulting binary is a transitional development build, not a completed GTFOBins scanner.

## Project status

| Phase                                      | Status      |
| ------------------------------------------ | ----------- |
| Repository preparation and baseline        | Complete    |
| Linux-only build conversion                | Complete    |
| GTFOBins catalog models                    | Not started |
| Live catalog client                        | Not started |
| Executable discovery                       | Not started |
| Alias and inheritance resolution           | Not started |
| Host applicability inspection              | Not started |
| Evaluation and rendering                   | Not started |
| Final orchestration                        | Not started |
| CI, documentation, and release preparation | Not started |

## Disclaimer

For authorized security testing, lab use, and education only. Run goGTFO only on systems you own or have explicit permission to assess. You are responsible for complying with applicable laws, policies, and rules of engagement. The project maintainers and original author are not responsible for misuse.
