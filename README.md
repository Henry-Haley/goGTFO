# goGTFO

goGTFO is a Linux scanner for [GTFOBins](https://gtfobins.github.io/): it finds catalog executables available through `PATH` and evaluates their documented contexts against the local host. GTFOBins entries are documented techniques, not vulnerabilities.

Repository: `github.com/Henry-Haley/goGTFO`

goGTFO fetches the live official GTFOBins catalog when it runs. It never executes GTFOBins commands, examples, listeners, connectors, senders, or receivers; catalog commands are display-only data.

## Requirements

- Linux
- Go 1.26.5 to build from source
- Network access to retrieve the live GTFOBins catalog

## Install

```bash
git clone https://github.com/Henry-Haley/goGTFO.git
cd goGTFO
go build -o goGTFO .
```

Or install directly:

```bash
go install github.com/Henry-Haley/goGTFO@latest
```

## Usage

```bash
./goGTFO
./goGTFO -plain
./goGTFO -s bash
./goGTFO -plain -all -sort context
```

Supported flags:

| Flag | Meaning |
| --- | --- |
| `-h`, `-help` | Show help without fetching the catalog. |
| `-plain` | Use ASCII-only presentation with no terminal control sequences. |
| `-s name`, `-search name` | Show one catalog executable and every documented context. A directory prefix is ignored; names otherwise match exactly, or case-insensitively when unambiguous. |
| `-sort mode` | Sort by `binary`, `context`, or `attack`. Aliases: `b`, `c`, `ctx`, `privilege`, `a`, and `mitre`. |
| `-all` | Include unknown and unavailable contexts in a normal listing. |
| `-check-sudo` | Run bounded, noninteractive `sudo -n -l <canonical-path>` policy checks. This may be logged by the host. |

The `privilege` sort alias is retained only for command-line compatibility; it does not enable non-Linux behavior.

## Discovery and applicability

Discovery is PATH-only: goGTFO checks catalog executable names through `PATH` and evaluates the resolved executable. It does not recursively scan the filesystem, so binaries outside `PATH` are not discovered.

Each documented context is reported as one of four states:

| State | Meaning |
| --- | --- |
| `confirmed` | Available host evidence satisfies the context. |
| `potential` | The available evidence is useful but does not prove the full technique can run. |
| `unknown` | Evidence is incomplete, a version restriction is unverified, or goGTFO has no evaluator for a future catalog context. |
| `unavailable` | A required executable or host condition is absent or safely blocked. |

Normal listings show `confirmed` and `potential` contexts, plus counts for hidden `unknown` and `unavailable` contexts. `-all` shows every state. Search mode acts like `-all` for its selected executable.

The Linux checks include executable and mount state, `noexec`, `nosuid`, `NoNewPrivs`, the process capability bounding set, root-owned SUID files, and file capabilities. These checks deliberately avoid overstating what can be proven from local metadata. Sudo trust is accepted only in the initial user namespace; mount namespaces and a privileged attacker who can replace files after validation remain outside the ordinary unprivileged PATH-poisoning threat model. goGTFO does not claim to detect whether a future target execution will be ptraced: `/proc/self/status` describes the scanner process, while the kernel's set-user-ID and file-capability suppression applies to the process being executed.

Sudo is disabled by default. With `-check-sudo`, a recognized canonical executable path is still only `potential`: a path-policy listing cannot prove authorization for an entire GTFOBins command line. If no trusted sudo binary is available, sudo contexts are `unavailable`; if a trusted sudo exists but its policy probe cannot establish authorization, they remain `unknown` rather than becoming `confirmed`.

## Exit status

| Code | Meaning |
| --- | --- |
| `0` | A successful listing, including a listing with zero confirmed results, or help. |
| `1` | Catalog fetch, parsing, or validation failure; absent catalog search name; or selected executable absent from `PATH`. |
| `2` | Invalid flag, unexpected argument, or invalid sort mode. |

## Safety and authorization

goGTFO is for authorized security testing, lab use, and education only. Run it only on systems you own or have explicit permission to assess. You are responsible for complying with applicable laws, policies, and rules of engagement.

The GTFOBins catalog is maintained by the [GTFOBins project](https://gtfobins.github.io/). A displayed technique is not a guarantee that it will work: host policy, configuration, versions, and runtime conditions may prevent it.
