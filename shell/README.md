# Shell Collector (`collect_macos.sh`)

A pure-shell equivalent of the Velociraptor collector in this repository. **This is a collector as well** — it pulls the same 71 artifacts as the YAML-defined Velociraptor collectors, just driven by `zsh` + `ditto` instead of a Go binary.

Designed for environments where the Velociraptor binary is blocked by MDM / Gatekeeper / notarization policy. Since a shell script runs through Apple-signed `/bin/zsh`, Gatekeeper does not evaluate it.

## Why this exists

Velociraptor v0.76.3 is signed by Rapid7 but **not notarized**. On Macs managed by an MDM that enforces notarization (a common hardening baseline), Gatekeeper blocks the binary. This script is a drop-in substitute for those environments.

## What it collects

All 71 macOS artifacts defined by the YAML collectors in this repo. Artifact parity has been verified against Velociraptor output (~99.8% file-count parity on a reference collection).

See `../Collectors/` for the authoritative artifact list. When a YAML collector is added, removed, or modified, this script should be updated in lockstep — the two define the same set of artifacts.

## Output layout

```
collection-<host>-<timestamp>/
├── filesystem/          ← mirrors the live filesystem; Dissect dir loader points here
│   ├── Users/<user>/...
│   ├── Library/...
│   └── private/...
├── manifest.csv         ← artifact,source,dest,size,sha256,status (per file)
├── collection.log       ← per-artifact BEGIN/END, errors
└── ARTIFACTS.txt        ← per-artifact item counts + failures
```

The whole collection is packaged as `<collection-dir>.zip` (via `ditto -c -k --sequesterRsrc --keepParent`) with a sidecar `.sha256` file for chain-of-custody.

## Usage

```sh
# Default — fast mode, tarball-level hash only:
sudo ./collect_macos.sh

# Specify output directory:
sudo ./collect_macos.sh /tmp/case-1234

# Force per-file sha256 (slower, rarely needed):
sudo ./collect_macos.sh --hash

# Disable batch-directory copy (debug only, much slower):
sudo ./collect_macos.sh --slow
```

## Full Disk Access

For parity with a Velociraptor collection, the shell that runs this script needs **Full Disk Access**:

1. System Settings → Privacy & Security → Full Disk Access
2. Add Terminal.app (or iTerm.app)
3. Restart the terminal, re-run

Without FDA, artifacts under `~/Library/Mail`, `~/Library/Messages`, `~/Library/Safari`, `~/Library/Application Support/AddressBook`, `TCC.db`, and keychains will be silently empty. The script probes for FDA at startup and logs a warning if it's not granted.

## Parsing with Dissect

The `filesystem/` output is directly consumable by the Dissect macOS plugins:

```sh
target-query collection-<host>-<ts>/filesystem --list
target-query collection-<host>-<ts>/filesystem -f macos.shellhistory
target-query collection-<host>-<ts>/filesystem -f macos.knowledgec
```

## MDM / EDR considerations

The script reads keychains, TCC.db, browser login data, iMessage chat.db, and other high-value paths — behaviors that overlap with macOS stealer malware. On hosts running CrowdStrike, SentinelOne, Jamf Protect, or similar behavioral EDR, expect "credential access" / "collection" alerts to fire.

**Coordinate with your SOC before running in production.** A brief heads-up ("IR collection from host X at time Y, please suppress credential-access alerts during this window") is standard DFIR practice.
