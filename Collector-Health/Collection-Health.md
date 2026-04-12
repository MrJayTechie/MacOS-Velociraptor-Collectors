# Collection Health Report

Validates a Velociraptor macOS collection before parsing. Checks artifact presence, SQLite WAL completeness, FDA/SIP status, and provides actionable recommendations.

**Author:** Ali Jammal

---

## Usage

```bash
# Basic usage
python3 collection_health.py /path/to/extracted/collection

# JSON output
python3 collection_health.py /path/to/extracted/collection -j

# Verbose mode (shows DB/WAL file sizes)
python3 collection_health.py /path/to/extracted/collection -v

# Disable colors
python3 collection_health.py /path/to/extracted/collection --no-color > report.txt
```

Accepts the collection root (parent of `uploads/auto/`) or `uploads/auto/` directly — auto-detects both. Runs in under 100ms.

---

## What It Checks

### 1. Collection Metadata

Extracted from `client_info.json` and `collection_context.json`:

- Hostname
- macOS version and build (parsed from SystemVersion.plist if available)
- Collection date and duration
- Total files and size
- User accounts found

### 2. Artifact Presence (70 artifacts)

For each of the 70 YAML collector artifacts, checks whether the expected files exist in `uploads/auto/`. Each artifact is categorized by:

- **IR function**: Browsers, Communications, User Activity, Persistence, Security, System, Logs, Filesystem, Network, Shell, Cloud, Apps
- **Access requirement**: USER, ROOT, FDA, SIP, FDA+SIP

Reports: **PRESENT** (files found) or **MISSING** (no files found).


### 4. FDA Inference

Determines whether Full Disk Access was granted to the collector binary by checking 10 FDA-protected indicator artifacts:

| Indicator | Path |
|-----------|------|
| KnowledgeC | /private/var/db/CoreDuet/Knowledge/ |
| Interactions | /private/var/db/CoreDuet/People/ |
| TCC | ~/Library/Application Support/com.apple.TCC/ |
| Biomes | ~/Library/Biome/ |
| iMessage | ~/Library/Messages/ |
| SafariFiles | ~/Library/Safari/ |
| AppleNotes | ~/Library/Group Containers/group.com.apple.notes/ |
| Notifications | ~/Library/Group Containers/group.com.apple.usernoted/ |
| Powerlogs | /private/var/db/powerlog/ |
| WifiIntelligence | ~/Library/IntelligencePlatform/ |

Inference logic:

| Present | Status | Confidence |
|---------|--------|------------|
| 8+ of 10 | GRANTED | HIGH |
| 5-7 of 10 | LIKELY_GRANTED | MEDIUM |
| 0-2 of 10 | NOT_GRANTED | HIGH |
| 3-5 of 10 | LIKELY_NOT_GRANTED | MEDIUM |

### 5. SIP-Blocked Artifacts

Flags artifacts that are always missing on live SIP-enabled systems:

| Artifact | Path | Status |
|----------|------|--------|
| xpdb | /private/var/protected/xprotect/db/ | Expected missing |
| KeyChain (SystemKey) | /private/var/db/SystemKey | Expected missing |


---

## Output Formats

| Flag | Format | Use Case |
|------|--------|----------|
| _(default)_ | Terminal with ANSI colors | Interactive review |
| `-j` | JSON to stdout | Automation / scripting |
| `-v` | Verbose terminal (includes file sizes) | Deep inspection |
| `--no-color` | Plain text | Piping to file |

---

## Example Output

```
========================================================================
  COLLECTION HEALTH REPORT
  Author: Ali Jammal
========================================================================

COLLECTION METADATA
  Hostname:        <Hostname>
  OS Version:      macOS 15.7.4 (24G517)
  Collection Date: 2026-04-12 07:50:00 UTC
  Duration:        7m 57s
  Total Files:     15,066
  Total Size:      3.3 GB
  Users Found:     aljammal

========================================================================
ARTIFACT PRESENCE (70 artifacts)
========================================================================

  PRESENT: 56   MISSING: 14

  -- Browsers --
    [PRESENT]  ChromiumBrowsers               [USER]
    [PRESENT]  FirefoxFiles                   [USER]
    [PRESENT]  SafariFiles                    [FDA]
    [PRESENT]  cookies                        [FDA]

  -- Communications --
    [PRESENT]  iMessage                       [FDA]
    [PRESENT]  AppleNotes                     [FDA]
    ...

========================================================================
FULL DISK ACCESS INFERENCE
========================================================================

  FDA Status:  GRANTED (HIGH confidence)
  Protected artifacts present: 10/10

    [YES]  KnowledgeC
    [YES]  Interactions
    [YES]  TCC
    [YES]  Biomes
    [YES]  iMessage
    [YES]  SafariFiles
    [YES]  AppleNotes
    [YES]  Notifications
    [YES]  Powerlogs
    [YES]  WifiIntelligence

========================================================================
RECOMMENDATIONS
========================================================================

  [OK]       FDA was granted — 10/10 protected artifacts present.
  [OK]       Collection looks complete (56/70 artifacts present).
  [WARN]     13 SQLite database(s) missing WAL files.
  [INFO]     2 SIP-blocked artifact(s) missing — expected on live systems.
```
