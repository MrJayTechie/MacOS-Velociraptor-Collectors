# MacOS.Collection — Velociraptor Forensic Collector

A set of 70 Velociraptor artefacts that collect macOS forensic evidence into a single offline `.zip`. Designed to feed the dissect-plugin parsers, but the resulting collection is also analysable with any tool that understands a tree of macOS files such as MacApt.

> **Author:** Ali Jammal
> **Tested on:** macOS 13 (Ventura), 14 (Sonoma), 15 (Sequoia)
> **Velociraptor version:** ≥ 0.72

---

## Quick start

1. **Build the collector** in the Velociraptor GUI: Client Artifacts → Upload artefact button→ Upload the Zip file.
2. The GUI produces two downloads — `Collector_velociraptor-collector` (the binary) and `spec.yaml` (the build spec, audit-only).
3. **Grant Full Disk Access** to the collector binary (see below). Without FDA, ~25 % of the artefacts return zero rows.
4. Run the collector on the target Mac:
   ```sh
   sudo ./velociraptor-v0.76.2-darwin-amd64 -- --embedded_config /path/to/Collector_velociraptor-collector
   ```
5. Output zip lands in `/tmp/Collection-<hostname>-<timestamp>.zip`. **Extract with `ditto` or bsdtar(not `unzip`) to an APFS volume preferably  as `unzip` mangles non-ASCII filenames and exFAT loses symlinks/perms/xattrs).
6. Point any of your analysis tool at `<extracted>/uploads/auto/`.
---

## Privilege model

macOS layers three independent permission systems on top of UNIX file permissions. Each artefact in this collector falls into one of four buckets — knowing which is critical to understanding why a collection might come back empty.

### USER — readable by any logged-in user
No special privileges needed. Files like `~/.zsh_history`, `/Applications/*`, `/etc/hosts`, `~/Library/Safari/Bookmarks.plist` (in some macOS versions).

### ROOT — needs admin/sudo, no TCC entitlement
Files owned by root with mode 600/640. Root unlocks them. Examples: `/etc/sudoers`, `/var/db/dslocal/nodes/Default/users/`, `/private/var/db/ConfigurationProfiles/Settings/`, `/Library/Keychains/System.keychain`.

### FDA — needs Full Disk Access entitlement (TCC)
Even with UID 0, **macOS TCC (Transparency, Consent, and Control) blocks access to user-private databases and protected system paths** unless the executing binary holds the FDA entitlement. This affects nearly all the high-value forensic artifacts on modern macOS:

- `~/Library/Mail`, `~/Library/Messages`, `~/Library/Safari` (browsing/email)
- `~/Library/Application Support/AddressBook`, `CallHistoryDB`, `FaceTime`, `Knowledge`, `com.apple.TCC`
- `~/Library/Group Containers/group.com.apple.notes` (Apple Notes)
- `~/Library/Containers/com.apple.Safari` (Safari container)
- `~/Library/Biome/streams/restricted/` (Biome event streams)
- `~/Library/IntelligencePlatform/` (Wi-Fi & person inference)
- `/private/var/db/CoreDuet/Knowledge/knowledgeC.db` and `/private/var/db/CoreDuet/People/interactionC.db`
- `/private/var/db/lockdown/` (iOS pairing records)
- `/private/var/db/locationd/` (location services clients)
- `/private/var/db/powerlog/` (battery/sleep events)
- `/private/var/folders/<2>/<32>/0/` and `/C/` (user TMPDIR — Launchpad, ScreenTime, QuickLook live here)
- `/private/var/db/sysdiagnose/`

#### How to grant Full Disk Access to the collector

1. Open **System Settings → Privacy & Security → Full Disk Access**
2. Click the **`+`** button at the bottom of the list (authenticate with Touch ID / password)
3. Add the terminal and provide it FDA
4. **Toggle the entry on** (new entries are sometimes added in the disabled state — verify the switch is blue/green)
5. No reboot needed. Re-run the collector.

### SIP — System Integrity Protection
A kernel-level write/read barrier that **even FDA + root cannot bypass**. SIP-protected paths require either:
- a process signed with a private Apple entitlement (e.g. `com.apple.private.security.storage.xprotect-database`), or
- SIP being disabled from Recovery (`csrutil disable`), or
- a forensic boot from external media

SIP-protected paths in this collector that **will always fail on a SIP-enabled live system**:

| Path                                     | Used by artifact | Notes                                     |
| ---------------------------------------- | ---------------- | ----------------------------------------- |
| `/private/var/db/SystemKey`              | `KeyChain`       | Master key for system keychain unwrap     |
| `/private/var/protected/xprotect/db/`    | `xpdb`           | XProtect Behavior Service & Remediator DB |
| `/private/var/protected/trustd/private/` |                  | Trust daemon private store                |
| `/private/var/db/Spotlight-V100/`        |                  | Spotlight reverse-index                   |

These will appear as `operation not permitted` in the Velociraptor log even with `--require_admin` and FDA. They are the only artefacts in the collector that genuinely **cannot** be acquired without disabling SIP — accept them as known gaps unless you're working from a forensic image.

---

## Artifact catalog

70 artefacts. Each row shows the privilege required, what it captures, and where it lives on disk.

### Browsers & web

| Artifact | Privilege | What it collects |
|---|---|---|
| **ChromiumBrowsers** | USER | Chrome, Brave (+ Beta, Nightly), Edge (+ Beta, Dev), Chromium, Opera, OperaGX, Vivaldi — `History`, `Cookies`, `Bookmarks`, `Login Data`, `Web Data`, `Shortcuts`, `Top Sites`, `Favicons`, `Preferences`, `Local State` (encryption key), and all SQLite `-wal`/`-shm` sidecars across `Default`, `Profile*`, and `Guest Profile` directories |
| **FirefoxFiles** | USER | `~/Library/Application Support/Firefox/**` — places.sqlite, cookies.sqlite, formhistory.sqlite, logins.json, permissions.sqlite |
| **SafariFiles** | FDA | `~/Library/Safari/**` — History.db, Bookmarks.plist, TopSites.plist, Downloads.plist (Safari container is TCC-protected) |
| **cookies** | FDA | `~/Library/Cookies/*.binarycookies`, `~/Library/Containers/com.apple.Safari/Data/Library/Cookies/` |

### Communications

| Artifact | Privilege | What it collects |
|---|---|---|
| **iMessage** | FDA | `~/Library/Messages/chat.db` + `-wal`/`-shm` + `Attachments/**` |
| **CallHistory** | FDA | `~/Library/Application Support/CallHistoryDB/CallHistory.storedata` + `-wal`/`-shm` |
| **FaceTime** | FDA | `~/Library/Application Support/FaceTime/FaceTime.sqlite3` + `-wal`/`-shm` |
| **AddressBook** | FDA | `~/Library/Application Support/AddressBook/**` (AddressBook-v22.abcddb + per-source dirs) |
| **AppleMail** | FDA | `~/Library/Mail/**` (full mailbox tree + Envelope Index DB) |
| **Notifications** | FDA | `~/Library/Group Containers/group.com.apple.usernoted/db2/db` + `-wal`/`-shm`, plus `/private/var/folders/.../com.apple.notificationcenter/db2/db` |
| **AppleNotes** | FDA | `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` + `-wal`/`-shm` |
| **notes** | FDA | Older Notes path: `~/Library/Containers/com.apple.Notes/Data/Library/Notes/**` |

### User activity & inference

| Artifact | Privilege | What it collects |
|---|---|---|
| **KnowledgeC** | FDA | `/private/var/db/CoreDuet/Knowledge/knowledgeC.db` + `-wal`/`-shm` (system) and `~/Library/Application Support/Knowledge/knowledgeC.db` + sidecars (per-user). App usage, web usage, notifications, intents, Bluetooth, sync peers |
| **Interactions** | FDA | `/private/var/db/CoreDuet/People/interactionC.db` + `-wal`/`-shm` — communication graph |
| **Biomes** | FDA | `~/Library/Biome/**` and `/private/var/db/biome/**` — SEGB stream files for App.Activity, Safari.Browsing, Messages.Read, ProactiveHarvesting.*, Siri.*, Screen.Sharing, Notification.Usage, ScreenTime.AppUsage, etc. (~100 streams on macOS 15) |
| **WifiIntelligence** | FDA | `~/Library/IntelligencePlatform/Artifacts/internal/views.db` + `-wal`/`-shm` — Wi-Fi events, person inference, entity aliases |
| **Powerlogs** | FDA | `/private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL` + `-wal`/`-shm` — sleep/wake, app usage, network |
| **ScreenTime** | FDA | `/private/var/folders/*/*/0/com.apple.ScreenTimeAgent/**` — RMAdminStore (parental controls, app usage blocks) |
| **Reminders** | FDA | `~/Library/Group Containers/group.com.apple.reminders/Container_v1/Stores/**` |
| **Calendars** | FDA | `~/Library/Calendars/**` — Calendar.app caches (modern macOS uses Group Containers, may be empty) |
| **FindMy** | FDA | `~/Library/Caches/com.apple.findmy.{fmipcore,fmfcore}/*.data` |

### System configuration & state

| Artifact | Privilege | What it collects |
|---|---|---|
| **OSName** | USER | `/System/Library/CoreServices/SystemVersion.plist` |
| **OSInstallationDate** | USER | `/var/db/.AppleSetupDone` mtime + SystemVersion |
| **Users** | ROOT | `/private/var/db/dslocal/nodes/Default/users/*.plist` |
| **localtime** | USER | `/etc/localtime` symlink target |
| **hosts** | USER | `/etc/hosts` |
| **etcFolder** | USER | `/etc/{nfs.conf, resolv.conf, services, ssh/*, ...}` |
| **DHCPLease** | FDA | `/private/var/db/dhcpclient/leases/**` |
| **FavoriteVolumes** | USER | `~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.FavoriteVolumes.sfl3` |
| **SharedFolder** | ROOT | `/private/var/db/dslocal/nodes/Default/sharepoints/*.plist` |
| **InternetAccounts** | USER | `~/Library/Accounts/Accounts4.sqlite` |
| **iCloud** | FDA | CloudDocs `server.db`/`client.db` + `-wal`/`-shm`, SyncedPreferences plists, iCloud Accounts metadata |
| **iCloudLocalStorage** | USER | `~/Library/Mobile Documents/**` (local copies of iCloud Drive files) |
| **lockdown** | FDA | `/private/var/db/lockdown/**` — iOS pairing records ("Trust This Computer") |
| **iDeviceBackup** | FDA | `~/Library/Application Support/MobileSync/Backup/**` — iPhone/iPad backups (Info.plist, Manifest.db) |
| **ManagedDeviceProfile** | ROOT | `/private/var/db/ConfigurationProfiles/Settings/**` — MDM profiles |

### Persistence & autostart

| Artifact | Privilege | What it collects |
|---|---|---|
| **Autostart** | USER | `/System/Library/Extensions/**`, `/Library/Extensions/**`, `/System/Library/LaunchDaemons/**`, `/Library/LaunchDaemons/**`, `/System/Library/LaunchAgents/**`, `/Library/LaunchAgents/**`, `~/Library/LaunchAgents/**`, `/System/Library/StartupItems/**`, `/Library/StartupItems/**`, `/etc/periodic/{daily,monthly,weekly}/**`, `/etc/launchd.conf`, `/etc/rc.common` |
| **KernelExtensions** | USER | `/System/Library/Extensions/*.kext`, `/Library/Extensions/*.kext`, `/Library/StagedExtensions/**`, `/Library/Apple/System/Library/Extensions/**` |
| **LaunchPad** | FDA | `/private/var/folders/*/*/0/com.apple.dock.launchpad/db/**` (current macOS path) and `~/Library/Application Support/com.apple.dock.launchpad/db/**` (legacy) |

### Security & access control

| Artifact | Privilege | What it collects |
|---|---|---|
| **TCC** | FDA | `/Library/Application Support/com.apple.TCC/TCC.db` + `-wal`/`-shm` (system) and `~/Library/Application Support/com.apple.TCC/TCC.db` + sidecars (per-user), plus `/private/var/db/locationd/clients.plist` |
| **KeyChain** | FDA + **SIP** | `~/Library/Keychains/**`, `/Library/Keychains/System.keychain`, `/private/var/db/SystemKey` (SIP — fails on live) |
| **xpdb** | **SIP** | `/private/var/protected/xprotect/db/**` — XProtect Behavior Service DB. **Will fail on live system without disabling SIP.** |
| **Sudoers** | USER | `/etc/sudoers` |
| **sudolastrun** | ROOT | `/var/db/sudo/ts/*` (sudo timestamp dir mtimes) |
| **AlternateLog** | USER | `/var/log/{system,install,...}.log`, `/var/audit/*` (audit trail), `/var/log/asl/*.asl` |
| **FirewallConfiguration** | USER | `/etc/pf.conf`, `/etc/pf.anchors/**`, `/Library/Preferences/com.apple.alf.plist` |
| **ScreenSharing** | FDA + ROOT | `/Library/Preferences/com.apple.RemoteManagement.plist`, `/Library/Preferences/com.apple.ScreenSharing.plist` |
| **ard** | FDA | `/private/var/db/RemoteManagement/caches/{AppUsage.tmp, AppUsage.plist, UserAcct.tmp}` — Apple Remote Desktop usage |
| **SSHHost** | USER | `/etc/ssh/ssh_config`, `~/.ssh/{known_hosts, config, authorized_keys}` |

### Filesystem evidence

| Artifact | Privilege | What it collects |
|---|---|---|
| **DSStore** | USER | `.DS_Store` files under `/Users`, `/Applications`, `/Library` (and `%2EDS_Store` URL-encoded variants for Velociraptor zip path sanitisation). **Note:** `/Volumes/**` is intentionally excluded — `/Volumes/Macintosh HD` is an APFS firmlink to `/`, scanning it doubles collection time. |
| **FsEvents** | USER | `/.fseventsd/**`, `/System/Volumes/Data/.fseventsd/**`, `/private/var/db/fseventsd/**` (gzip DLS1/DLS2) |
| **DocumentRevisions** | USER | `/.DocumentRevisions-V100/**` — Versions feature DB and stored revisions |
| **QuickLook** | FDA | `/private/var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/{index.sqlite + sidecars, thumbnails.data}` |
| **Trash** | USER | `~/.Trash/**`, `/.Trashes/**` (and `%2E` variants) |
| **CrashReporter** | USER | `~/Library/Logs/DiagnosticReports/**`, `/Library/Logs/DiagnosticReports/**` |

### Apps & application data

| Artifact | Privilege | What it collects |
|---|---|---|
| **Applications** | USER | `/Applications/*/Contents/Info.plist`, `~/Applications/**` |
| **Applist** | ROOT | `/Library/Application Support/com.apple.spotlight/appList.dat` |
| **ApplePayWallet** | FDA | `~/Library/Passes/passes23.sqlite` + `-wal`/`-shm` |
| **InstallHistory** | USER | `/Library/Receipts/InstallHistory.plist` |
| **SoftwareInstallationUpdates** | USER | `~/Library/Caches/com.apple.appstoreagent/storeSystem.db` + `-wal`/`-shm`, `/var/db/receipts/**`, `/Library/Preferences/com.apple.SoftwareUpdate.plist` |
| **MicrosoftOfficeMRU** | FDA | `~/Library/Containers/com.microsoft.{Word,Excel,Powerpoint}/Data/Library/Preferences/com.microsoft.*.securebookmarks.plist` |
| **msrdc** | FDA | Microsoft Remote Desktop `application-data.sqlite` + `-wal`/`-shm` and `SupportingImages/**` |

### Saved state & UI

| Artifact | Privilege | What it collects |
|---|---|---|
| **SavedState** | USER | `~/Library/Saved Application State/**` + `~/Library/Daemon Containers/*/Data/Library/Saved Application State/**` (macOS 15 relocated path) |
| **TerminalState** | USER | `~/Library/Saved Application State/com.apple.Terminal.savedState/**` + Daemon Containers equivalent (Terminal no longer saves state on macOS 15) |
| **SpotlightShortCuts** | ROOT | `/private/var/db/spotlight/com.apple.spotlight.Shortcuts.plist` |
| **KeyboardDictionary** | USER | `~/Library/Spelling/{LocalDictionary, dynamic-counts.dat}` |
| **PrintJobs** | USER | `/var/spool/cups/{c, tmp}/**`, `/private/etc/cups/cups-files.conf` |
| **ShellHistoryAndSessions** | USER | `~/.zsh_history`, `~/.bash_history`, `~/.zsh_sessions/**`, `~/.bash_sessions/**`, plus `%2E`-encoded variants |
| **LibraryPreferences** | USER | `/Library/Preferences/**`, `~/Library/Preferences/**` (system-wide and per-user plist tree) |
| **utmpx** | USER | `/private/var/run/utmpx` (binary login records) |


---

## Extracting the collection

> ⚠️ **Do NOT use the macOS Finder Archive Utility, and do NOT use `unzip`.** Both mangle non-ASCII filenames (curly apostrophes, accents, emoji) into U+FFFD replacement characters (`���`), which silently breaks dissect plugins that look up files by their real names. They also prompt interactively on errors.

### Use `ditto` or `bsdtar`

Both are built into macOS and handle UTF-8 filenames correctly.

```sh
# Option A — ditto (built-in, best macOS metadata fidelity)
ditto -x -k "/path/to/Collection-<host>-<timestamp>.zip" /path/to/output

# Option B — bsdtar (built-in, faster, identical results for forensic use)
bsdtar -xf "/path/to/Collection-<host>-<timestamp>.zip" -C /path/to/output
```

> **Tip on shell line continuations:** if you want to break the command across multiple lines with `\`, make sure there is **no whitespace between the `\` and the newline** — zsh treats `\<space>` as escaping the space, not as a line continuation, and the command will be parsed as multiple separate commands. Easiest workaround: just put it on one line.

### Always extract to APFS, never to exFAT/FAT32/NTFS

The dissect plugins rely on filesystem features that **only APFS (and HFS+) preserve**:

| Feature | APFS | exFAT | FAT32 | NTFS (read-only via macOS) |
|---|---|---|---|---|
| POSIX permissions | ✅ | ❌ | ❌ | ❌ |
| Symlinks | ✅ | ❌ | ❌ | ❌ |
| Extended attributes (xattrs) | ✅ | ❌ | ❌ | ❌ |
| Case-sensitive filenames | ✅ (if formatted case-sensitive) | ❌ | ❌ | ❌ |
| UTF-8 filenames | ✅ | ⚠️ partial | ❌ | ✅ |
| Resource forks | ✅ | ❌ | ❌ | ❌ |
| File timestamps (ns precision) | ✅ | ⚠️ 2-sec | ⚠️ 2-sec | ✅ |

If you extract to exFAT, you will see warnings like `cannot set modif./access times`, `fchmod (file attributes) error: Bad file descriptor`, and any symlinks in the source tree (e.g. `/etc → /private/etc`) will be silently skipped. Some dissect plugins follow these symlinks and will return zero rows on an exFAT extraction even though the same collection works fine on APFS.

**Recommended target: extract to your internal disk** (always APFS):

```sh
mkdir -p ~/Documents/dissect-collections/$(date +%Y-%m-%d)
ditto -x -k "/path/to/Collection-<host>-<timestamp>.zip" ~/Documents/dissect-collections/$(date +%Y-%m-%d)
```

If you must use an external drive, **reformat it as APFS first** (destructive — back up anything you care about):

```sh
diskutil list | grep -B 1 -A 3 <volume-name>     # find the disk identifier (e.g. disk2s1)
sudo diskutil eraseDisk APFS <new-name> /dev/<diskNsM>
```

---

## Pairing with dissect-plugin

After extracting the collection (with `ditto`/`bsdtar`, to APFS), parse it with the matching dissect plugins:

```sh
# Point dissect at uploads/auto/ (NOT the parent dir, NOT the zip)
python3 -m dissect.target.tools.query \
  --plugin-path /path/to/dissect-plugin/plugins \
  -f knowledgec.app_usage \
  ~/Documents/dissect-collections/2026-04-11/uploads/auto -j

# Run an entire plugin namespace
python3 -m dissect.target.tools.query \
  --plugin-path /path/to/dissect-plugin/plugins \
  -f biome.all \
  ~/Documents/dissect-collections/2026-04-11/uploads/auto -j
```

**Critical:** dissect's `VelociraptorLoader` cannot open the zip directly — always **extract first**, then point at `uploads/auto/`.

---

## Privilege summary at a glance

| Privilege              | Artifact count | Examples                                                                                                  |
| ---------------------- | -------------- | --------------------------------------------------------------------------------------------------------- |
| USER (no privs needed) | 30             | Applications, FsEvents, Autostart, ChromiumBrowsers, FirefoxFiles, ShellHistoryAndSessions                |
| ROOT (admin only)      | 7              | Users, Sudoers, sudolastrun, ManagedDeviceProfile, Applist, SharedFolder, SpotlightShortCuts              |
| FDA (TCC entitlement)  | 31             | KnowledgeC, Interactions, TCC, AppleNotes, AppleMail, Biomes, iMessage, Safari, lockdown, ard, ScreenTime |
| SIP (kernel-protected) | 2              | xpdb, KeyChain (SystemKey only)                                                                           |

If you grant the collector binary FDA and run with admin privileges, **68 of 70 artifacts** will collect successfully on a typical macOS 15 system. The remaining 2 (xpdb, the SystemKey component of KeyChain) require either disabling SIP or working from a forensic image.
