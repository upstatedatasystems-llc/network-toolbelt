# Changelog

All notable changes to Network Toolbelt are documented here.

Network Toolbelt is currently a single-file Python/Tkinter desktop utility optimized for Cisco/Netmiko-based network operations. Earlier version numbers were reconstructed from project history and implementation milestones, so entries before v2.8 should be treated as summarized release history rather than formal tagged releases.

---

## v2.93 - UI Polish and Cleanups

### Summary

v2.93 implements several UI refinements to streamline the application, improve menu accessibility, remove deprecated stubs, and improve navigation consistency.

### Added

- **New File Menu Shortcuts**: Added direct shortcuts under the File dropdown menu to quickly access Generic Command Runner, Maintenance Pre/Post Runner, and Credential Manager & Library.

### Changed

- **Settings Menu Restructuring**: Moved "Toggle Dark/Light Mode" from the File menu to the Settings menu for better logical organization.
- **Help Menu Simplification**: Consolidated the "General Information" and "How-To Instructions" menu items into a single "Documentation" button that opens the help window directly.
- **Network Scanners Page Polish**:
  - Repositioned the "Back to Dashboard" button to the top left of the Network Scanners page for consistent navigation across runner modules.
  - Aligned BGP/Route Summary button to center-span the grid.
- **Dashboard Text Cleanup**: Removed the redundant "Temporary Session Only. Credentials are never saved." subtitle from the main dashboard.

### Removed

- **Scanner Stubs**: Removed non-functional scanner buttons containing "(Soon)" (Config Backup / Diff Tool, Outage Snapshot Tool, Reachability / Path Test, VLAN / Trunk Consistency, STP Health Scanner) from the Network Scanners suite landing page.
- **Page Help Buttons**: Removed the `[Help]` button from the top right of runner pages (`BaseRunnerPage`) and the top left of `Network Scanners` page.

---

## v2.92 - First-Command Delay Fix (Switch Stack Performance)

### Summary

v2.92 resolves a critical performance bug that caused ~120-second delays before the first command executed on each host when using Auto Detect Platform, most visible on Cisco C9300-48P switch stacks. The root cause was Netmiko's SSHDetect autodetect mechanism, which opens a separate SSH session and cycles through many device types — each one timing out — before giving up and falling back to cisco_ios. This has been replaced with a direct cisco_ios connection, with the existing platform probe (`show version` + `DeviceDetector.classify()`) handling device classification instead. Additionally, session prep ordering, probe timing, and execution log verbosity have been improved.

### Fixed

- **Eliminated SSHDetect autodetect (~120s delay).** When using Auto Detect Platform, the app previously opened an SSHDetect session that cycled through multiple Netmiko device types before falling back to cisco_ios. On C9300 IOS-XE switch stacks, this consistently took ~120 seconds. SSHDetect has been removed entirely; the app now connects directly as cisco_ios and relies on the platform probe (`show version` → `DeviceDetector.classify()`) for platform classification.
- **Fixed session prep running after platform probe.** `prepare_session()` (which sends `terminal length 0` and `terminal width 511`) was called after the `show version` platform probe, meaning the probe ran without paging disabled. On switch stacks with large `show version` output, this could trigger `--More--` prompts during the probe, adding delay. Session prep now runs before the platform probe inside `connect()` when `run_platform_probe=True`.
- **Fixed redundant session prep calls.** Added `session_prepped` flag to `ConnectionResult` so that external callers (Maintenance Runner, Command Runner, Scanner Engine) skip `prepare_session()` when the connection phase already handled it.
- **Reduced platform probe timing window.** Lowered `platform_probe_last_read` from 1.0s to 0.5s. The 1.0s silence-wait was unnecessarily conservative for platform classification.

### Added

- **Comprehensive connection debug logging.** Every phase of the connection process (SSH session open, enable mode, session prep, platform probe) now logs timestamped progress messages to the execution log, making delays and failures immediately visible.
- **Improved host start messages.** Host iteration messages now read `▶ Starting host [x/y] <ip>` for better readability.

### Changed

- `ConnectionResult` dataclass now includes a `session_prepped` field (default `False`) to track whether terminal setup was already performed during the connection phase.
- Reconnect path in `execute_command_with_recovery()` now respects the `session_prepped` flag to avoid redundant prep after reconnection.
- Session Log label text simplified from "Session Log (creds etc redacted)" to "Session Log".

---

## v2.91 - Correctness and Security Patch

### Summary

v2.91 addresses correctness and security issues across redaction, parsing, session handling, and command execution.

### Fixed

- Fixed SSHDetect fallback logic to properly handle autodetect failures without crashing and securely pass credentials.
- Improved command output analysis to correctly identify authorization and syntax errors.
- Enhanced parser engine to use exact section header matching, preventing cross-section data bleed.
- Updated ARP snapshot parser to correctly capture `show ip arp` outputs.
- Standardized scanner platform normalization, fixing issues where Nexus-specific parsing was ignored.
- Fixed malformed echo detection logic to properly identify token-prefix truncation.
- Improved redaction engine to use line-buffered streaming, preventing secrets from leaking across chunk boundaries.
- Added targeted redaction patterns for TACACS/RADIUS nested keys, SNMPv3 secrets, and varied password prompts.
- Hardened temp session logging with strict directory permissions and robust cleanup handlers to ensure no raw artifacts persist.
- Gracefully handle privilege escalation (enable) failures, logging the warning instead of aborting the connection.
- Renamed "Routes Advertised / Received Scanner" to "BGP/Route Summary Scanner" to clarify its summary-only capabilities.

---

## v2.9 - Diagnostics, Performance, and Lean Output

### Summary
v2.9 addresses performance bottlenecks introduced by v2.85 execution improvements, enhances UI feedback, and reduces default file footprint by shifting to lean output formats.

### Added
- Added `elapsed_seconds` and diagnostic tracking to `CommandExecutionResult`.
- Added slow-command logging and threshold warnings in status bars.
- Added explicit settings for `write_json_outputs` and `write_csv_summaries`.
- Added `save_session_logs` options ("never", "errors_only", "always") for cleaner output folders.
- Added target list scrollbars to Runner and Scanner pages.

### Changed
- Command timeout default is now 20 seconds.
- Timing last_read default is 0.75 seconds.
- Slow command threshold is 5 seconds.
- TXT-first output profile (JSON disabled by default).
- Session logs are errors-only by default.
- Compare no longer relies on full-output JSON by default.
- Export Merged TXT excludes `.json` and `.log` by default.
- Increased default app window size to 1400x850.
- Replaced basic progress states with explicit status messaging (e.g., "Connecting", "Running commands", "Slow command").

### Fixed
- Fixed Maintenance Runner crash caused by missing execution result when using cached platform probes.
- Fixed unnecessary command retries triggered by empty valid output.
- Fixed self-test mode hanging GUI on exit by returning immediately after tests.

---

## v2.85 - Netmiko Execution Engine Overhaul

### Summary

v2.85 resolves critical reliability issues with the Netmiko execution engine across Cisco IOS, IOS-XE, NX-OS, and ASA platforms. It replaces fragile string-based `show version` platform probing with an explicit execution context, implements automatic session recovery for transport failures, and introduces platform-aware session preparation to prevent output truncation and malformed command echoes.

### Added

- Added `DeviceSessionContext` and `CommandExecutionResult` data models for robust connection tracking and execution recovery.
- Added automatic transport-error recovery (e.g., reconnecting after "Socket is closed" or "Connection reset").
- Added platform-aware session preparation (e.g., executing `terminal pager 0` for ASA and `terminal length 0` for IOS).
- Added `abort_host` signal support across runners to fast-fail devices with unrecoverable connection errors.
- Added `terminal pager` to `SAFE_PREFIXES` and ASA-specific baseline command bundles.
- Added hidden developer self-tests for the execution engine (`TOOLBELT_SELF_TEST=1`).

### Changed

- Replaced implicit `show version` autodetect probing with an explicit `run_platform_probe` flag throughout the connection chain.
- Refactored `ConnectionManager.safe_send_command` into a comprehensive `execute_command_with_recovery` engine.
- Defaulted `Auto Detect` fallback to `cisco_ios` to prevent unintended probes during `Generic Command Runner` sessions.
- Modified Netmiko `ConnectHandler` to defensively fall back to `fast_cli=False` and `global_cmd_verify=False` if supported.
- Updated `MaintenanceRunnerPage` and `BaseScannerPage` to utilize cached probe outputs to reduce duplicate command execution.

---

## v2.8 - Network Toolbelt Punch / Stabilization Pass

### Summary

v2.8 is a usability, stabilization, documentation, and workflow-polish release. It updates the app identity/versioning, improves ASA command compatibility, converts target/credential mapping into an in-app page, adds output export tools, improves dashboard behavior, and tightens session cleanup/status handling.

### Added

- Added `APP_VERSION = "2.8"` and updated user-facing version references.
- Added repository-level changelog maintenance.
- Added in-app `Version Changelog` documentation section.
- Added File menu export options:
  - Export full output directory as ZIP.
  - Export text-based outputs as one merged, AI-readable TXT file.
- Added merged text export delimiters with relative file paths and file timestamps.
- Added output export sensitivity warnings.
- Added single-target credential mapping test from the Target IPs & Credentials page.
- Added target auto-population into tools when the tool target box is empty and session targets exist.
- Added direct Back to Dashboard navigation to more pages/tools.
- Added clearer dashboard session status in one line:
  - Credentials loaded
  - Session targets
  - Mapped targets
- Added documentation for export workflows, ASA fallback behavior, and in-app target/credential mapping.

### Changed

- Renamed user-facing application language to **Network Toolbelt v2.8**.
- Converted the Target IP & Credential Mapper from a popup/Toplevel window into an embedded in-app page.
- Reordered dashboard session/help buttons:
  1. Credential Manager
  2. Set Target IPs & Credentials
  3. Help & Documentation
- Improved ASA command handling by using safer command-send behavior and fallback timing mode where appropriate.
- Improved manual platform fallback so manually selected ASA/NX-OS platforms are preserved if `show version` classification fails.
- Improved run-completion status handling so tools should end with `Status: Done` and 100% progress on successful completion.
- Renamed Generic Command Runner output folders away from Cisco-specific `CiscoLogs` naming.
- Updated in-app help documentation to reflect Network Toolbelt naming and v2.8 workflows.
- Improved dark-mode readability for mapper and dialog workflows.

### Fixed

- Fixed mapper navigation cleanup signature to match app-wide navigation guard behavior.
- Fixed mapping stop behavior so a target is not left stuck in `MAPPING`.
- Fixed no-credential mapping cleanup edge case.
- Fixed command configuration newline display/save issue.
- Fixed stale documentation around ASA fallback behavior.
- Fixed stale dashboard documentation around button order.
- Fixed session-log temp cleanup paths where failed connections could leave `.tmp_` files behind.
- Fixed export behavior to skip temporary files and avoid including the export file itself when saving inside the output folder.
- Fixed maintenance compare completion progress/status behavior.

### Known Follow-Ups

- Routes Advertised / Received Scanner currently needs more complete advertised/received route command generation and parsing.
- Parser logic is still best-effort and should be expanded over time for platform-specific output.
- Multi-vendor support is a long-term goal; current command bundles and detection are still Cisco/Netmiko-centered.

---

## v2.7 - Credential Mapping Evaluation Build

### Added

- Added volatile target IP to credential mapping.
- Added dashboard credential mapping workflow.
- Added per-tool pre-run mapping prompt.
- Added mapped credential preference during tool execution.
- Added stale mapping behavior when credentials are edited or deleted.
- Added session target sharing across tools.
- Added target/mapped count display on dashboard and target panels.
- Added fallback option for mapped-credential failures.

### Changed

- Updated connection flow so mapped credentials are preferred before global credential iteration.
- Updated credential manager behavior so label-only edits preserve mappings, while username/password/secret changes stale mappings.
- Updated target panel behavior to load/save session targets.

### Fixed

- Fixed credential mapping to use stable credential IDs rather than list indices.
- Fixed stale/deleted credential handling in mapped credential connection flow.
- Fixed repeated failed-auth preference by defaulting mapped credential fallback to disabled.

---

## v2.6 - Network Toolbelt Rename / Documentation Expansion

### Added

- Added expanded in-app documentation sections.
- Added broader project positioning as **Network Toolbelt** rather than Cisco-only Toolbelt.
- Added README language describing current Cisco optimization with future multi-vendor direction.

### Changed

- Replaced most user-facing `Cisco Toolbelt` wording with `Network Toolbelt`.
- Reorganized documentation into clearer categories:
  - General information
  - Architecture
  - Security and safety
  - Credential management
  - Target mapping
  - Tool references
  - How-to workflows
  - Troubleshooting
  - Limitations

---

## v2.5 - Command Bundle Configuration

### Added

- Added `Settings -> View/Configure tool commands`.
- Added local command override JSON storage.
- Added command bundle view/edit UI by tool and platform/group.
- Added reset group and reset tool behavior.

### Changed

- Built-in tool commands became configurable without changing source code.
- Tool command overrides are persisted locally in the output directory.

### Fixed

- Added validation to prevent dangerous commands from being saved into internal tool command bundles.

---

## v2.4 - Navigation and UI Stabilization

### Added

- Added active-run navigation protection.
- Added `Clear Current Session` workflow.
- Added status/progress UI across runner pages.
- Added consistent session log labeling.
- Added redacted/raw session log visibility improvements.

### Changed

- Improved runner layout and left-panel sizing.
- Improved button placement and session controls.
- Improved stop/clear behavior for active SSH sessions.

### Fixed

- Fixed duplicate button/session-control issues introduced during earlier refactors.
- Fixed progress/status behavior in several execution paths.
- Fixed several stale UI labels and old help button behaviors.

---

## v2.3 - Scanner Suite Buildout

### Added

- Added Network Scanner Suite framework.
- Added scanner landing page.
- Added `BaseScannerPage` runner foundation.
- Added Interface Error Scanner.
- Added Port-Channel / LACP Scanner.
- Added Optics Scanner.
- Added Routing Neighbor Scanner.
- Added Log Scanner.
- Added Device Inventory Scanner.
- Added Routes Advertised / Received Scanner.
- Added future scanner stubs:
  - Config Backup / Diff Tool
  - Outage Snapshot Tool
  - Reachability / Path Test Tool
  - VLAN / Trunk Consistency Scanner
  - STP Health Scanner

### Changed

- Scanner outputs standardized around per-host reports and summary files.
- Scanner findings were structured as PASS/WARN/FAIL/INFO-style results.

---

## v2.2 - Security and Execution Foundation

### Added

- Added redacted capture behavior.
- Added command policy modes:
  - Safe Read-Only
  - Expanded Operational
  - Unsafe Allowed
- Added command output validation.
- Added unsupported command handling.
- Added safer credential attempt logging.
- Added redaction rules for common secrets, keys, SNMP strings, certificates, and related sensitive output.

### Changed

- Command execution became policy-controlled.
- Unsupported command output was classified separately from host failure.

### Fixed

- Improved authentication failure logging across multiple credential attempts.
- Improved handling of partial command failures.

---

## v2.1 - Initial GUI Toolbelt Foundation

### Added

- Added Tkinter desktop app shell.
- Added Maintenance Pre/Post Runner.
- Added Generic Command Runner.
- Added output folder structure.
- Added initial Netmiko connection handling.
- Added initial in-app documentation browser.
- Added initial session log and execution log panes.

---

## Versioning Notes

The application started as a practical internal operations tool and evolved rapidly. Some early changes were implemented before formal version tracking was introduced. The changelog above is therefore a best-effort reconstruction from the development history and current application behavior.

