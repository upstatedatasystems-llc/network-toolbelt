# Changelog

All notable changes to Network Toolbelt are documented here.

Network Toolbelt is currently a modular desktop utility (migrating to PySide6). Earlier version numbers were reconstructed from project history and implementation milestones, so entries before v2.8 should be treated as summarized release history rather than formal tagged releases.

---

## v4.0.0-alpha2 - PySide6 UI Migration (Milestones 2 & 3)

### Summary

v4.0.0-alpha2 completes Milestones 2 & 3 of the Network Toolbelt PySide6 UI migration. This adds full PySide6 support for the **Maintenance Pre/Post Runner** and the **Network Scanner Suite** (Interface Errors, Port-Channel / LACP, Routing Neighbors, Logs, Device Inventory, Optics, and BGP/Route Summary).

### Added

- **Maintenance Pre/Post Runner (`MaintenanceRunnerPage`)**: Full PySide6 implementation supporting pre-check snapshot capture, post-check snapshot capture, compare engine execution, and report output generation.
- **Maintenance Core Module (`network_toolbelt/core/maintenance.py`)**: Extracted snapshot builder, output parsers (interfaces, logs, routes), interface/log/routing analyzers, and compare engine.
- **Network Scanner Suite (`network_toolbelt/ui/pages/scanner_pages.py`)**: PySide6 runner pages for all 7 network scanners built on a common `BaseScannerPage` foundation.
- **Scanner Landing Page (`network_toolbelt/ui/pages/scanner_landing_page.py`)**: Modern dashboard grid for selecting and navigating to scanner tools.
- **Scanners Core Module (`network_toolbelt/core/scanners.py`)**: Extracted scanner definitions, scanner run configs, host result models, scanner engine, and report summary generators.

---

## v4.0.0-alpha1 - PySide6 UI Migration (Milestone 1)

### Summary

v4.0.0-alpha1 completes Milestone 1 of the Network Toolbelt UI migration from Tkinter to PySide6. The application is restructured as a modular Python package while preserving the legacy Tkinter app as a fallback.

### Added

- **PySide6 Application Framework**: Restructured the app into a package `network_toolbelt` with a modern modular layout.
- **UI Event Bridge**: Introduced a thread-safe QObject signal bridge (`UIEventBridge`) for routing log, status, progress, and UI state events from worker threads to the main Qt thread.
- **PySide6 Pages**:
  - `LandingPage`: Dashboard home page showing session mapping status.
  - `CredentialManagerLibraryPage`: Complete manager page for volatile credentials and SSH target mappings.
  - `CommandRunnerPage`: Generic Command Runner vertical slice supporting policy execution and live logging.
  - **Tool Stubs**: Temporary placeholder pages for deferred components.
- **Dark Theme Styling**: Basic dark/light styling via QSS stylesheet.

### Changed

- **Package Migration**: Extracted core configuration, credential mapping, redaction rules, and netmiko device connection management into modular package files.

---

## v3.32 - Comprehensive Parallel Execution

### Summary

v3.32 expands the global parallel sessions configuration to cover all primary network execution mechanisms, including the **Generic Command Runner** and the **Credential Mapper**. Users can configure limits for all four major network execution engines inside the global settings configuration dialog.

### Added

- **Generic Command Runner Parallelization**: Integrated a concurrent ThreadPoolExecutor execution flow matching the bounded execution pattern.
- **Credential Mapper Parallelization**: Added parallel credential mapping capability allowing multiple target hosts to be checked concurrently.
- **Extended Settings Dialog**: Added configuration fields to global Settings -> "Parallel sessions..." for Generic Command Runner and Credential Mapper (1-20 limits, default 3).

### Changed

- **Self-tests Updates**: Updated and expanded self-test validation suites to cover the new concurrency settings.

---

## v3.31 - Global Concurrency, Tools Menu, and CSV Export

### Summary

v3.31 transitions the concurrency controls from per-tool widgets into a global settings dialog. It introduces a new "Tools" dropdown menu between File and Settings to clean up main menu options, and adds a direct "Session Export: CSV Summary File" feature under Export Operations to easily export CSV summaries from run sessions.

### Added

- **Global Concurrency Settings Dialog**: Added Settings -> "Parallel sessions..." which opens a window to configure the concurrency limits globally for the Maintenance Pre/Post Runner and Scanners.
- **"Tools" Dropdown Menu**: A dedicated menu containing Generic Command Runner, Maintenance Pre/Post Runner, Network Scanners, SNMP OID Scanner, SSH Credential Manager, and SNMP Credential Manager.
- **"Session Export: CSV Summary File"**: Added File -> Export Operations -> "Session Export: CSV Summary File" to copy and export the primary `.csv` summary file (such as `command_outputs_wide.csv`, `summary.csv`, or `scanner_summary.csv`) directly from a selected run session.

### Changed

- **Clean Sidebar Layouts**: Removed the local `ConcurrentHostsControl` widget from all sidebar panels.
- **Global Concurrency Execution**: Tools fetch concurrency limits globally from `settings.concurrency_maintenance` and `settings.concurrency_scanners`.

---

## v3.3 - Concurrent Host Execution

### Summary

v3.3 introduces concurrent host execution across all SSH-based tools in Network Toolbelt. Every runner and scanner page now includes a **Concurrent Hosts** spinbox control that allows parallelizing target host connections using a bounded `ThreadPoolExecutor`. Each host gets its own independent Netmiko session — no sessions are shared across threads. A new thread-safe `ActiveConnectionRegistry` enables clean teardown of all active connections on user-initiated STOP requests. Sequential execution is preserved when concurrency is set to 1.

### Added

- **`ConcurrentHostsControl` Widget**: Reusable `tk.LabelFrame` with a `Spinbox` (range 1–20, default 3) for selecting the number of concurrent host connections. Integrated into Maintenance Pre/Post Runner, all 7 SSH Scanner pages (via `BaseScannerPage`), and the Credential Mapper.
- **`ActiveConnectionRegistry` Class**: Thread-safe connection tracking with `register()`, `unregister()`, and `disconnect_all()` methods, all protected by `threading.Lock()`. Enables clean multi-connection teardown on STOP.
- **`format_concurrent_status()` Helper**: Returns human-readable status bar messages during concurrent execution (e.g., `"Running — 5/10 hosts completed, 3 active"`).
- **Bounded ThreadPoolExecutor Host Loop**: All concurrent runners use `concurrent.futures.wait(return_when=FIRST_COMPLETED)` to limit active tasks to `max_workers`, submitting new hosts as previous ones complete.
- **Host-Prefixed Log Output**: Concurrent execution log messages are prefixed with `[host_ip]` for clear per-host visibility in the shared execution log pane.
- **SNMP Scanner Concurrency**: `SnmpOidScannerPage` uses the same `ThreadPoolExecutor` pattern with a default concurrency of 5.
- **Credential Mapper Concurrency**: Target credential mapping uses bounded concurrency (default 3) to protect AAA (TACACS+/RADIUS) servers from lockout.

### Changed

- **`BaseRunnerPage`**: Now initializes `self.active_conns` from the controller's `ActiveConnectionRegistry`. `stop_execution()` and `stop_and_clear_for_navigation()` both call `active_conns.disconnect_all()` to sever all concurrent connections.
- **`NetworkToolbeltApp`**: Instantiates a shared `ActiveConnectionRegistry` on `self.active_conns` during app initialization.
- **Sequential Pathway Preservation**: When `concurrency == 1`, all tools route through the original sequential execution pathway without modifications.

---

## v3.2 - UI Status Prefixes and Wide CSV Outputs

### Summary

v3.2 introduces a standardized dynamic status prefix and improved progress tracking for the Credential Manager. It also adds a new wide-format CSV output (`command_outputs_wide.csv`) to the Generic Command Runner that streams command outputs per host, with unique column headers for duplicate commands, formula safety protection, and a suite of self-tests.

### Added

- **UI Status Prefix**: Added a visible static `Status:` label prefix before status messages on `BaseRunnerPage` and `CredentialManagerLibraryPage`.
- **Wide-Format CSV**: Dynamically streams `command_outputs_wide.csv` on the fly for completed and skipped hosts in Generic Command Runner sessions.
- **Formula Safety Protection**: Escapes metadata/error fields starting with `=`, `+`, `-`, or `@` with a leading single quote to prevent spreadsheet formula injection. Command outputs are preserved raw after redaction.
- **Credential mapping status tracking**: Progress callback correctly counts finished hosts and shows the active mapping target.
- **Wide CSV Self-Tests**: Added tests inside `_run_execution_self_tests()` covering status formatting, header generation, row formatting, and redaction verification.

---

## v3.1 - SNMP OID Scanner Integration

### Summary

v3.1 introduces a new SNMP OID Scanner page and SNMP Credential Manager page utilizing PySNMP 7. This allows read-only OID scanning over a list of host targets using multiple volatile credential types (SNMPv1, SNMPv2c, and SNMPv3) with dynamic credential testing/probing. Redactor rules were corrected and expanded to securely mask SNMP community configurations and SNMPv3 keys. Added spec-based PyInstaller build configuration with automated validation script.

### Added

- **SNMP OID Scanner Page**: Direct runner page allowing target inputs, OIDs (numeric validation), version selection (Dynamic / Auto or Force mode), and dynamic order prioritization.
- **SNMP Credential Manager Page**: Full CRUD manager for volatile SNMPv1, SNMPv2c, and SNMPv3 credentials. Password and protocol keys are masked and safely preserved on edit.
- **Dynamic Credential Probing**: Automatically probes credentials against `sysObjectID.0` (1.3.6.1.2.1.1.2.0) and `sysUpTime.0` (1.3.6.1.2.1.1.3.0) to dynamically select the best working configuration.
- **PyInstaller spec-based build path**: Hidden imports collect submodules for `pysnmp`, `pyasn1`, and `cryptography` automatically for standalone releases.
- **Build script (`build.ps1`)**: Handles PyInstaller spec execution, portable ZIP packaging, and post-build verification tests.

### Fixed

- **Redactor regex replacements**: Corrected replacement backreferences in `tacacs_radius_nested`, `snmpv3_auth_priv`, and `snmpv3_auth_only` rules where control characters were used instead of regex backreferences.
- **Expanded SNMP Redaction**: Added rules to securely mask community strings and authentication/privacy keys from captured config files and logs.

---

## v2.94 - Export Overhaul and Run Filtering

### Summary

v2.94 introduces a comprehensive overhaul of the file export system. All export options are now grouped under a nested "Export Operations" submenu. Added three new run session export features allowing filtering by Run ID, including zipping single sessions, merging single sessions, and extracting host command outputs only.

### Added

- **Export Operations Submenu**: Grouped all export actions under a single, nested `File -> Export Operations` cascade menu.
- **Run Session Selection Dialog**: Added a high-quality dialog using `ttk.Treeview` listing all completed runs inside the output directory sorted by modification time.
- **Export Selected Run (ZIP)**: Bulk exports all generated logs and outputs of a single chosen run session as a ZIP.
- **Export Selected Run (Unified TXT)**: Merges all output files belonging to a chosen run session into one text file.
- **Export Command Outputs Only**: Extracts only the host command execution outputs (excluding internal logs/summaries) from a chosen run session, presenting them cleanly sorted by host with clear border dividers.

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

