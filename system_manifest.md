# Network Toolbelt System Manifest

**Version:** 3.0  
**Primary Application File:** `network-toolbelt.pyw`  
**Project Name:** Network Toolbelt  
**Current Focus:** Cisco/Netmiko-optimized network operations utility  
**Long-Term Direction:** Broader multi-vendor network operations toolkit  
**Target Runtime:** Python 3.14.2 or compatible Python 3.x  
**GUI Framework:** Tkinter  
**Network Automation Library:** Netmiko  
**Deployment Model:** Single-file desktop utility; also distributable as a portable Windows folder via PyInstaller  

---

## 1. Executive Summary

Network Toolbelt is a locally run Python/Tkinter desktop application for network operations and engineering workflows.

It is currently optimized for Cisco network infrastructure through Netmiko, Cisco platform detection, and Cisco-oriented command bundles. The app is intentionally named **Network Toolbelt** because the long-term design goal is broader than Cisco-only operations. Future support can be added for additional vendors by extending platform detection, command bundles, parsers, and scanner definitions.

The application is designed to help network engineers:

- Load temporary credentials once per session.
- Save and reuse session target lists.
- Map target IPs/hostnames to working credential sets.
- Run safe ad-hoc commands.
- Collect maintenance pre/post snapshots.
- Compare maintenance results.
- Run focused scanner workflows.
- Export outputs for review, archiving, or AI-assisted analysis.

Network Toolbelt follows two main safety principles:

1. **Safe by default:** read-only command behavior is preferred and enforced where practical.
2. **Redacted by default:** sensitive output is scrubbed from logs/output where practical.

---

## 2. Application Scope

### In Scope

Network Toolbelt currently supports:

- SSH-based device access through Netmiko.
- Cisco IOS / IOS-XE, NX-OS, and ASA workflows.
- Volatile credential management.
- Target-to-credential mapping.
- Generic command execution with policy controls.
- Maintenance pre/post capture and comparison.
- Scanner-based operational checks.
- Local output generation in text, JSON, and CSV.
- Output exports as ZIP or merged text.

### Out of Scope

The current application does not attempt to be:

- A full network source of truth.
- A persistent credential vault.
- A telemetry platform.
- A replacement for monitoring systems.
- A configuration-management system.
- A guaranteed parser for every Cisco OS/version/output format.
- A multi-user web application.
- A full multi-vendor automation framework yet.

---

## 3. Runtime Environment and Dependencies

### Required

- Python 3.14.2 or compatible modern Python 3.x.
- Tkinter.
- Netmiko.

### Typical Installation

```bash
pip install -r requirements.txt
python network-toolbelt.pyw
```

If no requirements file is present, the minimum third-party dependency is typically:

```bash
pip install netmiko
```

### Platform Notes

Tkinter behavior and styling can vary slightly by OS. On macOS, system Tk warnings may appear depending on Python/Tk build, but the app should remain functional.

---

## 4. Deployment Model: Single-File Rule

Network Toolbelt is intentionally implemented as a single primary Python file:

```text
network-toolbelt.pyw
```

The app remains single-file for portability. This lets a network engineer copy, test, back up, and run the utility without packaging a Python module tree.

### Benefits

- Easy to distribute internally.
- Easy to back up before major edits.
- Low packaging overhead.
- Good fit for a small internal tool.

### Tradeoffs

- The file is large.
- Shared classes affect many pages/tools.
- Refactors require extra caution.
- Documentation, UI, parser logic, and execution logic live together.
- Strong internal organization is important to prevent the file from becoming hard to maintain.

### Portable Windows Build (PyInstaller)

Network Toolbelt can also be distributed as a portable Windows folder built with PyInstaller `--onedir`. This bundles the Python runtime, Netmiko, Paramiko, Cryptography, TextFSM, NTC Templates, Tkinter/Tcl, and all other dependencies into a standalone folder.

Build artifacts:

- Build script: `build-windows.ps1`
- Spec file: `NetworkToolbelt.spec` (committed for repeatable builds)
- Release artifact: `dist\NetworkToolbelt-portable.zip`
- Executable: `dist\NetworkToolbelt\NetworkToolbelt.exe`

Output paths:

- Source mode: `<repo folder>\toolbelt-output`
- Packaged EXE mode: `%USERPROFILE%\Documents\NetworkToolbelt\toolbelt-output`

The app detects whether it is running from source or as a packaged EXE using `sys.frozen` and adjusts output paths accordingly. The `_configure_frozen_environment()` function sets the `NET_TEXTFSM` environment variable to point to bundled NTC template files.

PyInstaller `--onedir` is preferred over `--onefile` because it starts faster, is easier to debug, and is generally less suspicious to endpoint security.

---

## 5. High-Level Code Organization

Although the app is one file, it is organized into logical layers.

### 5.1 Imports

Standard library imports, Tkinter imports, and Netmiko imports.

If Netmiko is missing, the app shows a Tkinter dependency error and exits.

### 5.2 Data Models

Dataclasses and enums define the app’s shared structures.

Important types include:

- `ConnectionStatus`
- `CommandStatus`
- `LogicalPlatform`
- `CommandPolicyMode`
- `CommandDecision`
- `CommandResult`
- `ConnectionResult`
- `CompareFinding`
- `ScannerRunConfig`
- `ScannerHostResult`
- `ScannerDefinition`
- `CredentialRecord`
- `TargetCredentialMapping`

### 5.3 Settings and Constants

Important global settings include:

- `APP_VERSION`
- `AppSettings`
- output directory
- command timeout
- command policy mode
- capture mode
- current theme

### 5.4 Credential Storage

`CredentialStore` manages credential records.

Credentials are:

- Stored in memory only.
- Cleared when the app closes.
- Not written to disk by the application.
- Displayed only in safe form.

### 5.5 Target/Credential Mapping

`TargetCredentialMapStore` manages the current session’s target list and target-to-credential mappings.

Mappings are:

- Stored in memory only.
- Based on stable credential IDs.
- Marked stale when credentials are edited/deleted.
- Used to reduce repeated failed authentication attempts.

### 5.6 Command Policy and Command Bundles

`CommandPolicy` controls ad-hoc user commands.

`ToolCommandManager` manages configurable internal tool command bundles.

Command overrides are saved locally as command strings only. They must never include credentials or credential mappings.

### 5.7 Redaction

`Redactor` applies regex-based redaction rules to output and session logs.

Redaction targets common sensitive patterns such as:

- Passwords.
- Enable secrets.
- SNMP communities.
- TACACS/RADIUS keys.
- IPSec pre-shared keys.
- OSPF authentication keys.
- Crypto/private keys.
- Certificates.
- Generic secret/key lines.

### 5.8 Device Detection and Connection Management

`DeviceDetector` classifies devices using `show version` output where possible.

`ConnectionManager` wraps Netmiko connection behavior and handles:

- Manual platform selection.
- Auto detect platform.
- Authentication and timeout errors.
- Enable-mode attempts.
- Safe command sending.
- Mapped credential preference.
- Global credential fallback.

### 5.9 Parser and Analyzer Layer

Parser logic is best-effort and platform-sensitive.

Important classes include:

- `ParserHelpers`
- `ParserEngine`
- `InterfaceAnalyzer`
- `LogAnalyzer`
- `RoutingAnalyzer`
- `SnapshotBuilder`
- `CompareEngine`

### 5.10 UI Layer

The UI is composed of Tkinter pages and shared components.

Important classes include:

- `DocumentationWindow`
- `ToolCommandConfigWindow`
- `CredentialManagerPage`
- `CredentialStatusPanel`
- `TargetPanel`
- `BaseRunnerPage`
- `MaintenanceRunnerPage`
- `CommandRunnerPage`
- `LandingPage`
- `ScannerLandingPage`
- `BaseScannerPage`
- `TargetCredentialMapperPage`
- `NetworkToolbeltApp`

---

## 6. Security Model

### 6.1 Credential Safety

Credentials are volatile.

The app does not intentionally write the following to disk:

- Passwords.
- Enable secrets.
- Raw credential dictionaries.
- Persistent credential stores.

Credential displays are safe-form only. Passwords and enable secrets are not shown after entry.

### 6.2 Mapping Safety

Target-to-credential mappings store:

- Host/IP.
- Credential ID.
- Credential label.
- Username.
- Mapping status.
- Last tested time.
- Platform metadata where available.
- Attempt result history.

Mappings do not store:

- Passwords.
- Enable secrets.
- Raw credential dictionaries.
- Persistent credential material.

Mappings are cleared when the app closes.

### 6.3 Redacted Capture

Redacted capture is the default mode.

The redactor attempts to scrub sensitive values before output is written or displayed where applicable.

Raw mode is available, but raw output should be treated as sensitive.

### 6.4 Command Safety

Generic Command Runner is controlled by command policy modes:

- Safe Read-Only.
- Expanded Operational.
- Unsafe Allowed.

Internal tool command bundles are also validated to prevent dangerous command overrides.

### 6.5 Filename Safety

`FilenameSafety` protects output paths by sanitizing:

- Run IDs.
- Host labels.
- File names.

This reduces accidental path traversal or invalid filesystem characters.

---

## 7. Threading and UI Queue Model

Tkinter must not be updated directly from background threads.

Network Toolbelt uses a queue-based UI update pattern:

1. User clicks RUN.
2. UI validates inputs.
3. UI disables run controls.
4. Worker thread starts.
5. Worker thread performs SSH work and file output.
6. Worker thread sends UI messages into a `queue.Queue`.
7. Tkinter page polls the queue using `.after(...)`.
8. Main thread updates logs, buttons, status, and progress safely.

This pattern is used by runner pages, scanner pages, and mapper workflows.

---

## 8. Core Workflows

### 8.1 Credential & Target Setup (Credential Manager & Library)

1. Open **Credential Manager & Library** from the dashboard.
2. Under **Add / Edit Credential**, fill in the label, username, and password/secret, then click **Save Credential**.
3. Under **Target IP & Platform Mapping**, enter the targets in the targets list.
4. Adjust fast mapping platform or probe settings if desired, then click **Start Credential Mapping** to verify access.
5. Review library credentials in the **Credentials Library** list, and mapping progress in the mapping table and logs.
6. When navigating to other tools, the mapped targets and credentials will auto-populate as needed.

### 8.3 Generic Command Run

1. Open Generic Command Runner.
2. Confirm targets and credentials.
3. Enter commands.
4. Confirm command policy.
5. Run.
6. Review output.

### 8.4 Maintenance Pre/Post

1. Open Maintenance Pre/Post Runner.
2. Enter Run ID.
3. Run Pre-Checks.
4. Perform maintenance.
5. Run Post-Checks using the same Run ID.
6. Run Compare.
7. Review summary and per-host reports.

### 8.5 Scanner Run

1. Open Network Scanners.
2. Choose scanner.
3. Enter Run ID.
4. Confirm targets/options.
5. Run.
6. Review summary and per-host outputs.

### 8.6 Output Export

1. Open File menu.
2. Choose ZIP export or merged TXT export.
3. Review sensitivity warning.
4. Choose destination.
5. Share/store output carefully.

---

## 9. Output Structure

Default output location (source mode):

```text
toolbelt-output/
```

Default output location (packaged EXE mode):

```text
Documents\NetworkToolbelt\toolbelt-output\
```

The output directory can be changed at runtime via Settings → Change Output Directory.

Typical subfolders:

```text
toolbelt-output/
├── Maintenance_Runner/
├── Command_Runner/
├── Scanners/
└── tool_command_overrides.json
```

### Maintenance Runner

```text
Maintenance_Runner/<run_id>/
├── pre/
├── post/
└── compare/
```

### Command Runner

```text
Command_Runner/CommandRunner-<timestamp>/
```

### Scanners

```text
Scanners/<scanner_name>/<run_id>/
├── index.txt
├── scanner_summary.txt
├── scanner_summary.csv
├── scanner_summary.json
└── hosts/
```

### Exports

Exports are user-selected save files and can include:

- ZIP archive of output folder.
- Merged text export containing text-based output files.

---

## 10. Implemented Tools

### 10.1 Credential Manager & Library

Unified inline in-app page that combines credential and target mapping workflows:

- **Add / Edit Credential:** Form to input and save volatile credentials.
- **Credentials Library:** Displays all active session credentials and allows deleting or clearing them.
- **Target IP & Platform Mapping:** Inline multiline text editor to input targets, configure platforms, and initiate/stop mapping.
- **Mapped Host List:** Interactive treeview display showing host, status, mapped credential, username, detected platform, and mapping result logs.

### 10.3 Generic Command Runner

Runs ad-hoc command lists across targets under command policy control.

### 10.4 Maintenance Pre/Post Runner

Captures pre/post device snapshots and compares results.

### 10.5 Network Scanner Suite

Implemented scanner pages include:

- Interface Error Scanner.
- Port-Channel / LACP Scanner.
- Optics Scanner.
- Routing Neighbor Scanner.
- Log Scanner.
- Device Inventory Scanner.
- Routes Advertised / Received Scanner.

Future scanner stubs include:

- Config Backup / Diff Tool.
- Outage Snapshot Tool.
- Reachability / Path Test Tool.
- VLAN / Trunk Consistency Scanner.
- STP Health Scanner.

---

## 11. Known Limitations

- Parsers are best-effort.
- Cisco output varies by platform, OS version, privilege level, feature set, and VRF.
- Auto-detect can misclassify devices.
- Some commands may be unsupported on some platforms.
- Redaction may not catch every secret.
- Raw mode may expose sensitive data.
- Large route outputs can produce large files and slow UI responsiveness.
- Stopping a run may wait for Netmiko timeout/disconnect behavior.
- Routes Advertised / Received Scanner is not yet a full route-analysis tool.
- Multi-vendor support is not fully implemented yet.

---

## 12. Developer Guide

### 12.1 Adding a Scanner

To add a scanner:

1. Define a parser function:

```python
def parse_my_scanner(platform: str, outputs: dict, options: dict):
    return parsed, findings, warnings
```

2. Define a `ScannerDefinition`.

```python
MY_SCANNER_DEF = ScannerDefinition(
    name="My Scanner",
    internal_key="my_scanner",
    description="What it checks.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": ["show example"],
        "NEXUS": ["show example"]
    },
    parser_callback=parse_my_scanner,
    report_callback=None
)
```

3. Create a page class inheriting from `BaseScannerPage`.

4. Add the page to the app frame registry.

5. Add a button to `ScannerLandingPage`.

6. Update documentation and changelog.

### 12.2 Adding a Platform

To add platform support:

1. Add or update `LogicalPlatform`.
2. Update `DeviceDetector`.
3. Update `PLATFORM_COMMAND_SET_MAP`.
4. Add command bundles.
5. Update scanner command definitions.
6. Add parser handling where output format differs.
7. Test with one device first.

### 12.3 Adding a Command Bundle

To add or update command bundles:

1. Keep commands read-only by default.
2. Validate with `ToolCommandManager.validate_commands()`.
3. Avoid disruptive commands.
4. Test on one device.
5. Document the change.

---

## 13. Troubleshooting for Developers

### UI Freezes

Likely cause:
A blocking operation is running on the Tkinter main thread.

Fix:
Move network/file-heavy work into a worker thread and update UI through the queue.

### Tkinter Runtime Errors from Threads

Likely cause:
Worker thread directly updated a widget.

Fix:
Use `enqueue(...)` and process UI updates on the main thread.

### Parser Crashes

Likely cause:
Parser assumed a command existed or output matched one platform.

Fix:
Use `outputs.get("command", "")`, defensive parsing, and `ParserHelpers`.

### Unsupported Commands

Likely cause:
Command is not valid on the platform or privilege level.

Fix:
Classify as `COMMAND_UNSUPPORTED`, adjust command bundle, or use platform-specific commands.

### Credential Mappings Look Wrong

Likely causes:
Credential was edited/deleted, targets changed, or mapping is stale.

Fix:
Re-run mapping for the affected targets.

---

## 14. Repository and Git Notes

The repository is expected to use the Network Toolbelt project identity.

Expected repository context:

```text
Primary branch: main
Primary app file: network-toolbelt.pyw
Build script: build-windows.ps1
PyInstaller spec: NetworkToolbelt.spec
Release artifact: dist\NetworkToolbelt-portable.zip
```

If using a dedicated GitHub SSH alias, confirm the remote and identity before committing:

```bash
git remote -v
git config --local user.name
git config --local user.email
ssh -T git@github-upstate
```

Do not commit output files containing raw logs or sensitive device output.

---

## 15. Maintenance Checklist

Before a release or major commit:

```bash
python -m py_compile network-toolbelt.pyw
```

Then verify:

- App launches.
- Dashboard opens.
- Version/title are correct.
- Credential Manager & Library page opens and works.
- Generic Command Runner works on one safe device.
- Maintenance Pre/Post works on one safe device.
- At least one scanner runs on one safe device.
- Output export works.
- No `.tmp_` files are left behind after runs.
- README, CHANGELOG, and system manifest are updated.

---

## 16. Current Version Summary

Network Toolbelt v3.0 includes:

- Eliminated SSHDetect autodetect, which caused ~120-second delays on C9300 IOS-XE switch stacks by cycling through many device types before falling back to cisco_ios. The app now connects directly as cisco_ios and relies on the platform probe for classification.
- Moved `prepare_session()` (terminal length/width setup) to run before the platform probe inside `connect()`, preventing `--More--` prompts during `show version` on devices with large output.
- Added `session_prepped` flag to `ConnectionResult` to prevent redundant terminal setup calls across Maintenance Runner, Command Runner, and Scanner Engine.
- Reduced `platform_probe_last_read` from 1.0s to 0.5s, cutting the mandatory silence-wait overhead during platform detection.
- Added comprehensive per-phase connection debug logging with timing for SSH, enable, session prep, and platform probe phases.
- Improved host start messages to `▶ Starting host [x/y] <ip>` for better readability.
- Simplified Session Log label from "Session Log (creds etc redacted)" to "Session Log".
- Reconnect path now respects `session_prepped` to avoid duplicate prep after transport-error recovery.
