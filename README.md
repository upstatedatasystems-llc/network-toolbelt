# Network Toolbelt

Network Toolbelt is a local Python/Tkinter desktop utility for network operations and engineering workflows.

It is currently optimized for Cisco network infrastructure through Netmiko, Cisco-oriented platform detection, and Cisco command bundles. The project is intentionally named **Network Toolbelt** because it is meant to grow beyond Cisco-only workflows over time.

Use Network Toolbelt to:

- Load temporary credentials once per app session.
- Save and reuse target IP/hostname lists.
- Map targets to working credential sets.
- Run controlled ad-hoc commands.
- Collect pre/post maintenance snapshots.
- Compare maintenance results.
- Run focused network scanner workflows.
- Export output for review, archiving, or AI-assisted analysis.

The app is intentionally maintained as a single-file utility, `network-toolbelt.py`, for simple internal deployment and portability.

---

## Status

Current version: **v2.9**

Current focus:

- Cisco IOS / IOS-XE, NX-OS, and ASA operations.
- Netmiko-based SSH workflows.
- Safe-by-default command execution.
- Redacted-by-default output capture.
- In-memory credential/session handling.
- Maintenance and scanner workflows.

Long-term direction:

- Broader network-vendor support.
- Stronger parser coverage.
- More scanner modules.
- More structured reporting.

---

## Requirements

- Python 3.14.2 or compatible Python 3.x.
- Tkinter.
- Netmiko.
- SSH reachability to target devices.

Install dependencies:

```bash
pip install -r requirements.txt
```

If a requirements file is not present, install Netmiko directly:

```bash
pip install netmiko
```

Run the app:

```bash
python network-toolbelt.py
```

or:

```bash
python3 network-toolbelt.py
```

---

## Important Security Notes

Network Toolbelt is designed to reduce accidental risk, but it is still a network automation tool. Use it carefully.

### Credentials

Credentials are stored in memory only.

The application does not intentionally save:

- Passwords.
- Enable secrets.
- Raw credential dictionaries.
- Persistent credential vaults.

Closing the app clears loaded credentials.

### Redaction

Redacted capture is the default.

The app attempts to redact common sensitive values from output and session logs, including:

- Passwords.
- Enable secrets.
- SNMP communities.
- TACACS/RADIUS keys.
- Pre-shared keys.
- Private keys.
- Certificates.
- Other common secret/key patterns.

Raw mode is available for troubleshooting but can expose sensitive data. Treat raw output as sensitive.

### Command Safety

Generic Command Runner uses command policy modes:

- Safe Read-Only.
- Expanded Operational.
- Unsafe Allowed.

Internal tool command bundles are intended to remain read-only. The command configuration system blocks dangerous commands from saved tool bundles.

---

## Main Workflows

### 1. Load Credentials

Open **Credential Manager** and add one or more credential sets.

Each credential set includes:

- Label.
- Username.
- Password.
- Optional enable secret.

Credential labels are used in logs and mapping tables. Passwords/secrets are not shown after entry.

---

### 2. Set Target IPs & Credentials

Open **Set Target IPs & Credentials** from the dashboard.

This page lets you:

- Enter session targets.
- Test a single IP.
- Map all targets to loaded credentials.
- Review mapping results.
- View redacted session logs.

Credential mapping helps avoid repeated failed authentication attempts when multiple credential sets are loaded.

Mapping statuses include:

- `UNMAPPED`
- `MAPPING`
- `MAPPED`
- `FAILED`
- `STALE`
- `STOPPED`

Mappings are in-memory only and are cleared when the app closes.

---

### 3. Run Generic Commands

Open **Generic Command Runner**.

Use it to run safe ad-hoc commands such as:

```text
show version
show ip interface brief
show interfaces description
show logging last 100
```

Commands are validated against the selected command policy before execution.

---

### 4. Run Maintenance Pre/Post Checks

Open **Maintenance Pre/Post Runner**.

Typical workflow:

1. Enter a Run ID.
2. Run Pre-Checks.
3. Perform maintenance.
4. Run Post-Checks using the same Run ID.
5. Run Compare.
6. Review summaries and per-host reports.

The compare engine can flag changes such as:

- Config hash changes.
- ARP/MAC count changes.
- EIGRP/OSPF/BGP neighbor changes.
- Interface errors or drops.
- High-severity logs or link-flap indicators.

---

### 5. Run Network Scanners

Open **Network Scanners**.

Implemented scanners include:

- Interface Error Scanner.
- Port-Channel / LACP Scanner.
- Optics Scanner.
- Routing Neighbor Scanner.
- Log Scanner.
- Device Inventory Scanner.
- Routes Advertised / Received Scanner.

Future/placeholder scanners include:

- Config Backup / Diff Tool.
- Outage Snapshot Tool.
- Reachability / Path Test Tool.
- VLAN / Trunk Consistency Scanner.
- STP Health Scanner.

Scanner parsers are best-effort. Review raw/redacted output before making operational decisions.

---

### 6. Export Output

From the File menu, export output in two ways:

1. **Export Output Folder as ZIP**
   - Preserves folder structure.
   - Skips temporary files.
   - Useful for archiving or sharing a complete run folder.

2. **Export Text Outputs as Merged TXT**
   - Merges `.txt`, `.csv`, and `.md` files. Intentionally excludes `.json`, `.log`, and `.tmp_*` files to reduce noise and prevent inclusion of sensitive raw session artifacts.
   - Adds clear BEGIN/END delimiters per file.
   - Designed to be readable by humans and easy for AI tools to analyze.

Exports may contain sensitive data if raw capture was used. Review before sharing.

---

## Dashboard Layout

The dashboard has two main columns.

### Tools

- Generic Command Runner.
- Maintenance Pre/Post Runner.
- Network Scanners.

### Session & Help

- Credential Manager.
- Set Target IPs & Credentials.
- Help & Documentation.

Dashboard status shows:

```text
Credentials loaded: N   Session targets: N   Mapped targets: X/N
```

---

## Output Structure

Default output folder:

```text
toolbelt-output/
```

Typical structure:

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

Credentials and credential mappings are not saved to disk.

---

## Command Configuration

Open:

```text
Settings -> View/Configure tool commands
```

This lets you view and edit built-in tool command bundles.

Command overrides are saved locally under the output directory as:

```text
tool_command_overrides.json
```

This file contains command strings only. It should never contain credentials.

---

## Platform Support

Current first-class platform focus:

- Cisco IOS / IOS-XE.
- Cisco NX-OS.
- Cisco ASA.

The app can attempt auto-detection, or you can manually select a platform. Manual selection is recommended when auto-detect is unreliable.

ASA support includes safer command-send fallback behavior for prompt/pattern issues during `show version` and other command execution.

---

## Known Limitations

- Parsers are best-effort.
- Output formats vary significantly by platform and OS version.
- Unsupported commands are expected in mixed environments.
- Auto-detect may misclassify devices.
- Redaction may not catch every possible secret.
- Raw capture can expose sensitive data.
- Large command outputs can produce large files.
- BGP route output can be very large.
- Stopping a run may wait for Netmiko timeout/disconnect behavior.
- Routes Advertised / Received Scanner needs further expansion before it is a full route-analysis tool.
- Multi-vendor support is not fully implemented yet.

---

## Recommended First Test

Before using broadly, test with one known-safe device.

1. Start the app.
2. Add one credential set.
3. Open Set Target IPs & Credentials.
4. Add one test target.
5. Test Single IP or Start Credential Mapping.
6. Open Generic Command Runner.
7. Confirm target auto-populates.
8. Run:

```text
show version
```

9. Confirm output files are written.
10. Confirm progress ends at 100% and status shows Done.

---

## Development Notes

Run a syntax check after edits:

```bash
python -m py_compile network-toolbelt.py
```

Before committing a release:

- Confirm app launches.
- Confirm dashboard version/title are correct.
- Test Credential Manager.
- Test Target IP & Credential Mapper.
- Test one Generic Command Runner run.
- Test one Maintenance Pre/Post run.
- Test at least one scanner.
- Test ZIP export.
- Test merged TXT export.
- Confirm no `.tmp_` session files remain after runs.

Do not commit raw output files or sensitive device logs.

---

## Project Files

Important files:

```text
network-toolbelt.py
README.md
CHANGELOG.md
system_manifest.md
requirements.txt
```

The application itself currently lives in:

```text
network-toolbelt.py
```

The user-facing project name is:

```text
Network Toolbelt
```

---

## Disclaimer

Network Toolbelt is an internal operational utility. It should be used by qualified network personnel who understand the devices, commands, and environments being accessed.

Review command output and findings carefully before making operational decisions.
