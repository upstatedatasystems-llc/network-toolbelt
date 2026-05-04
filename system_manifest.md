# Network Toolbelt System Manifest
**Version:** 2.1
**Primary File:** `cisco_toolbelt.py`
**Target Environment:** Python 3.14.2 (or compatible 3.x), Tkinter (System/OS native), Netmiko.

---

## 1. Executive Summary & Purpose
The Network Toolbelt is a locally deployed, single-file Python desktop utility explicitly designed for network operations and engineering. It provides an intuitive Graphical User Interface (GUI) via Tkinter to execute Secure Shell (SSH) driven workflows against Cisco network infrastructure. 

**Key Capabilities:**
- **Maintenance Pre/Post Runner:** Collects device state snapshots before and after a change window and performs automated diffs (e.g., config hashes, ARP/MAC counts, routing neighbors).
- **Generic Command Runner:** Executes safe, ad-hoc `show` commands across bulk targets with parallel processing.
- **Network Scanner Suite:** A framework for executing hardcoded, read-only operational checks (e.g., Interface Errors, Optics, BGP/OSPF states) and parsing the results into structured JSON/CSV reports.

This tool operates under a strict **Safe-by-Default** and **Redacted-by-Default** philosophy. It is designed to prevent destructive commands from being run accidentally and ensures credentials/secrets are scrubbed from local logs.

---

## 2. Runtime Environment & Dependencies
The application was designed to be as portable as possible, relying heavily on the Python standard library to ensure it can be dropped onto an engineer's workstation without a complex virtual environment setup.

### Core Dependencies
1. **Python 3.x:** Specifically targeted for 3.14.2, but compatible with standard Python 3.9+ environments.
2. **Tkinter:** The standard GUI library for Python. (Note: On macOS, system Tk deprecation warnings may appear, but the application remains fully functional).
3. **Netmiko:** The *only* required third-party PIP package (`pip install netmiko`). Netmiko handles all SSH connection management, device type templating, and privilege escalation (Enable mode).

### Portability Constraint (The Single-File Rule)
A critical architectural constraint of this application is its **Single-File Deployment**. The entire application—including data models, parsers, Tkinter UI elements, threading logic, and documentation—lives within `cisco_toolbelt.py`. 
*Why?* To allow network engineers to easily share the tool via a simple script transfer without needing to package, build, or manage complex module hierarchies.

---

## 3. Software Architecture & Structure

The codebase is structured sequentially to overcome the limitations of a single-file script. A junior engineer reading the file top-to-bottom will encounter the following logical layers:

### A. Data Models & Constants (`@dataclass`)
The script begins with strictly typed data models using `dataclasses`.
- `ConnectionStatus` / `CommandStatus`: Enums tracking the state of tasks.
- `CommandPolicyMode`: Enum tracking the security context (`SAFE_READ_ONLY`, `EXPANDED_OPERATIONAL`, `UNSAFE_ALLOWED`).
- `CommandDecision` / `CommandResult` / `ConnectionResult`: Objects passed between worker threads and the main UI thread.
- `ScannerRunConfig` / `ScannerHostResult` / `ScannerDefinition`: The core models driving the Network Scanner Framework.

### B. Security & Safety Mechanisms
- **`AppSettings`**: A global state manager holding the output directory, command timeouts, active theme, and security policies.
- **`FilenameSafety`**: A utility class that aggressively strips path traversal characters (`../`, `\`) and invalid filesystem characters from run IDs and hostnames.
- **`CommandPolicy`**: A strict regex-based engine. It compares proposed commands against `DANGEROUS_PREFIXES` (e.g., `configure`, `reload`, `clear`) and `EXPANDED_PREFIXES` (e.g., `ping`). *Scanner commands bypass the user-policy but are still forced through `validate_scanner_commands()`.*
- **`Redactor`**: A regex-based scrubber. It intercepts Netmiko session logs and CLI outputs, blanking out passwords, SNMP strings, pre-shared keys, and crypto certificates before they ever touch the disk.

### C. Network & Connection Logic
- **`DeviceDetector`**: Uses `show version` heuristics to map a generic SSH connection into a specific `LogicalPlatform` (e.g., `CATALYST_IOS_XE_SWITCH`, `NEXUS`, `ASA_FIREWALL`).
- **`ConnectionManager`**: The core Netmiko wrapper. It handles the initial `ConnectHandler`, attempts `enable()`, invokes the `DeviceDetector`, and returns a populated `ConnectionResult` object.

### D. Parsers & Snapshot Builders
- **`ParserHelpers`**: Static utilities (`safe_int()`, `normalize_interface_name()`) designed to prevent parser crashes when encountering unexpected device output.
- **`ParserEngine`**: Contains basic, "best-effort" text-scraping logic. It relies on standard string matching and split operations to extract MAC counts, ARP tables, and config hashes.
- **`SnapshotBuilder`**: Uses the `ParserEngine` to format the raw text output into a structured JSON dictionary.
- **`CompareEngine`**: Takes a Pre-Snapshot and a Post-Snapshot JSON, iterating through their keys to generate `CompareFinding` objects (e.g., flagging if EIGRP neighbors dropped).

### E. The Threading & UI Queue Model (CRITICAL)
Tkinter is notoriously unthread-safe. If a network SSH connection blocks the main thread, the GUI freezes.
1. When a user clicks "Run", the UI disables inputs and fires a background `threading.Thread`.
2. The background thread uses `concurrent.futures.ThreadPoolExecutor` to connect to multiple devices simultaneously.
3. The background thread *cannot* touch Tkinter widgets. Instead, it places tuple messages into a `queue.Queue` (e.g., `("LOG", "Connecting to 10.0.0.1...")`).
4. The main Tkinter `NetworkToolbeltApp` runs a `.after(100, self.process_queue)` loop, constantly polling the queue and safely updating the GUI.

### F. The Graphical User Interface (Tkinter Classes)
- **`CredentialPanel` & `TargetPanel`**: Reusable `tk.Frame` components embedded into the runner pages.
- **`BaseRunnerPage`**: A foundational class providing the unified layout (Left config panel, Top-Right Status logs, Bottom-Right Live Session logs) and managing the `stop_event` cancellation logic.
- **`MaintenanceRunnerPage` / `CommandRunnerPage`**: Implementations of the BaseRunner.
- **`BaseScannerPage`**: An extension of the BaseRunner specifically wired to execute `ScannerDefinition` objects and write standardized CSV/JSON reports.
- **`ScannerLandingPage`**: A grid of buttons acting as the router to specific scanner pages.
- **`DocumentationWindow`**: A dynamic, split-pane `tk.Toplevel` window that parses the `DOCUMENTATION_SECTIONS` list.
- **`NetworkToolbeltApp`**: The root `tk.Tk` application. It holds the `frames` dictionary and handles switching the visible page via `.tkraise()`.

---

## 4. How Data Flows (The Lifecycle of a Task)

If a junior engineer needs to trace how a command executes, this is the lifecycle:

1. **User Input:** The user adds targets to the `TargetPanel` and clicks Run.
2. **Validation:** The `Page` validates inputs (no empty targets, credentials exist). 
3. **Queue Initialization:** The `Page` clears old logs, locks the UI, and creates `stop_event` (for global cancellation) and `tail_stop_event` (for log cancellation).
4. **Thread Launch:** `threading.Thread(target=self._run_network_tasks).start()` is fired.
5. **Connection:** Inside the thread, the `ThreadPoolExecutor` hands each IP to `ConnectionManager.connect()`.
6. **Execution:** Netmiko sends the commands. Outputs are scrubbed by `Redactor`.
7. **Parsing:** If it's a Scanner or Maintenance task, the raw text is fed into `ParserEngine` or custom parser callbacks.
8. **File Writing:** The results are written to `toolbelt-output/` on the local disk.
9. **UI Update:** Throughout steps 5-8, `self.ui_queue.put()` is used to send progress bars and log lines back to the Tkinter UI.
10. **Completion:** The background thread finishes, sends a final `"DONE"` queue message, and the Tkinter UI unlocks.

---

## 5. Developer Guide: Adding a New Feature

### How to Add a New Network Scanner
Because of the generic `ScannerFramework`, adding a new scanner requires almost no UI code:
1. Scroll to the `Network Scanner Suite` implementation area.
2. Write a parser function: `def parse_my_new_feature(platform, outputs, options) -> Tuple[Dict, List, List]:`
3. Define the scanner configuration: 
   ```python
   MY_SCANNER_DEF = ScannerDefinition(
       name="My Custom Scanner",
       description="Checks a specific thing.",
       commands_by_command_set={"IOS": ["show my command"]},
       parser_callback=parse_my_new_feature
   )
   ```
4. Create the Page class: 
   ```python
   class MyScannerPage(BaseScannerPage):
       def __init__(self, parent, controller):
           super().__init__(parent, controller, MY_SCANNER_DEF)
   ```
5. Add `MyScannerPage` to the `ScannerLandingPage` grid buttons.
6. Add `MyScannerPage` to the `NetworkToolbeltApp` frame initialization tuple.

### Troubleshooting Code Issues
- **UI is Freezing:** You accidentally placed a blocking network call, `time.sleep()`, or heavy file I/O on the main Tkinter thread. Move it to the background thread and use `ui_queue`.
- **"RuntimeError: main thread is not in main loop":** A background thread tried to directly modify a Tkinter widget (e.g., `self.log_text.insert()`). Always use the `ui_queue` for this.
- **Parser is Crashing on Nexus:** The `ParserEngine` assumes IOS format by default. Ensure your parser gracefully handles empty strings or uses `outputs.get("show command", "")` to avoid `KeyError` exceptions when a command isn't supported on a specific platform. Use `ParserHelpers`.
- **Command is Blocked:** Check `CommandPolicy.DANGEROUS_PREFIXES`. If the scanner is using an internal operational command, ensure it's not inadvertently blocked by the policy engine.

---

## 6. Version Control & GitHub Configuration

This project is tracked via Git and hosted on GitHub. The local environment is configured to use a specific SSH alias and author identity for commits.

**Repository Configuration:**
- **Remote Origin:** `git@github-upstate:upstatedatasystems-llc/network-toolbelt.git`
- **Primary Branch:** `main`

**Git Config (Local):**
- **User Name:** `Upstate Data Systems LLC`
- **User Email:** `upstatedatasystems@gmail.com`

**SSH Alias Context:**
The remote uses the `github-upstate` host alias, meaning SSH keys and connections should be configured in `~/.ssh/config` under the `Host github-upstate` block to ensure correct authentication.
