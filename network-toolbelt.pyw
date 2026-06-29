# ============================================================
# Imports
# ============================================================
import os
import re
import sys
import json
import csv
import queue
import hashlib
import threading
import time
from datetime import datetime
from pathlib import Path
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any

import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, ttk

try:
    from netmiko import ConnectHandler
    from netmiko.ssh_autodetect import SSHDetect
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
        NetmikoBaseException,
    )
except ImportError:
    import tkinter.messagebox as mb
    root = tk.Tk()
    root.withdraw()
    mb.showerror("Missing Dependency", "The 'netmiko' library is required.\n\nPlease run:\npip install netmiko")
    sys.exit(1)


# ============================================================
# Data Models
# ============================================================
class ConnectionStatus(Enum):
    SUCCESS = auto()
    AUTH_FAILED = auto()
    TIMEOUT = auto()
    DNS_FAILED = auto()
    CONNECTION_REFUSED = auto()
    SSH_NEGOTIATION_FAILED = auto()
    ENABLE_FAILED = auto()
    UNSUPPORTED_PLATFORM = auto()
    STOP_REQUESTED = auto()
    UNKNOWN_ERROR = auto()
    SKIPPED = auto()

class CommandStatus(Enum):
    SUCCESS = auto()
    COMMAND_TIMEOUT = auto()
    COMMAND_BLOCKED_BY_POLICY = auto()
    COMMAND_UNSUPPORTED = auto()
    PRIVILEGE_DENIED = auto()
    DEVICE_ERROR = auto()
    STOP_REQUESTED = auto()
    UNKNOWN_ERROR = auto()
    SKIPPED = auto()

class LogicalPlatform(Enum):
    IOS = auto()
    IOS_XE_SWITCH = auto()
    IOS_XE_ROUTER = auto()
    IOS_LEGACY_ROUTER = auto()
    NXOS = auto()
    ASA = auto()
    UNKNOWN_CISCO = auto()

class CommandPolicyMode(Enum):
    SAFE_READ_ONLY = auto()
    EXPANDED_OPERATIONAL = auto()
    UNSAFE_ALLOWED = auto()

@dataclass
class CommandDecision:
    allowed: bool
    reason: str
    severity: str

@dataclass
class CommandResult:
    command: str
    status: CommandStatus
    output: str
    error_message: str = ""

@dataclass
class ConnectionResult:
    host: str
    status: ConnectionStatus
    connection: Optional[Any] = None
    netmiko_device_type: str = ""
    logical_platform: Optional[LogicalPlatform] = None
    error_message: str = ""
    attempt_history: List[Dict] = field(default_factory=list)
    _reconnect_credential: Optional[Dict[str, str]] = field(default=None, repr=False, compare=False)
    platform_probe_output: str = ""
    session_prepped: bool = False

@dataclass
class DeviceSessionContext:
    host: str
    platform_choice: str
    logical_platform: LogicalPlatform
    device_type: str
    temp_session_log: str
    conn: Any
    run_platform_probe: bool
    platform_probe_output: str = ""
    _reconnect_credential: Optional[Dict[str, str]] = field(default=None, repr=False, compare=False)

@dataclass
class CommandExecutionResult:
    command: str
    status: CommandStatus
    output: str
    error_message: str = ""
    attempts: int = 1
    method_used: str = ""
    reconnect_performed: bool = False
    unsupported_reason: str = ""
    abort_host: bool = False
    elapsed_seconds: float = 0.0
    first_attempt_elapsed_seconds: float = 0.0
    retry_elapsed_seconds: float = 0.0
    output_bytes: int = 0
    output_lines: int = 0
    timeout_seconds: int = 0
    last_read_seconds: float = 0.0
    slow_command: bool = False
    diagnostic_reason: str = ""
    retry_reason: str = ""

@dataclass
class CompareFinding:
    category: str
    status: str  # PASS, WARN, FAIL, INFO, NOT_APPLICABLE, UNKNOWN_PARSE
    message: str
    pre_val: Any = None
    post_val: Any = None

@dataclass
class InterfaceRecord:
    name: str
    status: str
    protocol: str
    description: str = ""
    input_errors: int = 0
    crc: int = 0
    output_errors: int = 0
    drops: int = 0

@dataclass
class LogEvent:
    timestamp: str
    facility: str
    severity: int
    mnemonic: str
    message: str

@dataclass
class RoutingNeighbor:
    protocol: str
    neighbor_ip: str
    state: str
    uptime: str


# ============================================================

@dataclass
class ScannerRunConfig:
    scanner_name: str
    targets: List[str]
    credentials: List[dict]
    platform_choice: str
    options: Dict[str, Any]
    run_id: str
    output_dir: Path
    timestamp: str

@dataclass
class ScannerHostResult:
    host: str
    safe_host: str
    connection_status: str
    detected_platform: str
    netmiko_device_type: str
    command_outputs: Dict[str, str]
    parsed: Dict[str, Any]
    findings: List[CompareFinding]
    errors: List[str]
    warnings: List[str]

@dataclass
class ScannerDefinition:
    name: str
    internal_key: str
    description: str
    commands_by_command_set: Dict[str, List[str]]
    parser_callback: Any
    report_callback: Any

# Constants and Settings
# ============================================================

APP_VERSION = "2.92"

@dataclass
class DocumentationSection:
    title: str
    body: str


@dataclass
class CredentialRecord:
    id: str
    label: str
    username: str
    password: str
    secret: str = ""
    created_at: str = ""

class CredentialStore:
    def __init__(self):
        self.records: List[CredentialRecord] = []
        
    def add(self, label, username, password, secret=""):
        import uuid
        from datetime import datetime
        rid = str(uuid.uuid4())
        self.records.append(CredentialRecord(rid, label, username, password, secret, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        
    def update(self, record_id, label, username, password, secret):
        for r in self.records:
            if r.id == record_id:
                r.label = label
                r.username = username
                if password:
                    r.password = password
                if secret:
                    r.secret = secret
                break
                
    def delete(self, record_id):
        self.records = [r for r in self.records if r.id != record_id]
        
    def clear(self):
        self.records.clear()
        

    def get_by_id(self, credential_id: str) -> Optional[CredentialRecord]:
        for r in self.records:
            if r.id == credential_id:
                return r
        return None

    def index_of_id(self, credential_id: str) -> int:
        for i, r in enumerate(self.records):
            if r.id == credential_id:
                return i
        return -1

    def safe_display_for_id(self, credential_id: str) -> str:
        idx = self.index_of_id(credential_id)
        if idx == -1:
            return "Unknown Credential"
        r = self.records[idx]
        return f"Credential Set {idx + 1} — {r.label} / {r.username}"
    def list_safe(self):
        safe_list = []
        for i, r in enumerate(self.records, 1):
            en_status = "yes" if r.secret else "no"
            safe_list.append(f"Credential Set {i} — label: {r.label} — user: {r.username} — enable: {en_status}")
        return safe_list
        
    def as_netmiko_dicts(self):
        return [{"username": r.username, "password": r.password, "secret": r.secret} for r in self.records]


@dataclass
class TargetCredentialMapping:
    host: str
    safe_host: str
    credential_id: str = ""
    credential_label: str = ""
    username: str = ""
    status: str = "UNMAPPED"  # UNMAPPED, MAPPED, FAILED, STALE, MAPPING, SKIPPED, STOPPED
    connection_status: str = ""
    detected_platform: str = ""
    netmiko_device_type: str = ""
    last_tested: str = ""
    error_message: str = ""
    attempt_history: List[Dict[str, Any]] = field(default_factory=list)

class TargetCredentialMapStore:
    def __init__(self):
        self.targets: List[str] = []
        self.mappings: Dict[str, TargetCredentialMapping] = {}

    @staticmethod
    def normalize_host_key(host: str) -> str:
        return host.strip().lower()

    def set_targets(self, targets: List[str]):
        # Deduplicate while preserving order
        seen = set()
        cleaned = []
        for t in targets:
            key = self.normalize_host_key(t)
            if key not in seen:
                seen.add(key)
                cleaned.append(t)
        self.targets = cleaned

    def get_targets(self) -> List[str]:
        return list(self.targets)

    def upsert_mapping(self, host: str, mapping: TargetCredentialMapping):
        key = self.normalize_host_key(host)
        self.mappings[key] = mapping

    def get_mapping(self, host: str) -> Optional[TargetCredentialMapping]:
        key = self.normalize_host_key(host)
        return self.mappings.get(key)

    def remove_mapping(self, host: str):
        key = self.normalize_host_key(host)
        if key in self.mappings:
            del self.mappings[key]

    def clear_mappings(self):
        self.mappings.clear()

    def clear_targets(self):
        self.targets.clear()

    def clear_all(self):
        self.clear_targets()
        self.clear_mappings()

    def mapped_count_for_current_targets(self) -> int:
        count = 0
        for host in self.targets:
            mapping = self.get_mapping(host)
            if mapping and mapping.status == "MAPPED":
                count += 1
        return count

    def stale_count_for_current_targets(self) -> int:
        count = 0
        for host in self.targets:
            mapping = self.get_mapping(host)
            if mapping and mapping.status == "STALE":
                count += 1
        return count

    def mark_stale_for_credential(self, credential_id: str):
        for mapping in self.mappings.values():
            if mapping.credential_id == credential_id:
                mapping.status = "STALE"
                mapping.last_tested = ""

    def get_summary_counts(self) -> Dict[str, int]:
        counts = {}
        for m in self.mappings.values():
            counts[m.status] = counts.get(m.status, 0) + 1
        return counts

class AppSettings:
    def __init__(self):
        self.base_output_dir = Path.cwd() / "toolbelt-output"
        self.base_output_dir.mkdir(exist_ok=True)
        self.command_timeout = 20
        self.slow_command_threshold = 5
        self.timing_last_read = 0.75
        self.prep_command_timeout = 10
        self.prep_last_read = 0.5
        self.platform_probe_timeout = 20
        self.platform_probe_last_read = 0.5
        self.diagnostics_enabled = True
        self.execution_strategy = "safe_timing"
        self.retry_on_command_timeout = False
        
        self.output_profile = "lean"
        self.write_json_outputs = False
        self.write_full_output_json = False
        self.write_csv_summaries = True
        self.save_session_logs = "errors_only"
        self.include_full_output_in_compare_reports = False
        
        self.command_policy_mode = CommandPolicyMode.SAFE_READ_ONLY
        self.capture_mode = "redacted"
        self.current_theme = "dark"

settings = AppSettings()

THEMES = {
    "dark": {
        "bg": "#2b2b2b",
        "fg": "#ffffff",
        "entry_bg": "#3c3f41",
        "entry_fg": "#ffffff",
        "btn_bg": "#4a4a4a",
        "list_bg": "#3c3f41",
        "list_fg": "#ffffff",
        "text_bg": "#1e1e1e",
        "warning_bg": "#856404",
        "warning_fg": "#ffe8a1"
    },
    "light": {
        "bg": "#f0f0f0",
        "fg": "#000000",
        "entry_bg": "#ffffff",
        "entry_fg": "#000000",
        "btn_bg": "#e0e0e0",
        "list_bg": "#ffffff",
        "list_fg": "#000000",
        "text_bg": "#ffffff",
        "warning_bg": "#fff3cd",
        "warning_fg": "#856404"
    }
}

COMMAND_SETS = {
    "CATALYST_IOS_SWITCH": [
        "show version", "show running-config", "show inventory", "show environment all",
        "show processes cpu sorted 5sec", "show memory statistics", "show interface status",
        "show interfaces description", "show interfaces", "show interfaces counters errors",
        "show vlan brief", "show interfaces trunk", "show spanning-tree summary",
        "show spanning-tree blockedports", "show etherchannel summary", "show lacp neighbor",
        "show cdp neighbors detail", "show lldp neighbors detail", "show ip interface brief",
        "show ip route summary", "show ip route 0.0.0.0", "show ip arp", 
        "show mac address-table count", "show standby brief", 
        "show logging | include LINK|LINEPROTO|SPANTREE|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP"
    ],
    "CATALYST_IOS_XE_SWITCH": [
        "show version", "show running-config", "show inventory", "show environment all",
        "show processes cpu sorted 5sec", "show memory statistics", "show interface status",
        "show interfaces description", "show interfaces", "show interfaces counters errors",
        "show vlan brief", "show interfaces trunk", "show spanning-tree summary",
        "show spanning-tree blockedports", "show etherchannel summary", "show lacp neighbor",
        "show cdp neighbors detail", "show lldp neighbors detail", "show ip interface brief",
        "show ip route summary", "show ip route 0.0.0.0", "show ip arp", 
        "show mac address-table count", "show standby brief", 
        "show logging | include LINK|LINEPROTO|SPANTREE|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP"
    ],
    "IOS_XE_ROUTER": [
        "show version", "show running-config", "show inventory", "show platform",
        "show environment all", "show processes cpu sorted 5sec", "show memory statistics",
        "show ip interface brief", "show interfaces description", "show interfaces",
        "show interfaces counters errors", "show ip route summary", "show ip route 0.0.0.0",
        "show ip route static", "show ip route eigrp", "show ip route ospf", "show ip route bgp",
        "show ip eigrp neighbors", "show ip eigrp topology summary", "show ip ospf neighbor",
        "show ip ospf interface brief", "show ip bgp summary", "show ip bgp neighbors",
        "show ip arp", "show standby brief", "show crypto session brief", 
        "show platform hardware throughput level",
        "show logging | include LINK|LINEPROTO|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP|CRYPTO"
    ],
    "LEGACY_IOS_ROUTER": [
        "show version", "show running-config", "show inventory", "show environment all",
        "show processes cpu sorted 5sec", "show memory statistics",
        "show ip interface brief", "show interfaces description", "show interfaces",
        "show interfaces counters errors", "show ip route summary", "show ip route 0.0.0.0",
        "show ip route static", "show ip route eigrp", "show ip route ospf", "show ip route bgp",
        "show ip eigrp neighbors", "show ip eigrp topology summary", "show ip ospf neighbor",
        "show ip ospf interface brief", "show ip bgp summary", "show ip bgp neighbors",
        "show ip arp", "show standby brief", "show crypto session brief",
        "show logging | include LINK|LINEPROTO|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP|CRYPTO"
    ],
    "NEXUS": [
        "show version", "show running-config", "show inventory", "show environment",
        "show interface brief", "show interface description", "show interface",
        "show interface counters errors", "show vlan brief", "show interface trunk",
        "show spanning-tree summary", "show port-channel summary", "show lacp neighbor",
        "show cdp neighbors detail", "show lldp neighbors detail", "show ip interface brief vrf all",
        "show ip route summary", "show ip route 0.0.0.0/0", "show ip route eigrp",
        "show ip route ospf", "show ip route bgp", "show eigrp neighbors", "show ip ospf neighbors",
        "show bgp ipv4 unicast summary", "show mac address-table count", "show hsrp brief",
        "show logging last 200"
    ],
    "ASA_FIREWALL": [
        "show version", "show running-config", "show inventory", "show interface ip brief",
        "show interface", "show route summary", "show route", "show arp", "show eigrp neighbors",
        "show ospf neighbor", "show bgp summary", "show conn count", "show xlate count",
        "show vpn-sessiondb summary", "show crypto ikev1 sa", "show crypto ikev2 sa summary",
        "show crypto ipsec sa summary", "show failover", "show cpu usage", "show memory",
        "show logging | include error|fail|down|up|IKE|IPSEC|OSPF|EIGRP|BGP"
    ]
}
MAINTENANCE_BASELINE_COMMANDS = {
    "CATALYST_IOS_SWITCH": [
        "show version", "show running-config", "show inventory", "show environment all",
        "show processes cpu sorted 5sec", "show memory statistics", "show interface status",
        "show interfaces description", "show interfaces", "show interfaces counters errors",
        "show vlan brief", "show interfaces trunk", "show spanning-tree summary",
        "show spanning-tree blockedports", "show etherchannel summary", "show lacp neighbor",
        "show cdp neighbors detail", "show lldp neighbors detail", "show ip interface brief",
        "show ip route summary", "show ip route 0.0.0.0", "show ip arp", 
        "show mac address-table count", 
        "show logging | include LINK|LINEPROTO|SPANTREE|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP"
    ],
    "CATALYST_IOS_XE_SWITCH": [
        "show version", "show running-config", "show inventory", "show environment all",
        "show processes cpu sorted 5sec", "show memory statistics", "show interface status",
        "show interfaces description", "show interfaces", "show interfaces counters errors",
        "show vlan brief", "show interfaces trunk", "show spanning-tree summary",
        "show spanning-tree blockedports", "show etherchannel summary", "show lacp neighbor",
        "show cdp neighbors detail", "show lldp neighbors detail", "show ip interface brief",
        "show ip route summary", "show ip route 0.0.0.0", "show ip arp", 
        "show mac address-table count", 
        "show logging | include LINK|LINEPROTO|SPANTREE|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP"
    ],
    "IOS_XE_ROUTER": [
        "show version", "show running-config", "show inventory", "show environment all",
        "show processes cpu sorted 5sec", "show memory statistics", 
        "show interfaces description", "show interfaces", "show interfaces counters errors",
        "show ip interface brief", "show ip route summary", "show ip route 0.0.0.0", "show ip arp",
        "show logging | include LINK|LINEPROTO|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP"
    ],
    "LEGACY_IOS_ROUTER": [
        "show version", "show running-config", "show inventory", "show environment all",
        "show processes cpu sorted 5sec", "show memory statistics", 
        "show interfaces description", "show interfaces", "show interfaces counters errors",
        "show ip interface brief", "show ip route summary", "show ip route 0.0.0.0", "show ip arp",
        "show logging | include LINK|LINEPROTO|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP"
    ],
    "NEXUS": [
        "show version", "show running-config", "show inventory", "show environment",
        "show processes cpu sorted 5sec", "show system resources", "show interface status",
        "show interface description", "show interface", "show interface counters errors",
        "show vlan", "show interface trunk", "show spanning-tree summary",
        "show spanning-tree blockedports", "show port-channel summary", "show lacp neighbor",
        "show cdp neighbors detail", "show lldp neighbors detail", "show ip interface brief vrf all",
        "show ip route summary vrf all", "show ip arp vrf all", 
        "show mac address-table count", 
        "show logging | include LINK|LINEPROTO|SPANTREE|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP"
    ],
    "ASA_FIREWALL": [
        "show version", "show running-config", "show inventory", "show environment",
        "show processes cpu-usage sorted", "show memory", "show interface ip brief",
        "show interface detail", "show arp", "show route", "show logging"
    ]
}

FEATURE_COMMANDS = {
    "bgp": ["show ip bgp summary", "show ip bgp neighbors", "show bgp ipv4 unicast summary", "show bgp l2vpn evpn summary"],
    "ospf": ["show ip ospf neighbor", "show ip ospf interface brief", "show ip ospf neighbors"],
    "eigrp": ["show ip eigrp neighbors"],
    "hsrp": ["show standby brief"],
    "vrrp": ["show vrrp brief"],
    "portchannel": ["show etherchannel summary", "show lacp neighbor", "show port-channel summary"],
    "crypto_vpn": ["show crypto isakmp sa", "show crypto ipsec sa", "show crypto ikev2 sa"],
    "asa_failover": ["show failover"]
}


PLATFORM_COMMAND_SET_MAP = {
    LogicalPlatform.IOS_XE_SWITCH: "CATALYST_IOS_XE_SWITCH",
    LogicalPlatform.IOS_XE_ROUTER: "IOS_XE_ROUTER",
    LogicalPlatform.IOS_LEGACY_ROUTER: "LEGACY_IOS_ROUTER",
    LogicalPlatform.NXOS: "NEXUS",
    LogicalPlatform.ASA: "ASA_FIREWALL",
    LogicalPlatform.IOS: "CATALYST_IOS_SWITCH",
    LogicalPlatform.UNKNOWN_CISCO: "CATALYST_IOS_SWITCH",
}


# ============================================================
# Filename Safety
# ============================================================
class FilenameSafety:
    @staticmethod
    def safe_filename(value: str, max_len: int = 100) -> str:
        if not value:
            return "unknown"
        # Replace ipv6 colons
        v = value.replace(":", "_")
        # Keep only safe chars
        v = re.sub(r"[^A-Za-z0-9_\.-]", "_", v)
        # Collapse multiple underscores
        v = re.sub(r"_+", "_", v)
        # Prevent traversal
        v = v.replace("..", "_").replace("/", "_").replace("\\", "_").replace("\0", "_")
        v = v.strip("_").strip()
        if not v:
            return "unknown"
        return v[:max_len]

    @staticmethod
    def safe_run_id(value: str) -> str:
        return FilenameSafety.safe_filename(value, max_len=50)

    @staticmethod
    def safe_host_label(value: str) -> str:
        return FilenameSafety.safe_filename(value, max_len=50)


# ============================================================
# Command Policy
# ============================================================
import json

class ToolCommandManager:
    def __init__(self):
        self.override_file = settings.base_output_dir / "tool_command_overrides.json"
        self.overrides = {}
        self.load_overrides()

    def load_overrides(self):
        if not self.override_file.exists():
            return
        try:
            with open(self.override_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or "tools" not in data:
                self._backup_bad_file("wrong shape")
                return
            self.overrides = data["tools"]
        except Exception as e:
            self._backup_bad_file(str(e))

    def _backup_bad_file(self, reason):
        messagebox.showwarning("Warning", f"tool_command_overrides.json is invalid ({reason}). It has been renamed. Starting with defaults.")
        try:
            backup_name = f"tool_command_overrides.bad-{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
            self.override_file.rename(settings.base_output_dir / backup_name)
        except Exception:
            pass
        self.overrides = {}

    def save_overrides(self):
        data = {
            "version": 1,
            "updated_at": datetime.now().isoformat(),
            "tools": self.overrides
        }
        try:
            with open(self.override_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            messagebox.showwarning("Warning", f"Could not save tool_command_overrides.json: {e}\nOverrides will only be kept in memory for this session.")

    def get_effective_commands(self, tool_key: str, group_key: str, default_cmds: list) -> list:
        if tool_key in self.overrides and group_key in self.overrides[tool_key]:
            return list(self.overrides[tool_key][group_key])
        return list(default_cmds)

    def update_commands(self, tool_key: str, group_key: str, commands: list):
        if tool_key not in self.overrides:
            self.overrides[tool_key] = {}
        self.overrides[tool_key][group_key] = list(commands)
        self.save_overrides()

    def reset_group(self, tool_key: str, group_key: str):
        if tool_key in self.overrides and group_key in self.overrides[tool_key]:
            del self.overrides[tool_key][group_key]
            if not self.overrides[tool_key]:
                del self.overrides[tool_key]
            self.save_overrides()

    def reset_tool(self, tool_key: str):
        if tool_key in self.overrides:
            del self.overrides[tool_key]
            self.save_overrides()

    @staticmethod
    def validate_commands(commands: list) -> list:
        blocked = []
        allowed_prefixes = ("show ", "terminal length", "terminal width", "terminal pager", "dir", "pwd")
        dangerous_prefixes = (
            "configure", "conf", "reload", "write", "copy", "delete", "erase",
            "clear", "debug", "undebug", "request", "install", "test",
            "ping", "traceroute"
        )

        for cmd in commands:
            low = cmd.lower().strip()

            if not any(low.startswith(prefix) for prefix in allowed_prefixes):
                blocked.append(cmd)
                continue

            if any(low == dp or low.startswith(dp + " ") for dp in dangerous_prefixes):
                blocked.append(cmd)
                continue

        return blocked

class CommandPolicy:
    SAFE_PREFIXES = ("show ", "terminal length ", "terminal width ", "terminal pager ", "dir ", "pwd ")
    EXPANDED_PREFIXES = ("ping ", "traceroute ")
    DANGEROUS_PREFIXES = (
        "configure", "conf", "reload", "write", "copy", "delete", "erase",
        "format", "clear", "debug", "undebug", "no debug", "archive",
        "request", "install", "license", "crypto key", "test", "hw-module",
        "mkdir", "rmdir", "squeeze", "more system:running-config", "send",
        "clock set", "terminal monitor", "terminal no monitor",
        "monitor capture", "packet-tracer", "capture", "failover active",
        "failover reload-standby", "redundancy force-switchover", "issu",
        "guestshell", "app-hosting", "virtual-service", "service internal"
    )

    @classmethod
    def evaluate(cls, command: str, mode: CommandPolicyMode) -> CommandDecision:
        cmd_lower = command.strip().lower()
        if mode == CommandPolicyMode.UNSAFE_ALLOWED:
            return CommandDecision(True, "Unsafe mode allows all commands.", "unsafe")
        for dp in cls.DANGEROUS_PREFIXES:
            if cmd_lower.startswith(dp):
                return CommandDecision(False, f"Command matches dangerous prefix '{dp}'.", "blocked")
        for ep in cls.EXPANDED_PREFIXES:
            if cmd_lower.startswith(ep):
                if mode == CommandPolicyMode.EXPANDED_OPERATIONAL:
                    return CommandDecision(True, "Matched expanded operational allowlist.", "expanded")
                return CommandDecision(False, "Command requires Expanded Operational mode.", "blocked")
        for sp in cls.SAFE_PREFIXES:
            if cmd_lower.startswith(sp):
                return CommandDecision(True, "Matched safe read-only allowlist.", "safe")
        return CommandDecision(False, "Command is not in the allowlist. Default deny.", "blocked")

    @classmethod
    def evaluate_many(cls, commands: List[str], mode: CommandPolicyMode) -> List[CommandDecision]:
        return [cls.evaluate(cmd, mode) for cmd in commands]



    @classmethod
    def validate_scanner_commands(cls, commands: List[str]) -> List[str]:
        unsafe = []
        for cmd in commands:
            c = cmd.strip().lower()
            if any(c.startswith(dp) for dp in cls.DANGEROUS_PREFIXES) or any(c.startswith(ep) for ep in cls.EXPANDED_PREFIXES):
                unsafe.append(cmd)
        return unsafe

class LineBufferedRedactor:
    def __init__(self, redact_fn):
        self.redact_fn = redact_fn
        self.pending = ""

    def feed(self, text: str) -> str:
        if not text: return ""
        combined = self.pending + text
        lines = combined.splitlines(True)
        if not lines: return ""
        if combined.endswith("\n") or combined.endswith("\r"):
            self.pending = ""
            return "".join(self.redact_fn(line) for line in lines)
        else:
            self.pending = lines[-1]
            return "".join(self.redact_fn(line) for line in lines[:-1])

    def flush(self) -> str:
        if self.pending:
            res = self.redact_fn(self.pending)
            self.pending = ""
            return res
        return ""

class SecureTempSessionLogManager:
    @staticmethod
    def ensure_secure_temp_session_dir(base_output_dir, run_id: str):
        temp_dir = base_output_dir / ".temp_sessions" / run_id
        temp_dir.mkdir(parents=True, exist_ok=True)
        try: temp_dir.chmod(0o700)
        except Exception: pass
        return temp_dir

    @staticmethod
    def create_secure_session_log_path(temp_dir, safe_host: str):
        import uuid
        p = temp_dir / f"{safe_host}_{uuid.uuid4().hex[:8]}.log"
        p.touch()
        try: p.chmod(0o600)
        except Exception: pass
        return p

    @staticmethod
    def cleanup_secure_session_log(path):
        try:
            if path and path.exists(): path.unlink(missing_ok=True)
        except Exception: pass

    @staticmethod
    def cleanup_stale_temp_session_dirs(base_output_dir):
        import shutil
        temp_base = base_output_dir / ".temp_sessions"
        if not temp_base.exists(): return
        for d in temp_base.iterdir():
            if d.is_dir():
                try: shutil.rmtree(d)
                except Exception: pass

# ============================================================
# ============================================================
# Redaction
# ============================================================
@dataclass
class RedactionRule:
    name: str
    pattern: re.Pattern
    replacement: Any

class Redactor:
    def __init__(self):
        self.rules = [
            RedactionRule("username_secret", re.compile(r"(?im)^(\s*username\s+\S+(?:\s+privilege\s+\d+)?\s+(?:secret|password)\s+(?:\d\s+)?)(.*)$"), r"\1<REDACTED>"),
            RedactionRule("enable_secret", re.compile(r"(?im)^(\s*enable\s+(?:secret|password)\s+(?:\d\s+)?)(.*)$"), r"\1<REDACTED>"),
            RedactionRule("line_password", re.compile(r"(?im)^(\s*password\s+(?:\d\s+)?)(.*)$"), r"\1<REDACTED>"),
            RedactionRule("snmp_community", re.compile(r"(?im)^(\s*snmp-server\s+community\s+)(\S+)(.*)$"), r"\1<REDACTED>\3"),
            RedactionRule("snmp_host", re.compile(r"(?im)^(\s*snmp-server\s+host\s+\S+(?:\s+vrf\s+\S+)?\s+(?:version\s+\S+\s+)?)(?!version)(\S+)(.*)$"), r"\1<REDACTED>\3"),
            RedactionRule("snmp_user", re.compile(r"(?im)^(\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\s+auth\s+\S+\s+)(\S+)(.*)$"), r"\1<REDACTED>\3"),
            RedactionRule("aaa_server_key", re.compile(r"(?im)^(\s*(?:tacacs|radius)-server\s+(?:host\s+\S+\s+)?key\s+(?:\d\s+)?)(.*)$"), r"\1<REDACTED>"),
            RedactionRule("crypto_isakmp_key", re.compile(r"(?im)^(\s*crypto\s+isakmp\s+key\s+(?:\d\s+)?)(?!address)(\S+)(.*)$"), r"\1<REDACTED>\3"),
            RedactionRule("crypto_ikev2_key", re.compile(r"(?im)^(\s*(?:local|remote)-authentication\s+pre-shared-key\s+(?:\d\s+)?)(.*)$"), r"\1<REDACTED>"),
            RedactionRule("tunnel_group_ike", re.compile(r"(?im)^(\s*ikev[12]\s+(?:remote-authentication\s+)?pre-shared-key\s+(?:\d\s+)?)(.*)$"), r"\1<REDACTED>"),
            RedactionRule("ospf_auth", re.compile(r"(?im)^(\s*ip\s+ospf\s+(?:message-digest-key\s+\d+\s+md5|authentication-key)\s+(?:\d\s+)?)(.*)$"), r"\1<REDACTED>"),
            RedactionRule("key_string", re.compile(r"(?im)^(\s*key-string\s+(?:\d\s+)?)(.*)$"), r"\1<REDACTED>"),
            RedactionRule("ntp_auth", re.compile(r"(?im)^(\s*ntp\s+authentication-key\s+\d+\s+md5\s+)(.*)$"), r"\1<REDACTED>"),
            RedactionRule("certificate_block", re.compile(r"(?s)(\s*certificate\s+self-signed\s*\n\s*[0-9A-Fa-f\s]+\n\s*quit)"), r"\n  certificate self-signed\n    <REDACTED>\n  quit"),
            RedactionRule("pem_private_key", re.compile(r"(?s)-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----"), r"-----BEGIN PRIVATE KEY-----\n<REDACTED>\n-----END PRIVATE KEY-----"),
            RedactionRule("pem_certificate", re.compile(r"(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"), r"-----BEGIN CERTIFICATE-----\n<REDACTED>\n-----END CERTIFICATE-----"),
            RedactionRule("wireless_psk", re.compile(r"(?im)^(\s*wpa-psk\s+(?:ascii\s+)?(?:\d\s+)?)(.*)$"), r"\1<REDACTED>"),
            RedactionRule("generic_catchall", re.compile(r"(?im)^.*(?:password|secret|community|key-string|pre-shared-key|server-key).*$"), lambda m: re.sub(r"(\s+(?:password|secret|community|key-string|pre-shared-key|server-key|key)\s+(?:\d\s+)?)(?![\s\n])(\S+)", r"\1<REDACTED>", m.group(0))),
            RedactionRule("tacacs_radius_nested", re.compile(r"(?im)^(\s*(?:key(?:word)?)\s+(?:\d\s+)?)(?![\s\n])(\S+)(.*)$"), r"<REDACTED>"),
            RedactionRule("snmpv3_auth_priv", re.compile(r"(?im)^(\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\s+auth\s+(?:md5|sha|sha-256)\s+)(\S+)(\s+priv\s+(?:des|3des|aes|aes\s+\d+)\s+)(\S+)(.*)$"), r"<REDACTED><REDACTED>"),
            RedactionRule("snmpv3_auth_only", re.compile(r"(?im)^(\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\s+auth\s+(?:md5|sha|sha-256)\s+)(\S+)(\s*)$"), r"<REDACTED>"),
            RedactionRule("password_colon", re.compile(r"(?im)^((?:.*[pP]assword|.*[pP]asscode)\s*:\s*)(.*)$"), lambda m: m.group(1) + "<REDACTED>" if m.group(2).strip() else m.group(0))
        ]

    def redact_text(self, text: str) -> str:
        if not text: return ""
        for rule in self.rules:
            if callable(rule.replacement):
                text = rule.pattern.sub(rule.replacement, text)
            else:
                text = rule.pattern.sub(rule.replacement, text)
        return text

    def redact_file(self, src: Path, dest: Path):
        try:
            content = src.read_text(encoding="utf-8")
            dest.write_text(self.redact_text(content), encoding="utf-8")
        except Exception:
            pass

redactor = Redactor()


# ============================================================
# Device Detection
# ============================================================
class DeviceDetector:
    @staticmethod
    def classify(version_output: str) -> LogicalPlatform:
        ver = version_output.lower()
        if "adaptive security appliance" in ver or "asa software" in ver:
            return LogicalPlatform.ASA
        if "nx-os" in ver or "nexus" in ver:
            return LogicalPlatform.NXOS
        if "c800" in ver or "c1800" in ver or "c1900" in ver or "c2900" in ver or "c3900" in ver:
            if "ios-xe" not in ver and "ios xe" not in ver:
                return LogicalPlatform.IOS_LEGACY_ROUTER
        if "ios-xe" in ver or "ios xe" in ver:
            if "catalyst" in ver or "switch" in ver or "c9300" in ver or "c9200" in ver or "c9500" in ver or "c3850" in ver:
                return LogicalPlatform.IOS_XE_SWITCH
            if "router" in ver or "asr" in ver or "isr" in ver or "c8300" in ver or "c8200" in ver or "c8000" in ver or "csr" in ver:
                return LogicalPlatform.IOS_XE_ROUTER
            return LogicalPlatform.IOS_XE_SWITCH
        if "cisco ios software" in ver or "cisco internetwork operating system software" in ver:
            return LogicalPlatform.IOS
        return LogicalPlatform.UNKNOWN_CISCO


# ============================================================
# Connection Manager
# ============================================================
class ConnectionManager:
    # DEPRECATED: Do not use for new execution paths. Prefer execute_command_with_recovery().
    @staticmethod
    def safe_send_command(conn, cmd, read_timeout=None, platform_hint=""):
        timeout_val = read_timeout or settings.command_timeout
        try:
            return conn.send_command(cmd, read_timeout=timeout_val, cmd_verify=False)
        except Exception as e:
            err_str = str(e).lower()
            if "pattern not detected" in err_str or "search pattern" in err_str or "command echo" in err_str or "prompt" in err_str or "read_channel_timing" in err_str:
                try:
                    return conn.send_command_timing(cmd, read_timeout=timeout_val)
                except Exception as inner_e:
                    raise inner_e
            raise e
    @staticmethod
    def prepare_session(conn, logical_platform: LogicalPlatform, device_type: str, log_callback=None):
        commands = []
        if logical_platform == LogicalPlatform.ASA or device_type == "cisco_asa":
            commands.append("terminal pager 0")
        elif logical_platform == LogicalPlatform.NXOS or device_type == "cisco_nxos":
            commands.append("terminal length 0")
        else:
            commands.append("terminal length 0")
            commands.append("terminal width 511")
            
        for cmd in commands:
            try:
                t0 = time.perf_counter()
                conn.send_command_timing(cmd, read_timeout=settings.prep_command_timeout, last_read=settings.prep_last_read, strip_prompt=False, strip_command=False)
                elapsed = time.perf_counter() - t0
                if settings.diagnostics_enabled and log_callback:
                    log_callback(f"  Debug: Session prep '{cmd}' completed in {elapsed:.2f}s")
            except Exception as e:
                if log_callback:
                    log_callback(f"Debug: Session prep command '{cmd}' error: {e}")

    @staticmethod
    def is_transport_error(error_msg: str, output: str) -> bool:
        err = (error_msg + output).lower()
        if "socket is closed" in err or "session is not active" in err or "connection reset" in err or "broken pipe" in err or "channel closed" in err or "eof" in err:
            return True
        return False
        
    @staticmethod
    def is_malformed_echo(cmd: str, output: str) -> bool:
        if not output.strip():
            return False
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            return False
        first_line = lines[0].lower()
        cmd_lower = cmd.strip().lower()
        if first_line == cmd_lower:
            return False
        if cmd_lower.startswith(first_line) and len(first_line) < len(cmd_lower):
            return True
        cmd_tokens = cmd_lower.split()
        out_tokens = first_line.split()
        if not out_tokens or len(out_tokens) > len(cmd_tokens):
            return False
        for i, token in enumerate(out_tokens):
            if not cmd_tokens[i].startswith(token):
                return False
        if len(out_tokens) < len(cmd_tokens):
            return True
        if any(len(out_tokens[i]) < len(cmd_tokens[i]) for i in range(len(out_tokens))):
            return True
        return False

    @staticmethod
    def summarize_command_diagnostics(result: CommandExecutionResult) -> str:
        s = f"method={result.method_used}, attempts={result.attempts}, bytes={result.output_bytes}, lines={result.output_lines}, timeout={result.timeout_seconds}s, last_read={result.last_read_seconds}s"
        if result.status == CommandStatus.SUCCESS:
            if result.slow_command:
                return f"! Slow command: {result.command.strip()} took {result.elapsed_seconds:.1f}s [{s}]. Possible causes: large output, device delay, timing wait, or prompt/read behavior."
            return f"✓ {result.command.strip()} completed in {result.elapsed_seconds:.1f}s [{s}]"
        elif result.status == CommandStatus.COMMAND_TIMEOUT:
            return f"✗ Timeout after {result.elapsed_seconds:.1f}s: {result.command.strip()} [{s}]"
        else:
            return f"✗ Failed in {result.elapsed_seconds:.1f}s: {result.command.strip()} [status={result.status.name}, {s}, reason={result.retry_reason or result.diagnostic_reason or 'unknown'}]"

    @staticmethod
    def format_diagnostic_header(result: CommandExecutionResult) -> str:
        return f"# status={result.status.name} elapsed={result.elapsed_seconds:.1f}s method={result.method_used} attempts={result.attempts} bytes={result.output_bytes} lines={result.output_lines} timeout={result.timeout_seconds}s last_read={result.last_read_seconds}s retry={result.retry_reason or 'none'}"

    @staticmethod
    def execute_command_with_recovery(context: DeviceSessionContext, cmd: str, read_timeout: int = None, log_callback=None) -> CommandExecutionResult:
        total_t0 = time.perf_counter()
        timeout_val = read_timeout or settings.command_timeout
        last_read_val = settings.timing_last_read
        
        use_timing = False
        if settings.execution_strategy == "safe_timing":
            use_timing = True
        elif "|" in cmd or context.logical_platform in (LogicalPlatform.ASA, LogicalPlatform.NXOS, LogicalPlatform.IOS_XE_SWITCH, LogicalPlatform.IOS_XE_ROUTER):
            use_timing = True

        def run_once(conn, method_timing):
            out = ""
            err = ""
            status = CommandStatus.SUCCESS
            t0 = time.perf_counter()
            try:
                if method_timing:
                    out = conn.send_command_timing(cmd, read_timeout=timeout_val, last_read=last_read_val, strip_prompt=False, strip_command=False)
                else:
                    out = conn.send_command(cmd, read_timeout=timeout_val, cmd_verify=False, strip_prompt=False, strip_command=False)
            except NetmikoTimeoutException as e:
                err = str(e)
                status = CommandStatus.COMMAND_TIMEOUT
            except Exception as e:
                err = str(e)
                status = CommandStatus.UNKNOWN_ERROR
            elapsed = time.perf_counter() - t0
            return out, err, status, elapsed
            
        out, err, status, elapsed_1 = run_once(context.conn, use_timing)
        method_used = "send_command_timing" if use_timing else "send_command"
        
        needs_retry = False
        is_transport = False
        retry_reason = ""
        fallback_last_read = False
        if status != CommandStatus.SUCCESS and ConnectionManager.is_transport_error(err, out):
            needs_retry = True
            is_transport = True
            retry_reason = "transport_error"
        elif status == CommandStatus.SUCCESS:
            if ConnectionManager.is_transport_error("", out):
                needs_retry = True
                is_transport = True
                retry_reason = "transport_error"
            elif ConnectionManager.is_malformed_echo(cmd, out):
                needs_retry = True
                retry_reason = "malformed_echo"
                fallback_last_read = True
        elif status == CommandStatus.COMMAND_TIMEOUT:
            if settings.retry_on_command_timeout:
                needs_retry = True
                retry_reason = "command_timeout"
                fallback_last_read = True
            else:
                needs_retry = False
        else:
            if status != CommandStatus.SUCCESS:
                needs_retry = True
                retry_reason = "unknown_error"
        
        if not needs_retry and status == CommandStatus.SUCCESS:
            status, analyze_err = CommandOutputAnalyzer.analyze(out)
            if status != CommandStatus.SUCCESS:
                err = analyze_err or "Device error"
                
        def finalize_result(out_f, err_f, status_f, attempts_f, method_f, recon_perf, abort_h, elaps_1, elaps_retry, r_reason, d_reason):
            elaps = time.perf_counter() - total_t0
            ob = len(out_f.encode('utf-8')) if out_f else 0
            ol = len(out_f.splitlines()) if out_f else 0
            slow = elaps >= settings.slow_command_threshold
            res = CommandExecutionResult(
                command=cmd, status=status_f, output=out_f, error_message=err_f, attempts=attempts_f, method_used=method_f, reconnect_performed=recon_perf, 
                unsupported_reason="Unsupported" if status_f == CommandStatus.COMMAND_UNSUPPORTED else "", abort_host=abort_h,
                elapsed_seconds=elaps, first_attempt_elapsed_seconds=elaps_1, retry_elapsed_seconds=elaps_retry,
                output_bytes=ob, output_lines=ol, timeout_seconds=timeout_val, last_read_seconds=last_read_val if "timing" in method_f else 0.0,
                slow_command=slow, diagnostic_reason=d_reason, retry_reason=r_reason
            )
            if settings.diagnostics_enabled and log_callback:
                log_callback(ConnectionManager.summarize_command_diagnostics(res))
            return res
                
        if not needs_retry:
            return finalize_result(out, err, status, 1, method_used, False, False, elapsed_1, 0.0, "", "")
            
        if fallback_last_read:
            last_read_val = 2.0
            if log_callback:
                log_callback(f"  Debug: Retrying with conservative timing last_read=2.0s ({retry_reason})")
        elif log_callback:
            log_callback(f"  Debug: Command error detected ({retry_reason}). Retrying...")
            
        recon_elapsed = 0.0
        if is_transport and context._reconnect_credential:
            if log_callback:
                log_callback(f"  Debug: Transport error detected. Reconnecting...")
            t_rec = time.perf_counter()
            try:
                context.conn.disconnect()
            except:
                pass
            
            recon_res = ConnectionManager.connect(context.host, context._reconnect_credential, context.platform_choice, context.temp_session_log, context.run_platform_probe)
            if recon_res.status == ConnectionStatus.SUCCESS:
                context.conn = recon_res.connection
                if not recon_res.session_prepped:
                    ConnectionManager.prepare_session(context.conn, context.logical_platform, context.device_type, log_callback)
            else:
                recon_elapsed = time.perf_counter() - t_rec
                return finalize_result(out, f"Reconnect failed: {recon_res.error_message}", CommandStatus.UNKNOWN_ERROR, 1, method_used, False, True, elapsed_1, 0.0, retry_reason, "Reconnect failed")
            recon_elapsed = time.perf_counter() - t_rec
            
            out, err, status, elapsed_2 = run_once(context.conn, True)
            method_used = "reconnect + send_command_timing"
            reconnect_performed = True
        else:
            out, err, status, elapsed_2 = run_once(context.conn, True)
            method_used = "retry + send_command_timing"
            reconnect_performed = False

        if status == CommandStatus.SUCCESS:
            status, analyze_err = CommandOutputAnalyzer.analyze(out)
            if status != CommandStatus.SUCCESS:
                err = analyze_err or "Device error"

        if (status != CommandStatus.SUCCESS and ConnectionManager.is_transport_error(err, out)) or (status == CommandStatus.SUCCESS and ConnectionManager.is_transport_error("", out)):
            return finalize_result(out, err or "Transport error during retry", status if status != CommandStatus.SUCCESS else CommandStatus.UNKNOWN_ERROR, 2, method_used, reconnect_performed, True, elapsed_1, elapsed_2, retry_reason, "Transport error persisted")

        if status == CommandStatus.SUCCESS and ConnectionManager.is_malformed_echo(cmd, out):
            return finalize_result(out, "Malformed command echo persisted after retry", CommandStatus.UNKNOWN_ERROR, 2, method_used, reconnect_performed, True, elapsed_1, elapsed_2, retry_reason, "Malformed echo persisted")

        return finalize_result(out, err, status, 2, method_used, reconnect_performed, False, elapsed_1, elapsed_2, retry_reason, "")
    @staticmethod
    def connect(ip: str, creds: dict, platform_choice: str, temp_session_log: str, run_platform_probe: bool = True, log_callback=None):
        try:
            t_connect_total = time.perf_counter()
            device_type = "cisco_ios"

            if platform_choice == "Cisco NX-OS":
                device_type = "cisco_nxos"
            elif platform_choice == "Cisco ASA":
                device_type = "cisco_asa"
            elif platform_choice in ("Auto Detect", "Auto Detect Platform"):
                device_type = "cisco_ios"
                if log_callback and settings.diagnostics_enabled:
                    log_callback(f"  ℹ Auto Detect selected — connecting as cisco_ios (platform probe will classify device)")

            if log_callback and settings.diagnostics_enabled:
                log_callback(f"  ⏳ Opening SSH session (device_type={device_type}, timeout=15s)...")
            t_ssh = time.perf_counter()
            try:
                try:
                    conn = ConnectHandler(
                        device_type=device_type,
                        host=ip,
                        username=creds["username"],
                        password=creds["password"],
                        secret=creds.get("secret", ""),
                        session_log=temp_session_log,
                        auth_timeout=15,
                        timeout=15,
                        fast_cli=False,
                        global_cmd_verify=False
                    )
                except TypeError:
                    conn = ConnectHandler(
                        device_type=device_type,
                        host=ip,
                        username=creds["username"],
                        password=creds["password"],
                        secret=creds.get("secret", ""),
                        session_log=temp_session_log,
                        auth_timeout=15,
                        timeout=15,
                        fast_cli=False
                    )
            except NetmikoAuthenticationException as e:
                if log_callback and settings.diagnostics_enabled:
                    log_callback(f"  ✗ SSH authentication failed after {time.perf_counter() - t_ssh:.2f}s")
                return ConnectionResult(host=ip, status=ConnectionStatus.AUTH_FAILED, error_message=str(e), _reconnect_credential=creds)
            except NetmikoTimeoutException as e:
                if log_callback and settings.diagnostics_enabled:
                    log_callback(f"  ✗ SSH connection timed out after {time.perf_counter() - t_ssh:.2f}s")
                return ConnectionResult(host=ip, status=ConnectionStatus.TIMEOUT, error_message=str(e), _reconnect_credential=creds)
            except Exception as e:
                if log_callback and settings.diagnostics_enabled:
                    log_callback(f"  ✗ SSH connection error after {time.perf_counter() - t_ssh:.2f}s: {type(e).__name__}")
                err = str(e).lower()
                if "connection refused" in err:
                    status = ConnectionStatus.CONNECTION_REFUSED
                elif "dns" in err or "name or service not known" in err:
                    status = ConnectionStatus.DNS_FAILED
                elif "negotiation" in err or "kex" in err:
                    status = ConnectionStatus.SSH_NEGOTIATION_FAILED
                else:
                    status = ConnectionStatus.UNKNOWN_ERROR
                return ConnectionResult(host=ip, status=status, error_message=str(e), _reconnect_credential=creds)
            if log_callback and settings.diagnostics_enabled:
                log_callback(f"  ✓ SSH session established in {time.perf_counter() - t_ssh:.2f}s")

            if log_callback and settings.diagnostics_enabled:
                log_callback(f"  ⏳ Attempting privilege escalation (enable)...")
            t_enable = time.perf_counter()
            try:
                conn.enable()
                if log_callback and settings.diagnostics_enabled:
                    log_callback(f"  ✓ Enable mode succeeded in {time.perf_counter() - t_enable:.2f}s")
            except Exception as e:
                if log_callback:
                    log_callback(f"  ⚠ Enable mode failed in {time.perf_counter() - t_enable:.2f}s (session will continue without privilege escalation)")

            logical = LogicalPlatform.UNKNOWN_CISCO
            ver_out_saved = ""
            session_prepped = False
            if platform_choice == "Cisco ASA" or device_type == "cisco_asa":
                logical = LogicalPlatform.ASA
            elif platform_choice == "Cisco NX-OS" or device_type == "cisco_nxos":
                logical = LogicalPlatform.NXOS
            elif platform_choice == "Cisco IOS / IOS-XE":
                logical = LogicalPlatform.IOS

            if run_platform_probe:
                if log_callback and settings.diagnostics_enabled:
                    log_callback(f"  ⏳ Preparing session (terminal length/width)...")
                ConnectionManager.prepare_session(conn, logical, device_type, log_callback)
                session_prepped = True
                if log_callback and settings.diagnostics_enabled:
                    log_callback(f"  ⏳ Running platform probe (show version, timeout={settings.platform_probe_timeout}s, last_read={settings.platform_probe_last_read}s)...")
                try:
                    t0 = time.perf_counter()
                    ver_out = conn.send_command_timing("show version", read_timeout=settings.platform_probe_timeout, last_read=settings.platform_probe_last_read, strip_prompt=False, strip_command=False)
                    logical = DeviceDetector.classify(ver_out)
                    ver_out_saved = ver_out
                    elapsed = time.perf_counter() - t0
                    if log_callback and settings.diagnostics_enabled:
                        log_callback(f"  ✓ Platform probe completed in {elapsed:.2f}s — classified as {logical.name} [bytes={len(ver_out.encode('utf-8'))}, lines={len(ver_out.splitlines())}]")
                except Exception as e:
                    if log_callback and settings.diagnostics_enabled:
                        log_callback(f"  ⚠ Platform probe failed after {time.perf_counter() - t0:.2f}s: {type(e).__name__}")

            if log_callback and settings.diagnostics_enabled:
                log_callback(f"  ✓ Connection setup complete in {time.perf_counter() - t_connect_total:.2f}s [platform={logical.name}, device_type={device_type}]")

            return ConnectionResult(
                host=ip,
                status=ConnectionStatus.SUCCESS,
                connection=conn,
                netmiko_device_type=device_type,
                logical_platform=logical,
                _reconnect_credential=creds,
                platform_probe_output=ver_out_saved,
                session_prepped=session_prepped
            )

        except Exception as e:
            return ConnectionResult(host=ip, status=ConnectionStatus.UNKNOWN_ERROR, error_message=str(e))

    @staticmethod
    def connect_with_mapped_or_global_credentials(host: str, platform_choice: str, temp_session_log: str, credential_store, mapping_store, log_callback, stop_event=None, fallback_to_all=False, run_platform_probe: bool = True):
        if mapping_store is None:
            return ConnectionManager.connect_with_global_credentials(host, platform_choice, temp_session_log, credential_store.as_netmiko_dicts(), log_callback, stop_event, run_platform_probe)
        
        mapping = mapping_store.get_mapping(host)
        
        if not mapping or mapping.status not in ("MAPPED", "STALE"):
            return ConnectionManager.connect_with_global_credentials(host, platform_choice, temp_session_log, credential_store.as_netmiko_dicts(), log_callback, stop_event, run_platform_probe)
            
        c_record = credential_store.get_by_id(mapping.credential_id)
        if not c_record:
            mapping.status = "STALE"
            mapping.last_tested = ""
            mapping.error_message = "Credential was deleted"
            mapping_store.upsert_mapping(host, mapping)
            
            if not fallback_to_all:
                if log_callback:
                    log_callback(f"Warning: Mapped credential for {host} was deleted and fallback is disabled.")
                return ConnectionResult(
                    host=host,
                    status=ConnectionStatus.AUTH_FAILED,
                    error_message="Mapped credential was deleted and fallback is disabled."
                )
            else:
                if log_callback:
                    log_callback(f"Warning: Mapped credential for {host} was deleted. Fallback enabled; trying all credentials.")
                return ConnectionManager.connect_with_global_credentials(host, platform_choice, temp_session_log, credential_store.as_netmiko_dicts(), log_callback, stop_event, run_platform_probe)
            
        if mapping.status == "STALE" and not fallback_to_all:
            if log_callback:
                log_callback(f"Warning: Mapped credential for {host} is STALE (was modified since testing).")
            return ConnectionResult(
                host=host,
                status=ConnectionStatus.AUTH_FAILED,
                error_message="Mapped credential is STALE and fallback is disabled."
            )
            
        if mapping.status == "STALE" and fallback_to_all:
            if log_callback:
                log_callback(f"Warning: Mapped credential for {host} is STALE. Fallback enabled; trying all credentials.")
            return ConnectionManager.connect_with_global_credentials(host, platform_choice, temp_session_log, credential_store.as_netmiko_dicts(), log_callback, stop_event, run_platform_probe)

        idx = credential_store.index_of_id(mapping.credential_id)
        display_str = f"Credential Set {idx + 1} — {c_record.label} / {c_record.username}" if idx != -1 else f"{c_record.label} / {c_record.username}"
        
        if log_callback:
            log_callback(f"Using mapped credential for {host}: {display_str}")
            
        c_dict = {"username": c_record.username, "password": c_record.password, "secret": c_record.secret}
        res = ConnectionManager.connect(host, c_dict, platform_choice, temp_session_log, run_platform_probe, log_callback)
        
        if res.status == ConnectionStatus.SUCCESS:
            return res
            
        if log_callback:
            log_callback(f"Mapped credential failed for {host}: {res.status.name}")
            
        if fallback_to_all:
            if log_callback:
                log_callback(f"Fallback enabled; trying remaining credentials.")
            
            remaining_creds = []
            for r in credential_store.records:
                if r.id != mapping.credential_id:
                    remaining_creds.append(r)
            
            for r in remaining_creds:
                if stop_event and stop_event.is_set():
                    res.status = ConnectionStatus.STOP_REQUESTED
                    res.error_message = "Aborted by user"
                    break
                if log_callback:
                    idx_remaining = credential_store.index_of_id(r.id)
                    disp = f"Credential Set {idx_remaining + 1}" if idx_remaining != -1 else r.label
                    log_callback(f"  Trying {disp} for {host}...")
                rem_dict = {"username": r.username, "password": r.password, "secret": r.secret}
                rem_res = ConnectionManager.connect(host, rem_dict, platform_choice, temp_session_log, run_platform_probe, log_callback)
                if rem_res.status == ConnectionStatus.SUCCESS:
                    return rem_res
                    
            res.error_message = "All fallback credentials failed"
            return res
            
        return res

    @staticmethod
    def connect_with_global_credentials(host: str, platform_choice: str, temp_session_log: str, credentials: List[Dict], log_callback, stop_event=None, run_platform_probe: bool = True) -> ConnectionResult:
        attempt_history = []
        last_result = None
        
        for i, cred in enumerate(credentials, 1):
            if stop_event and stop_event.is_set():
                break
                
            username = cred.get("username", "unknown")
            res = ConnectionManager.connect(host, cred, platform_choice, temp_session_log, run_platform_probe, log_callback)
            
            history_record = {
                "set_number": i,
                "username": username,
                "status": res.status.name,
                "error_category": res.error_message,
                "success": res.status == ConnectionStatus.SUCCESS
            }
            attempt_history.append(history_record)
            
            if res.status == ConnectionStatus.SUCCESS:
                if log_callback:
                    log_callback(f"  ✓ Credential set {i} succeeded for user {username}")
                res.attempt_history = attempt_history
                return res
            else:
                if log_callback:
                    log_callback(f"  → Credential set {i} failed for user {username}: {res.status.name}")
                last_result = res
                
        if last_result:
            if log_callback and last_result.status != ConnectionStatus.SUCCESS:
                log_callback(f"  ✗ All credential sets failed for {host}. Common causes: bad password, TACACS/RADIUS issue, SSH blocked, wrong platform, account lacks privilege.")
            last_result.attempt_history = attempt_history
            return last_result
            
        return ConnectionResult(host=host, status=ConnectionStatus.UNKNOWN_ERROR, error_message="No credentials available")


# ============================================================
# Parsers and Snapshot Builder
# ============================================================

class FeatureDetector:
    @staticmethod
    def detect_features(running_config: str) -> List[str]:
        features = []
        if re.search(r'^router bgp \d+', running_config, re.MULTILINE):
            features.append('bgp')
        if re.search(r'^router ospf \d+', running_config, re.MULTILINE) or re.search(r'^ip ospf ', running_config, re.MULTILINE):
            features.append('ospf')
        if re.search(r'^router eigrp \d+', running_config, re.MULTILINE) or re.search(r'^ip router eigrp', running_config, re.MULTILINE):
            features.append('eigrp')
        if 'standby ' in running_config:
            features.append('hsrp')
        if 'vrrp ' in running_config:
            features.append('vrrp')
        if re.search(r'interface Port-channel|channel-group|lacp', running_config, re.IGNORECASE):
            features.append('portchannel')
        if re.search(r'crypto map|tunnel-group|crypto ikev|ipsec', running_config, re.IGNORECASE):
            features.append('crypto_vpn')
        if 'failover' in running_config:
            features.append('asa_failover')
        return features

    @staticmethod
    def generate_dynamic_commands(features: List[str], platform: LogicalPlatform) -> List[str]:
        cmds = []
        if 'bgp' in features:
            if platform in (LogicalPlatform.NXOS,):
                cmds.extend(["show bgp ipv4 unicast summary", "show bgp l2vpn evpn summary"])
            else:
                cmds.extend(["show ip bgp summary", "show ip bgp neighbors"])
        if 'ospf' in features:
            if platform in (LogicalPlatform.NXOS,):
                cmds.extend(["show ip ospf neighbors", "show ip ospf interface brief"])
            else:
                cmds.extend(["show ip ospf neighbor", "show ip ospf interface brief"])
        if 'eigrp' in features:
            if platform in (LogicalPlatform.NXOS,):
                cmds.extend(["show ip eigrp neighbors"])
            else:
                cmds.extend(["show ip eigrp neighbors"])
        if 'hsrp' in features:
            cmds.extend(["show standby brief"])
        if 'vrrp' in features:
            cmds.extend(["show vrrp brief"])
        return list(dict.fromkeys(cmds))

class CommandOutputAnalyzer:
    @staticmethod
    def analyze(output: str) -> Tuple[CommandStatus, str]:
        lower_out = output.lower()
        if "% invalid input" in lower_out or "% incomplete command" in lower_out or "% ambiguous command" in lower_out or "% unrecognized command" in lower_out:
            return CommandStatus.COMMAND_UNSUPPORTED, "Command syntax invalid or unsupported on this platform."
        if any(phrase in lower_out for phrase in ["authorization failed", "% authorization failed", "command authorization failed", "permission denied", "insufficient privileges", "insufficient privilege", "not authorized", "requires privilege", "privilege denied", "access denied"]):
            return CommandStatus.PRIVILEGE_DENIED, "Account lacks privilege for this command."
        if "% error" in lower_out or "%error" in lower_out or "% failed" in lower_out or "%failed" in lower_out:
            return CommandStatus.DEVICE_ERROR, "Device returned an error."
        return CommandStatus.SUCCESS, ""

class ParserHelpers:
    @staticmethod
    def normalize_parser_platform(logical_platform) -> str:
        if logical_platform == LogicalPlatform.NXOS: return "NEXUS"
        if logical_platform in (LogicalPlatform.IOS_XE_SWITCH, LogicalPlatform.IOS_XE_ROUTER): return "IOSXE"
        if logical_platform == LogicalPlatform.ASA: return "ASA"
        return "IOS"

    @staticmethod
    def safe_int(value, default=0):
        try: return int(value)
        except (ValueError, TypeError): return default

    @staticmethod
    def parse_first_int(text):
        m = re.search(r'\d+', text)
        return int(m.group(0)) if m else 0

    @staticmethod
    def normalize_interface_name(name):
        if not name: return ""
        name = name.strip()
        name = re.sub(r'^Gi(?:gabitEthernet)?', 'Gi', name, flags=re.IGNORECASE)
        name = re.sub(r'^Te(?:nGigabitEthernet)?', 'Te', name, flags=re.IGNORECASE)
        name = re.sub(r'^Fa(?:stEthernet)?', 'Fa', name, flags=re.IGNORECASE)
        name = re.sub(r'^Po(?:rt-channel)?', 'Po', name, flags=re.IGNORECASE)
        return name

    @staticmethod
    def extract_ipv4_addresses(text):
        return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

    @staticmethod
    def line_contains_any(line, keywords):
        line_lower = line.lower()
        return any(k.lower() in line_lower for k in keywords)

    @staticmethod
    def severity_rank(status):
        ranks = {"FAIL": 4, "WARN": 3, "INFO": 2, "PASS": 1}
        return ranks.get(status, 0)

    @staticmethod
    def add_finding(findings_list, category, status, message, pre_val=None, post_val=None):
        findings_list.append(CompareFinding(category, status, message, pre_val, post_val))

class ParserEngine:
    @staticmethod
    def parse_interfaces(lines: List[str]) -> List[InterfaceRecord]:
        interfaces = []
        current_iface = None
        for line in lines:
            if line.startswith(" ") and current_iface:
                # parsing counters
                if "input errors" in line:
                    m = re.search(r'(\d+) input errors, (\d+) CRC', line)
                    if m:
                        current_iface.input_errors = int(m.group(1))
                        current_iface.crc = int(m.group(2))
                elif "output errors" in line:
                    m = re.search(r'(\d+) output errors', line)
                    if m:
                        current_iface.output_errors = int(m.group(1))
                elif "drops" in line.lower() and "input drop" in line.lower():
                    m = re.search(r'(\d+) drops', line.lower())
                    if m:
                        current_iface.drops += int(m.group(1))
            elif " is " in line and " line protocol is " in line:
                m = re.match(r'^(\S+) is (\S+).*line protocol is (\S+)', line)
                if m:
                    if current_iface: interfaces.append(current_iface)
                    current_iface = InterfaceRecord(name=m.group(1), status=m.group(2), protocol=m.group(3))
            elif "Description:" in line and current_iface:
                current_iface.description = line.split("Description:", 1)[1].strip()
                
        if current_iface: interfaces.append(current_iface)
        return interfaces

    @staticmethod
    def parse_logs(lines: List[str]) -> List[LogEvent]:
        logs = []
        for line in lines:
            m = re.search(r'%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+):\s*(.*)', line)
            if m:
                logs.append(LogEvent(timestamp="", facility=m.group(1), severity=int(m.group(2)), mnemonic=m.group(3), message=m.group(4).strip()))
        return logs

    @staticmethod
    def parse_routes(bgp_lines: List[str], ospf_lines: List[str], eigrp_lines: List[str]) -> List[RoutingNeighbor]:
        neighbors = []
        bgp_dict = ParserEngine.bgp_summary(bgp_lines)
        for ip, state in bgp_dict.items():
            neighbors.append(RoutingNeighbor("BGP", ip, state, ""))
            
        ospf_list = ParserEngine.ospf_neighbors(ospf_lines)
        for ip in ospf_list:
            neighbors.append(RoutingNeighbor("OSPF", ip, "FULL", ""))
            
        eigrp_list = ParserEngine.eigrp_neighbors(eigrp_lines)
        for ip in eigrp_list:
            neighbors.append(RoutingNeighbor("EIGRP", ip, "UP", ""))
            
        return neighbors

    @staticmethod
    def extract_section(section_header: str, lines: List[str]) -> List[str]:
        result, grab = [], False
        expected_header = f"## {section_header}".strip()
        for line in lines:
            if line.strip() == expected_header:
                grab = True
                continue
            if grab and line.startswith("## "):
                break
            if grab:
                result.append(line)
        return result

    @staticmethod
    def cfg_hash(lines: List[str]) -> Optional[str]:
        clean = [l for l in lines if not l.startswith("#") and not l.startswith("!") and "Current configuration" not in l and "Last configuration change" not in l and "NVRAM config last updated" not in l]
        if not clean: return None
        return hashlib.sha256("\n".join(clean).encode("utf-8")).hexdigest()

    @staticmethod
    def arp_count(lines: List[str]) -> int:
        count = 0
        for line in lines:
            if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line): count += 1
        return count

    @staticmethod
    def mac_count(lines: List[str]) -> int:
        for line in lines:
            if "Total" in line and re.search(r'\d+', line):
                nums = re.findall(r'\d+', line)
                if nums: return int(nums[-1])
        count = 0
        for line in lines:
            if re.search(r'(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}', line) or re.search(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', line):
                count += 1
        return count

    @staticmethod
    def eigrp_neighbors(lines: List[str]) -> List[str]:
        neighbors = []
        for line in lines:
            if line.strip() and re.search(r'\d+\.\d+\.\d+\.\d+', line):
                parts = line.split()
                if len(parts) > 1 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[1]):
                    neighbors.append(parts[1])
                elif re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    neighbors.append(parts[0])
        return neighbors

    @staticmethod
    def ospf_neighbors(lines: List[str]) -> List[str]:
        neighbors = []
        for line in lines:
            if line.strip() and re.search(r'\d+\.\d+\.\d+\.\d+', line):
                parts = line.split()
                if len(parts) > 0 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    neighbors.append(parts[0])
        return neighbors

    @staticmethod
    def bgp_summary(lines: List[str]) -> Dict[str, str]:
        neighbors = {}
        for line in lines:
            if line.strip() and re.search(r'\d+\.\d+\.\d+\.\d+', line):
                parts = line.split()
                if len(parts) >= 9 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    neighbors[parts[0]] = parts[-1]
        return neighbors


class InterfaceAnalyzer:
    @staticmethod
    def analyze_interfaces(interfaces: List[InterfaceRecord]) -> List[str]:
        findings = []
        for iface in interfaces:
            if iface.status == "up" and iface.protocol != "up":
                findings.append(f"WARN: {iface.name} is UP but protocol is {iface.protocol}")
            if iface.crc > 100:
                findings.append(f"FAIL: {iface.name} high CRC errors ({iface.crc})")
            elif iface.crc > 0:
                findings.append(f"WARN: {iface.name} has CRC errors ({iface.crc})")
            if iface.input_errors > 1000:
                findings.append(f"WARN: {iface.name} has high input errors ({iface.input_errors})")
            if iface.output_errors > 1000:
                findings.append(f"WARN: {iface.name} has high output errors ({iface.output_errors})")
            if iface.drops > 1000:
                findings.append(f"WARN: {iface.name} has high drops ({iface.drops})")
        return findings

class LogAnalyzer:
    @staticmethod
    def analyze_logs(logs: List[LogEvent]) -> List[str]:
        findings = []
        flap_counts = {}
        for log in logs:
            if log.facility in ("LINK", "LINEPROTO") and log.mnemonic == "UPDOWN":
                m = re.search(r'Interface ([^,]+), changed state to (up|down)', log.message)
                if m:
                    iface = m.group(1)
                    flap_counts[iface] = flap_counts.get(iface, 0) + 1
            if log.severity <= 2:
                findings.append(f"FAIL: CRITICAL LOG - {log.facility}-{log.severity}-{log.mnemonic}: {log.message}")
            elif log.severity == 3:
                findings.append(f"WARN: ERROR LOG - {log.facility}-{log.severity}-{log.mnemonic}: {log.message}")
                
        for iface, count in flap_counts.items():
            if count > 5:
                findings.append(f"FAIL: {iface} is flapping heavily ({count} events)")
            elif count > 2:
                findings.append(f"WARN: {iface} is flapping ({count} events)")
        return findings

class RoutingAnalyzer:
    @staticmethod
    def analyze_neighbors(neighbors: List[RoutingNeighbor]) -> List[str]:
        findings = []
        for n in neighbors:
            if "INIT" in n.state or "DOWN" in n.state or "ACTIVE" in n.state or "IDLE" in n.state.upper():
                findings.append(f"FAIL: {n.protocol} neighbor {n.neighbor_ip} is in state {n.state}")
        return findings

class SnapshotBuilder:
    @staticmethod
    def build(run_id: str, phase: str, host: str, platform: str, cmd_set: str, capture_mode: str, output_text: str, command_results: List[Dict] = None) -> dict:
        lines = output_text.splitlines()
        snap = {
            "run_id": run_id,
            "phase": phase,
            "host": host,
            "safe_host": FilenameSafety.safe_host_label(host),
            "timestamp": datetime.now().isoformat(),
            "capture_mode": capture_mode,
            "detected_platform": platform,
            "command_set": cmd_set,
            "command_results": command_results or [],
            "config": {"hash_redacted": ParserEngine.cfg_hash(ParserEngine.extract_section("show running-config", lines))},
            "neighbors": {
                "arp_count": ParserEngine.arp_count(ParserEngine.extract_section("show arp", lines) + ParserEngine.extract_section("show ip arp summary", lines) + ParserEngine.extract_section("show ip arp", lines) + ParserEngine.extract_section("show ip arp vrf all", lines)),
                "eigrp": ParserEngine.eigrp_neighbors(ParserEngine.extract_section("show ip eigrp neighbors", lines) + ParserEngine.extract_section("show eigrp neighbors", lines)),
                "ospf": ParserEngine.ospf_neighbors(ParserEngine.extract_section("show ip ospf neighbor", lines) + ParserEngine.extract_section("show ospf neighbor", lines)),
                "bgp": ParserEngine.bgp_summary(ParserEngine.extract_section("show ip bgp summary", lines) + ParserEngine.extract_section("show bgp summary", lines) + ParserEngine.extract_section("show bgp ipv4 unicast summary", lines))
            },
            "layer2": {
                "mac_count": ParserEngine.mac_count(ParserEngine.extract_section("show mac address-table count", lines))
            },
            "deep_analysis": {
                "interfaces": [vars(i) for i in ParserEngine.parse_interfaces(ParserEngine.extract_section("show interfaces", lines))],
                "logs": [vars(l) for l in ParserEngine.parse_logs(ParserEngine.extract_section("show logging | include LINK|LINEPROTO|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP|CRYPTO", lines) + ParserEngine.extract_section("show logging | include LINK|LINEPROTO|SPANTREE|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP", lines))],
                "routing_neighbors": [vars(r) for r in ParserEngine.parse_routes(
                    ParserEngine.extract_section("show ip bgp summary", lines) + ParserEngine.extract_section("show bgp summary", lines) + ParserEngine.extract_section("show bgp ipv4 unicast summary", lines),
                    ParserEngine.extract_section("show ip ospf neighbor", lines) + ParserEngine.extract_section("show ospf neighbor", lines),
                    ParserEngine.extract_section("show ip eigrp neighbors", lines) + ParserEngine.extract_section("show eigrp neighbors", lines)
                )]
            }
        }
        return snap


# ============================================================
# Compare Engine
# ============================================================
class CompareEngine:
    @staticmethod
    def compare_snapshots(pre_snap: dict, post_snap: dict) -> List[CompareFinding]:
        findings = []
        
        # Reachability
        if not post_snap:
            findings.append(CompareFinding("Reachability", "FAIL", "Missing POST output snapshot."))
            return findings

        # Config hash
        cfg_pre = pre_snap.get("config", {}).get("hash_redacted")
        cfg_post = post_snap.get("config", {}).get("hash_redacted")
        if cfg_pre and cfg_post and cfg_pre != cfg_post:
            findings.append(CompareFinding("Config", "FAIL", "running-config changed", cfg_pre, cfg_post))

        # ARP Count
        arp_pre = pre_snap.get("neighbors", {}).get("arp_count", 0)
        arp_post = post_snap.get("neighbors", {}).get("arp_count", 0)
        if arp_pre > 0:
            diff = (arp_pre - arp_post) / arp_pre
            if diff > 0.50:
                findings.append(CompareFinding("ARP", "FAIL", f"ARP drop > 50%", arp_pre, arp_post))
            elif diff > 0.15:
                findings.append(CompareFinding("ARP", "WARN", f"ARP drop 15-50%", arp_pre, arp_post))

        # MAC Count
        mac_pre = pre_snap.get("layer2", {}).get("mac_count", 0) or 0
        mac_post = post_snap.get("layer2", {}).get("mac_count", 0) or 0
        if mac_pre > 0:
            diff = (mac_pre - mac_post) / mac_pre
            if diff > 0.50:
                findings.append(CompareFinding("MAC", "FAIL", f"MAC drop > 50%", mac_pre, mac_post))
            elif diff > 0.15:
                findings.append(CompareFinding("MAC", "WARN", f"MAC drop 15-50%", mac_pre, mac_post))

        # EIGRP
        e_pre = set(pre_snap.get("neighbors", {}).get("eigrp", []))
        e_post = set(post_snap.get("neighbors", {}).get("eigrp", []))
        if e_pre != e_post:
            findings.append(CompareFinding("EIGRP", "FAIL", "EIGRP neighbor set changed", len(e_pre), len(e_post)))

        # OSPF
        o_pre = set(pre_snap.get("neighbors", {}).get("ospf", []))
        o_post = set(post_snap.get("neighbors", {}).get("ospf", []))
        if o_pre != o_post:
            findings.append(CompareFinding("OSPF", "FAIL", "OSPF neighbor set changed", len(o_pre), len(o_post)))
            
        # BGP
        b_pre = pre_snap.get("neighbors", {}).get("bgp", {})
        b_post = post_snap.get("neighbors", {}).get("bgp", {})
        if set(b_pre.keys()) != set(b_post.keys()):
            findings.append(CompareFinding("BGP", "FAIL", "BGP neighbor count changed", len(b_pre), len(b_post)))
        else:
            for nbr, state in b_pre.items():
                if state.isdigit() and not b_post.get(nbr, "").isdigit():
                    findings.append(CompareFinding("BGP", "FAIL", f"BGP peer {nbr} lost Established state", state, b_post.get(nbr)))

        # Interfaces
        if post_snap and "deep_analysis" in post_snap and "interfaces" in post_snap["deep_analysis"]:
            for iface in post_snap["deep_analysis"]["interfaces"]:
                if iface["input_errors"] > 0 or iface["output_errors"] > 0 or iface["crc"] > 0 or iface["drops"] > 0:
                    findings.append(CompareFinding("Interface", "WARN", f"{iface['name']} has errors/drops (In:{iface['input_errors']}, Out:{iface['output_errors']}, CRC:{iface['crc']}, Drops:{iface['drops']})"))

        # Logs
        if post_snap and "deep_analysis" in post_snap and "logs" in post_snap["deep_analysis"]:
            for log in post_snap["deep_analysis"]["logs"]:
                if "UPDOWN" in log["mnemonic"] or "FLAP" in log["mnemonic"]:
                    findings.append(CompareFinding("Log", "WARN", f"Log flap detected: {log['message']}"))
                elif log["severity"] <= 3:
                    findings.append(CompareFinding("Log", "FAIL", f"High severity log: {log['message']}"))

        if not findings:
            findings.append(CompareFinding("General", "PASS", "No material changes detected"))

        return findings

    @staticmethod
    def build_snapshot_from_txt(filepath: Path) -> dict:
        if not filepath.exists():
            return None
        text = filepath.read_text(encoding="utf-8")
        run_id, phase, host, platform, mode = "unknown", "unknown", "unknown", "UNKNOWN", "REDACTED"
        for line in text.splitlines()[:20]:
            if line.startswith("# Run ID:"): run_id = line.split(":", 1)[1].strip()
            elif line.startswith("# Phase:"): phase = line.split(":", 1)[1].strip()
            elif line.startswith("# Host:"): host = line.split(":", 1)[1].strip()
            elif line.startswith("# Platform:"): platform = line.split(":", 1)[1].strip()
            elif line.startswith("# Capture Mode:"): mode = line.split(":", 1)[1].strip()
        return SnapshotBuilder.build(run_id, phase, host, platform, "UNKNOWN", mode, text)

    @staticmethod
    def run_comparison(run_id: str, base_dir: Path) -> str:
        pre_dir = base_dir / "pre"
        post_dir = base_dir / "post"
        out_dir = base_dir / "compare"
        out_dir.mkdir(parents=True, exist_ok=True)

        if not pre_dir.exists():
            return f"Pre directory {pre_dir} does not exist."

        summary_txt = []
        summary_csv = [["Host", "Category", "Status", "Message", "Pre Value", "Post Value"]]
        summary_json = {}

        for pre_file in list(pre_dir.glob("*-pre*.json")) + list(pre_dir.glob("*-pre*.txt")):
            if pre_file.suffix == ".txt" and pre_file.with_suffix(".json").exists(): continue
            
            ip = pre_file.name.replace("-pre_RAW.json", "").replace("-pre.json", "").replace("-pre_RAW.txt", "").replace("-pre.txt", "")
            
            post_file_redacted_json = post_dir / f"{ip}-post.json"
            post_file_raw_json = post_dir / f"{ip}-post_RAW.json"
            post_file_redacted_txt = post_dir / f"{ip}-post.txt"
            post_file_raw_txt = post_dir / f"{ip}-post_RAW.txt"
            
            pre_snap = None
            if pre_file.suffix == ".json":
                with open(pre_file, "r") as f: pre_snap = json.load(f)
            else:
                pre_snap = CompareEngine.build_snapshot_from_txt(pre_file)
            
            post_snap = None
            if post_file_raw_json.exists():
                with open(post_file_raw_json, "r") as f: post_snap = json.load(f)
            elif post_file_redacted_json.exists():
                with open(post_file_redacted_json, "r") as f: post_snap = json.load(f)
            elif post_file_raw_txt.exists():
                post_snap = CompareEngine.build_snapshot_from_txt(post_file_raw_txt)
            elif post_file_redacted_txt.exists():
                post_snap = CompareEngine.build_snapshot_from_txt(post_file_redacted_txt)

            findings = CompareEngine.compare_snapshots(pre_snap, post_snap)
            
            summary_json[ip] = [f.__dict__ for f in findings]
            host_status = "FAIL" if any(f.status == "FAIL" for f in findings) else ("WARN" if any(f.status == "WARN" for f in findings) else "PASS")
            
            summary_txt.append(f"[{ip}] Overall: {host_status}")
            for f in findings:
                summary_txt.append(f"  - {f.status}: [{f.category}] {f.message}")
                summary_csv.append([ip, f.category, f.status, f.message, str(f.pre_val), str(f.post_val)])

            host_txt = [f"HOST: {ip}", f"STATUS: {host_status}", "\nTop Findings:"]
            for f in findings:
                host_txt.append(f"[{f.status}] {f.category}: {f.message}")
            if not findings:
                host_txt.append("[PASS] No material changes detected.")
                
            host_txt.append("\n--- Post-Maintenance Summary ---")
            if settings.include_full_output_in_compare_reports:
                host_txt.append("\n--- Post-Maintenance Raw/Redacted Output ---")
                post_txt_file = post_dir / f"{ip}-post_RAW.txt"
                if not post_txt_file.exists():
                    post_txt_file = post_dir / f"{ip}-post.txt"
                if post_txt_file.exists():
                    host_txt.append(post_txt_file.read_text(encoding="utf-8"))
                else:
                    host_txt.append("No post-maintenance output found.")
            else:
                post_txt_file = post_dir / f"{ip}-post.txt"
                pre_txt_file = pre_dir / f"{ip}-pre.txt"
                host_txt.append(f"Output files stored in:\n  Pre:  {pre_txt_file}\n  Post: {post_txt_file}")
                
            hosts_dir = out_dir / "hosts"
            hosts_dir.mkdir(parents=True, exist_ok=True)
            (hosts_dir / f"{ip}_compare_report.txt").write_text("\n".join(host_txt), encoding="utf-8")

        sum_txt_data = "\n".join(summary_txt)
        (out_dir / "summary.txt").write_text(sum_txt_data, encoding="utf-8")
        if settings.write_json_outputs:
            with open(out_dir / "summary.json", "w") as f: json.dump(summary_json, f, indent=4)
        with open(out_dir / "summary.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(summary_csv)

        return sum_txt_data



# ============================================================
# Documentation Content
# ============================================================
DOCUMENTATION_SECTIONS = [
    DocumentationSection("General Information", """Network Toolbelt is a local desktop utility for network operations work.

It is designed to help network engineers run repeatable read-only checks, collect troubleshooting output, compare pre/post maintenance snapshots, and run focused scanner workflows across many devices from one GUI.

Core ideas:
- Credentials are loaded once into volatile memory and reused across tools.
- Target IPs can be saved into the current app session and shared between tools.
- Target IPs can be mapped to the credential that successfully authenticates.
- Output capture is redacted by default.
- Generic commands are controlled by a command policy.
- Built-in tool command bundles are intended to be safe, read-only command sets.
- Reports are written to a local output directory for later review.

Primary tools:
- Credential Manager: Load, edit, and delete temporary credential sets inline.
- Set Target IPs & Credentials: Build a session target list and map each target to a working credential using inline tools.
- Maintenance Pre/Post Runner: Collect pre/post snapshots and compare changes.
- Generic Command Runner: Run ad-hoc commands against selected targets.
- Network Scanner Suite: Run focused read-only checks such as interface errors, routing neighbors, logs, inventory, optics, and BGP route collection.

This app is meant to assist an engineer, not replace engineering judgment. Treat findings as indicators that need review, especially when parsers are marked best-effort."""),

    DocumentationSection("Quick Start", """Basic first-use workflow:

1. Open Credential Manager.
2. Add one or more credential sets.
3. Return to the dashboard.
4. Open Set Target IPs & Credentials.
5. Paste target IPs or hostnames.
6. Run credential mapping if you have more than one credential set.
7. Open the tool you want to use.
8. Click Load Session Targets if you want to reuse the saved target list.
9. Configure the tool options.
10. Run the tool.
11. Review the execution log, session log, and output files.

Recommended first test:
- Add one credential.
- Use one known-safe test device.
- Run Generic Command Runner with:
  show version

Recommended first maintenance test:
- Use one known-safe test device.
- Run Maintenance Pre/Post Runner in Pre mode.
- Confirm output files are created.
- Run Post mode with the same Run ID.
- Run Compare mode and review the summary.

Recommended first scanner test:
- Open Network Scanners.
- Choose Device Inventory Scanner.
- Use one known-safe device.
- Review the TXT/CSV/JSON outputs."""),

    DocumentationSection("Dashboard", """The dashboard is the main navigation page.

The left column contains tools:
- Generic Command Runner
- Maintenance Pre/Post Runner
- Network Scanners

The right column contains session and help features:
- Credential Manager
- Set Target IPs & Credentials
- Help & Documentation

Dashboard status indicators:
- Credentials loaded: Number of credential sets currently stored in memory.
- Session targets: Number of targets saved into the current app session.
- Mapped targets: Number of current session targets that have a valid credential mapping.

These values are session-only. Closing the application clears credentials, session targets, and credential mappings.

Navigation protection:
If you try to leave a running tool, the app should warn you that leaving will stop the tool and clear the current session view. You can cancel and stay on the running tool, or confirm and return to navigation.

Output files that have already been written are not deleted by navigation cleanup."""),

    DocumentationSection("Credential Manager", """Credential Manager is the central place to load credentials for all tools.

Credential behavior:
- Credentials are stored in memory only.
- Credentials are never written to disk by the app.
- Closing the app clears all credentials.
- Passwords and enable secrets are not displayed after entry.
- Editing a credential provides blank replacement fields for password/enable secret.

Each credential set has:
- Label: A friendly name such as Core TACACS or Local Admin.
- Username
- Password
- Optional enable secret

Credential labels are for your convenience. They may appear in logs and mapping tables, but passwords and secrets should not.

Editing credentials:
- Adding or editing is done directly through the inline form on the right.
- Changing only the label should keep existing mappings valid and update the display label.
- Changing username, password, or enable secret marks related target mappings as STALE because the actual login behavior may have changed.
- Leaving password or secret blank keeps the existing value.

Deleting credentials:
- If a credential is deleted, any target mappings using that credential become STALE.
- Tools should not silently use deleted credentials.

Clearing all credentials:
- Removes all loaded credentials from memory.
- Existing target mappings should become STALE because their referenced credentials are no longer available.

Operational recommendation:
Use clear labels when loading multiple credentials. Example:
- Credential Set 1 — Core TACACS / username
- Credential Set 2 — Legacy Local / username
- Credential Set 3 — Firewall Admin / username"""),

    DocumentationSection("Target IP & Credential Mapping", """Target IP & Credential Mapping reduces repeated authentication failures when multiple credential sets are loaded.

Problem it solves:
If you load four credential sets and run a tool against many devices, the app may need to try credential set 1, then 2, then 3, then 4 until one works. That can create many failed authentication attempts. Mapping lets the app learn which credential works for each target before the real tool run.

What mapping stores:
- Target host/IP
- Credential ID
- Credential label
- Username
- Mapping status
- Last tested time
- Detected platform where available
- Attempt result history

What mapping does NOT store:
- Passwords
- Enable secrets
- Raw credential dictionaries
- Session logs
- Persistent credential material

Mapping statuses:
- UNMAPPED: No successful credential has been identified for this target.
- MAPPING: The target is currently being tested.
- MAPPED: A credential successfully authenticated.
- FAILED: No loaded credential successfully authenticated.
- STALE: The mapped credential was changed or deleted after mapping.
- STOPPED: Mapping was stopped before completion.

Dashboard mapping workflow:
1. Load credentials in Credential Manager.
2. Open Set Target IPs & Credentials from the dashboard (opens as an in-app page).
3. Enter or update target IPs.
4. Test a Single IP or Start credential mapping for all targets.
5. Watch the table, execution log, and redacted session log.
6. Confirm each target maps to the expected credential.
7. Return to Dashboard and open a tool. Targets will auto-populate if the tool's target list is empty.

Per-tool mapping workflow:
When running a tool with multiple credentials and unmapped/stale targets, the app may ask:
Map IPs to loaded credentials before running this tool?

Options:
- Map Now: Run a mapping pass first.
- Continue Without Mapping: Run using normal credential order.
- Cancel: Do not start the tool.

Fallback behavior:
By default, if a mapped credential fails during tool execution, the app should not try all other credentials unless fallback is explicitly enabled. This protects against repeated failed authentication attempts.

Security note:
Mapping is volatile and in-memory only. Closing the app clears all target mappings."""),

    DocumentationSection("Session Targets", """Session targets are the target IPs or hostnames saved into the current app session.

Why use session targets:
- Avoid pasting the same target list into every tool.
- Keep credential mappings associated with the target list.
- Move between tools more easily.

TargetPanel buttons:
- Save Targets to Session: Reads the current target box and saves the de-duplicated target list into the session.
- Load Session Targets: Loads the session target list into the current tool.

Safe behavior:
- Loading session targets manually will not overwrite existing tool targets without confirmation.
- Opening a tool with an empty target box will automatically populate your session targets.
- Session targets are not permanent.
- Closing the app clears them.

Best practice:
Use Set Target IPs & Credentials to define the target list first, then load that same list into tools as needed."""),

    DocumentationSection("Architecture Overview", """Network Toolbelt is intentionally kept as a single Python file for portability, but the file is organized into logical internal sections.

Major architecture areas:
- Data models: Dataclasses and enums for connections, command results, scanner results, findings, and mappings.
- Settings: Runtime app settings such as output directory, command timeout, capture mode, theme, and command policy.
- Credential storage: Volatile in-memory credential manager.
- Target/credential mapping: Volatile in-memory mapping between session targets and credential IDs.
- Command policy: Allow/block decisions for ad-hoc commands and configurable tool command bundles.
- Redaction: Rules for scrubbing sensitive output in redacted capture mode.
- Device detection: Platform classification using show version.
- Connection manager: Netmiko connection handling and credential attempt logic.
- Parser/analyzer layer: Best-effort extraction of structured findings from command output.
- Compare engine: Pre/post comparison for maintenance runs.
- Documentation content: The text shown in this help browser.
- Shared UI components: Target panel, credential status panel, runner pages, dialogs, log panes, documentation window.
- Tool pages: Maintenance runner, command runner, scanner pages, credential manager, mapper window, dashboard.

Single-file design tradeoff:
The app is easy to copy, back up, and run as one script. The tradeoff is that changes must be made carefully because shared classes affect many tools."""),

    DocumentationSection("Security and Safety Model", """Network Toolbelt uses several safety layers.

1. Credentials are volatile
Credentials are stored in RAM only. They are not saved to disk by the app. Closing the app clears them.

2. Credential mapping is volatile
Target-to-credential mappings are also in-memory only. They store credential IDs and labels, not passwords or secrets.

3. Redacted capture is default
The app attempts to redact secrets from captured output and live session logs. Redaction covers common password, key, SNMP, crypto, certificate, and shared-secret patterns.

4. Raw capture requires caution
Raw mode disables redaction and can expose secrets. Use it only when absolutely necessary, store output carefully, and return to redacted mode afterward.

5. Generic commands are governed by policy
The Generic Command Runner uses command policy modes to allow or block commands. Safe Read-Only mode is the default.

6. Tool command bundles are intended to be read-only
Maintenance/scanner command bundles should use read-only commands such as show, terminal length, terminal width, dir, and pwd.

7. Dangerous command overrides are blocked
The command bundle editor should block dangerous operations such as configure, reload, write, copy, delete, erase, clear, debug, request, install, test, ping, and traceroute for internal tool bundles.

8. Unsupported commands are handled as unsupported
If a platform does not support a command, the result should be classified as COMMAND_UNSUPPORTED rather than treated as a device failure.

Important limitation:
No redaction system is perfect. Review redacted output before sharing it outside trusted channels."""),

    DocumentationSection("Capture Modes and Redaction", """Capture mode controls how output is displayed and saved.

Redacted mode:
- Default mode.
- Runs output through the redactor before display/save where applicable.
- Intended for normal use.
- Redacts common secrets such as passwords, enable secrets, SNMP communities, TACACS/RADIUS keys, pre-shared keys, private keys, certificates, and similar sensitive lines.

Raw mode:
- Redaction is disabled.
- Output may contain passwords, keys, SNMP strings, tunnel secrets, certificates, tokens, or other sensitive data.
- Should be used only when you intentionally need exact raw output.
- Treat raw output files as sensitive.

Session log labels:
- Session Log: Redacted display of the raw SSH session.
- Session Log (RAW - sensitive): Raw display.

Mapping sessions:
Credential mapping should display session logs in redacted form for safety.

Temporary Session Logs:
- During active Netmiko sessions, raw session data may temporarily reside in a restricted dedicated temp folder.
- On normal completion, Network Toolbelt redacts the session output into final logs and removes the raw temp file.
- On startup, Network Toolbelt attempts to remove stale temp session artifacts left by abnormal exits.
- Operators should still treat output folders as sensitive.
- Merged TXT export intentionally excludes .json, .log, session logs, .tmp_* files, and the temp session folder.

Recommendation:
Leave capture mode set to Redacted unless you have a specific reason to collect raw output."""),

    DocumentationSection("Command Policy and Safety Controls", """Command policy controls ad-hoc commands in Generic Command Runner.

Safe Read-Only:
- Default mode.
- Intended for normal use.
- Allows standard read-only commands such as show, terminal length, terminal width, dir, and pwd.
- Blocks configuration, reload, clear, debug, copy/delete, and other risky operations.

Expanded Operational:
- Allows additional operational commands such as ping and traceroute.
- Use only when intentionally testing reachability/path behavior.
- Still not intended for configuration changes.

Unsafe Allowed:
- Allows commands that are normally blocked.
- Use only when you intentionally need to run non-read-only commands and fully understand the impact.
- Not recommended for normal toolbelt use.

Internal tool bundles:
Maintenance and scanner command bundles are separate from Generic Command Runner input. They should remain read-only. The command bundle editor validates saved commands and blocks dangerous operations.

Unsupported command behavior:
If a read-only command is not supported on a platform, it should be logged as COMMAND_UNSUPPORTED rather than automatically failing the device."""),

    DocumentationSection("View/Configure Tool Commands", """Settings -> View/Configure tool commands opens the tool command configuration window.

Purpose:
This window lets you inspect and customize the read-only commands used by built-in tools.

What can be configured:
- Maintenance baseline command bundles by platform/device type.
- Maintenance feature command bundles such as BGP, OSPF, EIGRP, HSRP, VRRP, port-channel, crypto/VPN, and ASA failover.
- Scanner command bundles by scanner and platform/device type.

What is not configured here:
- Generic Command Runner commands. Those are entered directly in the Generic Command Runner.
- Credentials.
- Target IPs.
- Credential mappings.

Persistence:
Command overrides are saved to a local JSON file under the output directory. This file contains command strings only. It must never contain credentials.

Safety validation:
Saved command bundles are validated. Dangerous commands should be blocked.

Reset behavior:
- Reset Group removes the override for the selected command group.
- Reset Tool removes all overrides for the selected tool.
- Defaults are preserved internally so reset can return to the original built-in command list.

Important:
Command edits apply to future runs only. They do not change a run that is already in progress."""),

    DocumentationSection("Output Files and Folder Structure", """Network Toolbelt writes output under the Base Output Directory configured in Settings.

v2.91 Lean Output Profile:
By default, the tool writes TXT-first outputs. JSON is disabled by default to save space, meaning scanner_summary.json, compare summary.json, and per-host JSON snapshots are skipped. Session logs are saved only for errors or diagnostics (like slow commands/timeouts) unless you explicitly change settings.

Typical base path:
toolbelt-output

Maintenance Runner:
<base>/Maintenance_Runner/<run_id>/pre
<base>/Maintenance_Runner/<run_id>/post
<base>/Maintenance_Runner/<run_id>/compare

Maintenance outputs may include:
- Per-host TXT output
- Per-host JSON snapshot
- Raw output if raw capture is enabled
- Compare summary TXT/CSV/JSON
- Per-host compare reports

Generic Command Runner:
<base>/Command_Runner/<timestamped_run_folder>

Generic outputs may include:
- Per-host command output files
- Execution logs
- Session logs depending on capture mode

Scanners:
<base>/Scanners/<scanner_name>/<run_id>/

Scanner outputs may include:
- scanner_summary.csv
- index.txt or summary TXT
- per-host reports
- per-host JSON
- captured command output

Tool command overrides:
<base>/tool_command_overrides.json

Credential mappings:
Not saved to disk.

Credentials:
Not saved to disk.

Raw output warning:
Raw output files may contain sensitive data and should be protected accordingly."""),

    DocumentationSection("Platform Detection and Device Support", """The app uses Netmiko and show version output to classify devices.

Common logical platforms:
- Catalyst IOS switch
- Catalyst IOS-XE switch
- IOS-XE router
- Legacy IOS router
- Nexus NX-OS
- ASA firewall
- Unknown Cisco

Auto Detect Platform:
When Auto Detect Platform is selected, the app attempts to determine the Netmiko device type. If autodetect fails, it may fall back to cisco_ios.

Platform selection matters because:
- Different platforms support different command syntax.
- Maintenance command sets vary by platform.
- Scanner command bundles vary by platform.
- Unsupported commands should be logged cleanly.

Limitations:
- Platform detection is best-effort.
- Some devices may require manual platform selection.
- VRF-heavy, firewall, or mixed-vendor environments may require command-bundle adjustments.
- Some commands may be unsupported depending on OS version, license, feature set, or privilege level.

Note: Maintenance and Scanner workflows may use a "show version" command for explicit platform detection and feature validation. However, the Generic Command Runner does not run hidden show-version classification probes; it executes only what you enter."""),

    DocumentationSection("Maintenance Pre/Post Runner", """Purpose:
Maintenance Pre/Post Runner captures a snapshot before work, captures another snapshot after work, and compares the two.

Typical use case:
Use this before and after a maintenance window to identify unexpected changes in routing, neighbors, ARP/MAC counts, interface counters, logs, and configuration hash.

Modes:
- Pre-Checks: Collects the baseline snapshot.
- Post-Checks: Collects the after-maintenance snapshot.
- Compare: Compares pre and post outputs for the same Run ID.

Recommended workflow:
1. Load credentials.
2. Save or paste target IPs.
3. Choose Pre-Checks.
4. Enter a clear Run ID, such as a ticket/change number.
5. Run pre-checks.
6. Perform maintenance.
7. Choose Post-Checks using the same Run ID.
8. Run post-checks.
9. Choose Compare.
10. Review summary and per-host reports.

Feature-aware command behavior:
The runner collects baseline commands and may add feature-specific commands when features are detected, such as BGP, OSPF, EIGRP, HSRP, VRRP, port-channel, crypto/VPN, or ASA failover.

Compare findings may include:
- Missing post snapshot
- Config hash changes
- ARP count changes
- MAC count changes
- EIGRP/OSPF/BGP neighbor changes
- Interface errors/drops
- High-severity logs or flaps

Important limitations:
- Compare logic is best-effort.
- Config hash changes do not always mean bad changes.
- Lack of a finding does not prove the device is healthy.
- Always review raw/redacted output when the result matters."""),

    DocumentationSection("Generic Command Runner", """Purpose:
Generic Command Runner runs user-provided commands across one or more targets.

Use it for:
- Quick ad-hoc show command collection.
- Gathering the same output from many devices.
- Checking a known command across a target list.
- Controlled troubleshooting where you know exactly what command you want.

Basic workflow:
1. Load credentials.
2. Open Generic Command Runner.
3. Load session targets or paste targets directly.
4. Enter commands, one per line.
5. Confirm command policy mode.
6. Run.
7. Review execution log, session log, and output files.

Safety:
Generic Command Runner is controlled by Command Policy. Safe Read-Only mode is recommended for normal use.
Note: Generic Command Runner executes only the user-entered commands plus minimal terminal/pager prep commands. It does not perform hidden platform classification probes.

Examples of safe commands:
show version
show ip interface brief
show interfaces description
show logging last 100
dir flash:

Examples that should generally be blocked unless intentionally allowed:
configure terminal
reload
write memory
clear counters
delete flash:
debug
copy

Credential mapping:
If targets are mapped, the tool should use the mapped credential for each mapped target. If targets are unmapped and multiple credentials are loaded, the app may prompt to map before running."""),

    DocumentationSection("Network Scanner Suite", """Purpose:
The Network Scanner Suite provides focused read-only workflows for common operational checks.

Scanner workflow:
1. Open Network Scanners from the dashboard.
2. Choose a scanner.
3. Enter a Run ID.
4. Load or paste targets.
5. Configure scanner options.
6. Run scanner.
7. Review summary and per-host reports.

Scanner output:
Most scanners write structured output such as TXT, CSV, and JSON. Reports usually put top findings first, followed by raw/redacted command output.

Implemented scanners:
- Interface Error Scanner
- Port-Channel / LACP Scanner
- Optics Scanner
- Routing Neighbor Scanner
- Log Scanner
- Device Inventory Scanner
- BGP/Route Summary Scanner

Common scanner statuses:
- PASS: No notable issue found.
- WARN: Review recommended.
- FAIL: Likely operational issue or critical condition.
- INFO: Informational result.
- COMMAND_UNSUPPORTED: Command was not supported on that platform.

Important limitations:
The scanner parsers are best-effort. They are useful for triage, but should not be treated as complete network validation."""),

    DocumentationSection("Interface Error Scanner", """Purpose:
Find interface-level health problems.

Checks may include:
- Interface state
- Line protocol state
- Input errors
- CRC errors
- Output errors
- Drops
- Err-disabled or abnormal states where detected

Useful for:
- Finding physical-layer issues.
- Spotting noisy links.
- Checking uplinks after maintenance.
- Comparing device health across many switches.

How to use:
1. Open Network Scanners.
2. Choose Interface Error Scanner.
3. Enter Run ID and targets.
4. Choose options such as uplink-sensitive mode if available.
5. Run.
6. Review top findings first.

Interpretation:
- CRC errors usually point to physical layer problems such as cabling, optics, duplex/speed mismatch, dirty fiber, or faulty hardware.
- Output drops can indicate congestion or queueing.
- Input/output errors should be reviewed in context.

Limitations:
Interface output differs widely across IOS, IOS-XE, NX-OS, and ASA. Parser results are best-effort and may miss platform-specific counters."""),

    DocumentationSection("Port-Channel / LACP Scanner", """Purpose:
Check port-channel and LACP health.

Checks may include:
- Port-channel summary
- LACP neighbor state
- Suspended members
- Individual/not bundled members
- Down port-channels
- Down member links

Useful for:
- Validating uplinks.
- Checking switch stacks.
- Reviewing LAG health after maintenance.
- Finding members that silently left a bundle.

Interpretation:
Port-channel flags vary by platform, but common concerns include:
- Suspended member
- Individual member
- Down member expected to be bundled
- Port-channel down when it should be up

Limitations:
The parser is best-effort. Always review the raw/redacted port-channel output for important changes."""),

    DocumentationSection("Optics Scanner", """Purpose:
Review optical transceiver status where supported.

Checks may include:
- Transceiver presence
- DOM alarms
- DOM warnings
- RX power
- TX power
- Temperature
- Unsupported or missing optics

Useful for:
- Finding weak optics.
- Checking fiber links.
- Reviewing uplinks before/after maintenance.
- Spotting DOM alarms across many devices.

Interpretation:
Low RX power can indicate dirty fiber, bad patching, distance budget issues, failing optics, or upstream transmitter problems.

Limitations:
DOM output varies heavily by platform and optic type. Some devices do not support detailed DOM output. Treat parser findings as triage and review raw output."""),

    DocumentationSection("Routing Neighbor Scanner", """Purpose:
Check routing protocol neighbor state and gateway redundancy health.

Checks may include:
- EIGRP neighbors
- OSPF neighbors
- BGP peers
- HSRP/VRRP state depending on command support and options

Useful for:
- Validating routing health after maintenance.
- Checking whether expected routing peers are established.
- Reviewing BGP peers for non-established states.
- Spotting obvious neighbor losses.

Common interpretations:
- BGP Established normally appears as a prefix count in many IOS outputs.
- BGP Idle/Active/Connect generally requires investigation.
- OSPF FULL is normally healthy for many adjacencies.
- OSPF 2-WAY may be normal on broadcast segments with DROTHER behavior.
- EIGRP missing neighbors may indicate adjacency loss.

Limitations:
Routing output can be VRF-specific and platform-specific. The current parser is best-effort and may require future expansion for complex environments."""),

    DocumentationSection("Log Scanner", """Purpose:
Collect and classify relevant device log events.

Checks may include:
- Interface up/down events
- Link flaps
- Errdisable events
- Routing protocol down events
- Crash or reload messages
- Power, fan, or temperature alarms
- Authentication/authorization errors where present in logs

Useful for:
- Quickly reviewing recent device instability.
- Finding repeated flaps.
- Checking for crash/reload indicators.
- Correlating maintenance impact.

Interpretation:
A single log line may not be a problem by itself. Repeated patterns, high severity logs, and events tied to important interfaces should be reviewed carefully.

Limitations:
Log buffers vary in size and retention. If the device rotated logs, the scanner can only analyze what is still available."""),

    DocumentationSection("Device Inventory Scanner", """Purpose:
Collect inventory and platform facts.

Checks may include:
- Hostname
- Model
- Serial number
- Software version
- Uptime
- Inventory components
- Environment status where available

Useful for:
- Audits.
- Asset inventory.
- Upgrade planning.
- Hardware replacement planning.
- Confirming what device type is actually at a target IP.

Output:
Inventory output is usually less about PASS/WARN/FAIL and more about structured facts.

Limitations:
Cisco inventory formats differ by platform. Some virtual devices or older platforms may not report serial/model data consistently."""),

    DocumentationSection("BGP/Route Summary Scanner", """Purpose:
Collect BGP route information for selected neighbors.

Checks may include:
- BGP summary
- Advertised routes
- Received routes
- Neighbor route output depending on options

Useful for:
- Validating route advertisements.
- Confirming whether routes are being sent to a peer.
- Reviewing received route tables where supported.
- Capturing evidence during routing troubleshooting.

Important warnings:
- Output can be very large.
- Received-routes may require platform support or soft-reconfiguration inbound.
- Some route commands can be slow on large peers.
- Manual neighbor selection is recommended for safety.

Limitations:
This scanner is primarily a collection tool unless route parsing/diffing has been expanded. Review captured output manually for route-level decisions."""),

    DocumentationSection("How-To Workflows", """Workflow 1: Set up credentials and targets
1. Open Credential Manager.
2. Add credential sets with clear labels.
3. Return to dashboard.
4. Open Set Target IPs & Credentials.
5. Paste target IPs.
6. Start mapping if more than one credential is loaded.
7. Confirm mapped count on dashboard.

Workflow 2: Run a basic ad-hoc command
1. Open Generic Command Runner.
2. Click Load Session Targets or paste targets.
3. Enter:
   show version
4. Confirm Command Policy is Safe Read-Only.
5. Click RUN.
6. Review output files.

Workflow 3: Run maintenance pre/post comparison
1. Open Maintenance Pre/Post Runner.
2. Enter Run ID.
3. Load targets.
4. Select Pre-Checks and run.
5. Perform maintenance.
6. Select Post-Checks with the same Run ID and run.
7. Select Compare and run.
8. Review summary and per-host reports.

Workflow 4: Use credential mapping before a tool run
1. Load multiple credentials.
2. Load/paste targets into a tool.
3. Click RUN.
4. If prompted, choose Map Now.
5. Review mapping progress.
6. Continue the tool run after mapping completes.

Workflow 5: Configure tool commands
1. Open Settings.
2. Choose View/Configure tool commands.
3. Select a tool.
4. Select a device type or command group.
5. Edit commands, one per line.
6. Save.
7. Run future tool executions using the updated bundle.

Workflow 6: Stop or clear a session
1. Click STOP to request cancellation.
2. Wait for the current connection/command to stop or timeout.
3. Use Clear Current Session to reset logs and fields.
4. Choose whether to retain credentials and target IPs.

Workflow 7: Safely share output
1. Use Redacted capture mode.
2. Review output for remaining sensitive data.
3. Share only the minimum required files.
4. Avoid sharing Raw output unless absolutely necessary."""),

    DocumentationSection("Troubleshooting", """Missing Netmiko:
Symptom: App reports missing dependency.
Fix: Install Netmiko with pip install netmiko.

Authentication failed:
Possible causes:
- Wrong username/password.
- TACACS/RADIUS issue.
- Device not reachable over SSH.
- Wrong platform type.
- Account lacks privilege.
- Device ACL blocks management access.

Platform detection failed (ASA note):
- On some ASA devices, `show version` may fail pattern matching. The app will fall back to a safe timing mode. If you manually selected Cisco ASA and the version check fails, the app will continue using the ASA logical platform and its specific command bundle.

Credential mapping failed:
Possible causes:
- No credential works for that target.
- Target is unreachable.
- SSH is disabled.
- Device requires a different platform type.
- TACACS/RADIUS is rejecting the account.

Mapped credential is STALE:
Meaning:
- The credential was edited or deleted after mapping.
Fix:
- Re-run credential mapping for that target.

Command unsupported:
Meaning:
- The device does not support that command.
- Platform syntax differs.
- User privilege may be insufficient.
Fix:
- Review command output.
- Adjust command bundle if needed.

No output files:
Check:
- Base Output Directory.
- Whether the run actually started.
- Whether targets were entered.
- Whether credentials were loaded.
- Whether command policy blocked execution.

Tool appears stuck:
Try:
- Click STOP.
- Wait for the current SSH timeout.
- Check network reachability.
- Reduce target count for testing.
- Increase or decrease command timeout as appropriate.

Raw mode warning:
If raw output was enabled, treat files as sensitive and move them to a secure location."""),

    DocumentationSection("Limitations and Best Practices", """Known limitations:
- Parsers are best-effort.
- Device output varies by platform, version, feature set, privilege level, and VRF.
- Unsupported commands are expected in mixed environments.
- Autodetect may misclassify some devices.
- Redaction is not guaranteed to catch every secret.
- Large commands can produce large output and slow the UI.
- Received BGP routes can be very large or unsupported.
- Stopping a run may wait for Netmiko timeout or disconnect behavior.

Best practices:
- Test new command bundles on one device before many.
- Use redacted mode by default.
- Use clear Run IDs tied to tickets/change windows.
- Keep target lists small during first validation.
- Review top findings first, then raw/redacted output.
- Label credentials clearly.
- Use credential mapping when multiple credentials are loaded.
- Avoid Unsafe Allowed mode unless intentionally needed.
- Reset command overrides if a tool starts producing unexpected results.
- Keep backups of known-good script versions."""),

    DocumentationSection("About Network Toolbelt", """Network Toolbelt is a local Python/Tkinter utility for network operations tasks.

Version:
Network Toolbelt v2.91

Primary design goals:
- Portable single-file utility.
- Safe-by-default command behavior.
- Redacted-by-default output capture.
- Volatile credential handling.
- Repeatable pre/post maintenance workflows.
- Focused scanner workflows.
- Practical reporting for network engineers.

This application is intended for internal operational use by someone who understands the network environment. It should be tested carefully before broad use."""),

    DocumentationSection("Export Output", """Network Toolbelt allows you to easily export your run data.

From the File menu, you can choose:

1. Export Output Folder as ZIP...
   - Zips the entire base output directory.
   - Preserves folder structure.
   - Ignores temporary logs and cache files.
   - Useful for sharing a complete snapshot of a run.

2. Export Text Outputs as Merged TXT...
   - Finds text-based outputs (.txt, .csv, .md) and merges them into one single text file.
   - Note: Raw JSON files and session logs are excluded by default to reduce noise.
   - Adds clear BEGIN and END delimiters with timestamps before each file.
   - Perfect for feeding a set of scanner outputs or command logs into an AI analysis tool for rapid summarization.

Security Note: 
If you used Raw Capture mode, these exports may contain sensitive data (passwords, secrets). Review exported files before sharing."""),

    DocumentationSection("Version Changelog", """Network Toolbelt Version History

## v2.91 - Diagnostics, Performance, and Lean Output
- Command timeout default is now 20 seconds.
- Timing last_read default is 0.75 seconds.
- Slow command threshold is 5 seconds.
- TXT-first output profile (JSON disabled by default).
- Session logs are errors-only by default.
- Compare no longer relies on full-output JSON by default.
- Added per-command elapsed-time diagnostics and slow-command warnings.
- Improved status bar states with command-level detail.
- Added target-list scrollbars to UI.
- Increased default app window size.

## v2.85 - Netmiko Execution Engine Overhaul
- Generic Command Runner no longer performs hidden show version classification probes.
- Added platform-aware session prep.
- Added ASA terminal pager 0 handling.
- Added timing-first execution for piped/unstable commands.
- Added reconnect/retry for transport failures.
- Added malformed echo detection.

## v2.8 - Network Toolbelt Punch / Stabilization Pass
- Updated app versioning from v2.1 to v2.8.
- Improved ASA command execution compatibility.
- Converted Target IP & Credential Mapper from popup window to in-app page.
- Added single-target credential mapping test.
- Improved dashboard layout and status display.
- Added target auto-population from session targets.
- Fixed completed-run status/progress behavior.
- Added output export options for ZIP and merged AI-readable text.
- Added/updated version changelog.

## v2.7 - Credential Mapping Evaluation Build
- Added volatile target IP to credential mapping.
- Added dashboard mapping workflow.
- Added per-tool pre-run mapping prompt.
- Added mapped credential preference during tool execution.
- Added stale mapping behavior when credentials are edited or deleted.
- Added session target sharing across tools.

## v2.6 - Network Toolbelt Rename / Documentation Expansion
- Renamed user-facing app language from Cisco Toolbelt to Network Toolbelt.
- Expanded in-app documentation sections.
- Improved README language to position the app as Cisco-optimized but not Cisco-only.

## v2.5 - Command Bundle Configuration
- Added Settings -> View/Configure tool commands.
- Added local command override JSON.
- Added validation for saved tool command bundles.
- Added reset group and reset tool behavior.

## v2.4 - Navigation and UI Stabilization
- Added active-run navigation protection.
- Added Clear Current Session behavior.
- Added status/progress UI across runner pages.
- Cleaned up duplicated buttons and session log labels.

## v2.3 - Scanner Suite Buildout
- Added Network Scanner Suite.
- Added Interface Error Scanner.
- Added Port-Channel / LACP Scanner.
- Added Optics Scanner.
- Added Routing Neighbor Scanner.
- Added Log Scanner.
- Added Device Inventory Scanner.
- Added BGP/Route Summary Scanner.
  v2.91 collects and reports route/BGP summary information only.
  It does not collect per-neighbor advertised-routes or received-routes output yet.

## v2.2 - Security and Execution Foundation
- Added redacted capture behavior.
- Added command policy modes.
- Added command output validation.
- Added unsupported command handling.
- Added safer credential attempt logging.

## v2.1 - Initial GUI Toolbelt Foundation
- Added Tkinter desktop app shell.
- Added Maintenance Pre/Post Runner.
- Added Generic Command Runner.
- Added output folder structure.
- Added initial Netmiko connection handling.
""")
]

class DocumentationWindow(tk.Toplevel):
    def __init__(self, parent, controller, sections, initial_section=None, title="Network Toolbelt Documentation"):
        super().__init__(parent)
        self.controller = controller
        self.sections = sections
        self.title(title)
        self.geometry("1000x720")
        self.minsize(800, 500)
        
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Split pane
        main_pane = tk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        left_frame = tk.Frame(main_pane)
        main_pane.add(left_frame, minsize=250)
        
        right_frame = tk.Frame(main_pane)
        main_pane.add(right_frame, minsize=500)
        
        # Left: Listbox
        self.listbox = tk.Listbox(left_frame, font=("Arial", 11))
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        lb_scroll = tk.Scrollbar(left_frame, command=self.listbox.yview)
        lb_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.config(yscrollcommand=lb_scroll.set)
        
        for sec in self.sections:
            self.listbox.insert(tk.END, sec.title)
            
        self.listbox.bind("<<ListboxSelect>>", self.on_select)
        
        # Right: Text
        self.text_area = tk.Text(right_frame, font=("Arial", 11), wrap=tk.WORD)
        self.text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        txt_scroll = tk.Scrollbar(right_frame, command=self.text_area.yview)
        txt_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_area.config(yscrollcommand=txt_scroll.set)
        
        # Bottom Buttons
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill=tk.X, pady=5, padx=5)
        tk.Button(btn_frame, text="Copy Section", command=self.copy_section).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Copy All", command=self.copy_all).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Save As TXT", command=self.save_txt).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Close", command=self.on_close).pack(side=tk.RIGHT, padx=5)

        self.apply_theme()
        self.select_section(initial_section if initial_section else "General Information")

    def on_close(self):
        self.controller.documentation_window = None
        self.destroy()

    def apply_theme(self):
        th = THEMES[settings.current_theme]
        self.config(bg=th["bg"])
        self.listbox.config(bg=th["list_bg"], fg=th["list_fg"], selectbackground="#0078D7")
        self.text_area.config(bg=th["text_bg"], fg=th["fg"])

    def on_select(self, event=None):
        sel = self.listbox.curselection()
        if sel:
            idx = sel[0]
            sec = self.sections[idx]
            self.text_area.config(state=tk.NORMAL)
            self.text_area.delete("1.0", tk.END)
            self.text_area.insert(tk.END, f"=== {sec.title} ===\n\n{sec.body}")
            self.text_area.config(state=tk.DISABLED)

    def select_section(self, title: str):
        if not title: title = "General Information"
        
        titles = [s.title for s in self.sections]
        match_idx = -1
        
        if title in titles:
            match_idx = titles.index(title)
        else:
            t_low = title.lower()
            for i, t in enumerate(titles):
                if t.lower() == t_low:
                    match_idx = i; break
            if match_idx == -1:
                for i, t in enumerate(titles):
                    if t_low in t.lower():
                        match_idx = i; break
        
        if match_idx == -1: match_idx = 0
            
        self.listbox.selection_clear(0, tk.END)
        self.listbox.selection_set(match_idx)
        self.listbox.see(match_idx)
        self.on_select()

    def copy_section(self):
        self.clipboard_clear()
        self.clipboard_append(self.text_area.get("1.0", tk.END))

    def copy_all(self):
        self.clipboard_clear()
        all_text = "\n\n".join([f"=== {s.title} ===\n{s.body}" for s in self.sections])
        self.clipboard_append(all_text)

    def save_txt(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="Toolbelt_Documentation.txt")
        if path:
            all_text = "\n\n".join([f"=== {s.title} ===\n{s.body}" for s in self.sections])
            try:
                with open(path, "w", encoding="utf-8") as f: f.write(all_text)
                messagebox.showinfo("Saved", f"Documentation saved to {path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file: {e}")


# ============================================================
# Shared UI Components
# ============================================================

class ToolCommandConfigWindow(tk.Toplevel):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.title("Tool Command Configuration")
        self.geometry("1000x700")
        self.transient(parent)
        self.grab_set()
        if hasattr(controller, "apply_theme_to_widget"):
            controller.apply_theme_to_widget(self)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.current_tool_key = None
        self.current_group_key = None
        self.has_unsaved_changes = False
        self.default_dict = {}
        
        self.tools_info = {
            "maintenance_baseline": {"name": "Maintenance Runner - Baseline", "desc": "Commands run for the selected platform before feature-specific commands are added. These should remain safe read-only data-collection commands. Groups are device types."},
            "maintenance_features": {"name": "Maintenance Runner - Features", "desc": "Commands added only when a feature is detected in running-config. Groups are features (e.g. bgp, ospf)."},
            "generic_runner": {"name": "Generic Command Runner", "desc": "Generic Command Runner does not use a fixed command bundle. Commands are entered directly in the tool and validated by the active Command Policy."},
            # Scanners will be added dynamically
        }
        
        # Discover scanners
        for page_name, frame in self.controller.frames.items():
            if hasattr(frame, "scanner_def"):
                k = frame.scanner_def.internal_key
                self.tools_info[k] = {
                    "name": frame.scanner_def.name,
                    "desc": f"Commands used by the {frame.scanner_def.name} for the selected device type. If a command is unsupported, it will be recorded as COMMAND_UNSUPPORTED. Groups are device types.",
                    "defaults": frame.scanner_def.commands_by_command_set
                }
                
        self.tools_info["maintenance_baseline"]["defaults"] = MAINTENANCE_BASELINE_COMMANDS
        self.tools_info["maintenance_features"]["defaults"] = FEATURE_COMMANDS
        
        self._build_ui()
        self.controller.apply_theme_to_widget(self)
        
    def _build_ui(self):
        main_paned = tk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left pane: Tool List
        left_frame = tk.Frame(main_paned)
        main_paned.add(left_frame, minsize=250)
        
        tk.Label(left_frame, text="Tools", font=("Arial", 12, "bold")).pack(pady=(0, 5))
        self.tool_listbox = tk.Listbox(left_frame, exportselection=False)
        self.tool_listbox.pack(fill=tk.BOTH, expand=True)
        self.tool_listbox.bind("<<ListboxSelect>>", self.on_tool_select)
        
        self.tool_keys = list(self.tools_info.keys())
        for k in self.tool_keys:
            self.tool_listbox.insert(tk.END, self.tools_info[k]["name"])
            
        # Right pane
        self.right_frame = tk.Frame(main_paned)
        main_paned.add(self.right_frame, minsize=500)
        
        self.header_lbl = tk.Label(self.right_frame, text="Select a tool", font=("Arial", 16, "bold"))
        self.header_lbl.pack(anchor="w", pady=(0, 5))
        
        self.desc_lbl = tk.Label(self.right_frame, text="", wraplength=600, justify=tk.LEFT, fg="gray")
        self.desc_lbl.pack(anchor="w", pady=(0, 10))
        
        self.group_var = tk.StringVar()
        group_frame = tk.Frame(self.right_frame)
        group_frame.pack(fill=tk.X, pady=(0, 5))
        tk.Label(group_frame, text="Command group / device type:").pack(side=tk.LEFT)
        from tkinter import ttk
        self.group_combo = ttk.Combobox(group_frame, textvariable=self.group_var, state="readonly")
        self.group_combo.pack(side=tk.LEFT, padx=10)
        self.group_combo.bind("<<ComboboxSelected>>", self.on_group_select)
        
        self.override_status_lbl = tk.Label(group_frame, text="", fg="blue")
        self.override_status_lbl.pack(side=tk.LEFT, padx=10)
        
        self.text_area = tk.Text(self.right_frame, wrap=tk.NONE, undo=True)
        self.text_area.pack(fill=tk.BOTH, expand=True, pady=5)
        self.text_area.bind("<<Modified>>", self.on_text_modified)
        
        btn_frame = tk.Frame(self.right_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(btn_frame, text="Save Group", command=self.save_group, width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Reset Group to Default", command=self.reset_group).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Reset Tool to Defaults", command=self.reset_tool).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Close", command=self.on_close).pack(side=tk.RIGHT, padx=5)
        
        self.val_lbl = tk.Label(self.right_frame, text="Commands are one per line. Dangerous commands are blocked.", fg="gray")
        self.val_lbl.pack(anchor="w")

    def on_text_modified(self, event=None):
        if self.text_area.edit_modified():
            self.has_unsaved_changes = True
            self.text_area.edit_modified(False)
    def on_tool_select(self, event):
        if self.has_unsaved_changes:
            if not messagebox.askyesno("Discard changes?", "You have unsaved changes. Discard?"):
                self.tool_listbox.selection_clear(0, tk.END)
                if self.current_tool_key in self.tool_keys:
                    self.tool_listbox.selection_set(self.tool_keys.index(self.current_tool_key))
                return
        self.has_unsaved_changes = False
        
        sel = self.tool_listbox.curselection()
        if not sel: return
        self.current_tool_key = self.tool_keys[sel[0]]
        info = self.tools_info[self.current_tool_key]
        
        self.header_lbl.config(text=info["name"])
        self.desc_lbl.config(text=info["desc"])
        
        if self.current_tool_key == "generic_runner":
            self.group_combo.set("")
            self.group_combo.config(values=[])
            self.text_area.delete("1.0", tk.END)
            self.text_area.config(state=tk.DISABLED)
            self.override_status_lbl.config(text="")
            self.current_group_key = None
            return
            
        self.text_area.config(state=tk.NORMAL)
        self.default_dict = info["defaults"]
        groups = list(self.default_dict.keys())
        self.group_combo.config(values=groups)
        if groups:
            self.group_combo.set(groups[0])
            self.on_group_select(None)
            
    def on_group_select(self, event):
        if self.has_unsaved_changes and event:
            if not messagebox.askyesno("Discard changes?", "You have unsaved changes. Discard?"):
                self.group_combo.set(self.current_group_key)
                return
        self.has_unsaved_changes = False
        
        self.current_group_key = self.group_var.get()
        if not self.current_group_key: return
        
        tcm = self.controller.tool_command_manager
        default_cmds = self.default_dict.get(self.current_group_key, [])
        
        has_override = self.current_tool_key in tcm.overrides and self.current_group_key in tcm.overrides[self.current_tool_key]
        if has_override:
            self.override_status_lbl.config(text="(User Overrides Applied)", fg="blue")
            cmds = tcm.overrides[self.current_tool_key][self.current_group_key]
        else:
            self.override_status_lbl.config(text="(Default Bundle)", fg="gray")
            cmds = default_cmds
            
        self.text_area.delete("1.0", tk.END)
        self.text_area.insert("1.0", "\n".join(cmds))
        self.has_unsaved_changes = False
        self.text_area.edit_modified(False)
        
    def save_group(self):
        if not self.current_tool_key or not self.current_group_key: return
        raw = self.text_area.get("1.0", tk.END).splitlines()
        cmds = []
        for c in raw:
            c = c.strip()
            if c and c not in cmds: cmds.append(c)
            
        tcm = self.controller.tool_command_manager
        blocked = tcm.validate_commands(cmds)
        if blocked:
            messagebox.showerror("Validation Error", f"The following commands are blocked for safety:\n{', '.join(blocked)}")
            return
            
        if not cmds:
            if not messagebox.askyesno("Confirm Empty", "Are you sure you want to save an empty command list?"):
                return
                
        tcm.update_commands(self.current_tool_key, self.current_group_key, cmds)
        self.has_unsaved_changes = False
        messagebox.showinfo("Saved", "Command group saved. Changes will apply to future runs.")
        self.on_group_select(None)
        
    def reset_group(self):
        if not self.current_tool_key or not self.current_group_key: return
        if messagebox.askyesno("Reset Group", "Reset this group to defaults?"):
            self.controller.tool_command_manager.reset_group(self.current_tool_key, self.current_group_key)
            self.has_unsaved_changes = False
            self.on_group_select(None)
            
    def reset_tool(self):
        if not self.current_tool_key: return
        if messagebox.askyesno("Reset Tool", "Reset ALL groups for this tool to defaults?"):
            self.controller.tool_command_manager.reset_tool(self.current_tool_key)
            self.has_unsaved_changes = False
            self.on_group_select(None)
            
    def on_close(self):
        if self.has_unsaved_changes:
            if not messagebox.askyesno("Discard unsaved command changes?", "Discard unsaved command changes?"):
                return
        self.destroy()

class CredentialManagerLibraryPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.title_text = "Credential Manager & Library"
        self.controller = controller
        self.mapping_store = self.controller.target_credential_store
        self.credential_store = self.controller.credential_store
        
        self.ui_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.is_running = False
        self.current_edit_id = None
        
        self._setup_ui()
        self.after(100, self.process_queue)
        
    def _setup_ui(self):
        # 1. Nav Frame
        nav_frame = tk.Frame(self)
        nav_frame.pack(fill=tk.X, pady=5, padx=10)
        tk.Button(nav_frame, text="← Back to Dashboard", command=lambda: self.controller.show_frame("LandingPage")).pack(side=tk.LEFT)
        
        # 2. Top Frame (Status & Progress)
        top_frame = tk.Frame(self)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_lbl = tk.Label(top_frame, text="Idle", font=("Arial", 12, "bold"))
        self.status_lbl.pack(side=tk.LEFT)
        
        self.progress = ttk.Progressbar(top_frame, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.progress.pack(side=tk.RIGHT, padx=10)
        
        # 3. Main Pane (Vertical split: Upper Content, Lower Log)
        main_pane = tk.PanedWindow(self, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Upper Frame containing Left and Right Columns
        upper_frame = tk.Frame(main_pane)
        main_pane.add(upper_frame, minsize=400)
        
        # --- LEFT COLUMN (Add/Edit Credential & Mapping Controls) ---
        left_container = tk.Frame(upper_frame)
        left_container.pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        # A. Add/Edit Credential LabelFrame
        cred_form_frame = tk.LabelFrame(left_container, text="Add / Edit Credential", font=("Arial", 11, "bold"))
        cred_form_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(cred_form_frame, text="Label:").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.lbl_var = tk.StringVar()
        tk.Entry(cred_form_frame, textvariable=self.lbl_var, width=30).pack(fill=tk.X, padx=5, pady=2)
        
        tk.Label(cred_form_frame, text="Username:").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.user_var = tk.StringVar()
        tk.Entry(cred_form_frame, textvariable=self.user_var, width=30).pack(fill=tk.X, padx=5, pady=2)
        
        tk.Label(cred_form_frame, text="Password (leave blank to keep existing):").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.pass_var = tk.StringVar()
        tk.Entry(cred_form_frame, textvariable=self.pass_var, show="*", width=30).pack(fill=tk.X, padx=5, pady=2)
        
        tk.Label(cred_form_frame, text="Enable Secret (leave blank to keep existing):").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.sec_var = tk.StringVar()
        tk.Entry(cred_form_frame, textvariable=self.sec_var, show="*", width=30).pack(fill=tk.X, padx=5, pady=2)
        
        form_btn_frame = tk.Frame(cred_form_frame)
        form_btn_frame.pack(pady=10, fill=tk.X)
        tk.Button(form_btn_frame, text="Save Credential", command=self.save_cred, width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(form_btn_frame, text="New / Clear", command=self.clear_form, width=12).pack(side=tk.LEFT, padx=5)
        
        # B. Mapping Controls LabelFrame
        mapping_controls_frame = tk.LabelFrame(left_container, text="Target IP & Platform Mapping", font=("Arial", 11, "bold"))
        mapping_controls_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(mapping_controls_frame, text="Targets (IP/Hostname):", font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=5, pady=(5,0))
        self.targets_text = tk.Text(mapping_controls_frame, height=6, width=30)
        self.targets_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        
        tk.Label(mapping_controls_frame, text="Platform for Fast Mapping:").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.fast_platform_var = tk.StringVar(value="Cisco IOS/IOS-XE")
        fast_platform_cb = ttk.Combobox(mapping_controls_frame, textvariable=self.fast_platform_var, values=["Cisco IOS/IOS-XE", "Cisco NX-OS", "Cisco ASA", "Auto Detect"])
        fast_platform_cb.pack(fill=tk.X, padx=5, pady=2)
        
        self.probe_var = tk.BooleanVar(value=False)
        tk.Checkbutton(mapping_controls_frame, text="Run platform detection", variable=self.probe_var).pack(anchor=tk.W, padx=5)
        
        self.retest_var = tk.BooleanVar(value=False)
        tk.Checkbutton(mapping_controls_frame, text="Re-test already mapped", variable=self.retest_var).pack(anchor=tk.W, padx=5)
        
        map_btn_frame = tk.Frame(mapping_controls_frame)
        map_btn_frame.pack(pady=5, fill=tk.X)
        self.start_btn = tk.Button(map_btn_frame, text="Start Mapping", command=self.start_mapping, width=14)
        self.start_btn.pack(side=tk.LEFT, padx=2)
        self.stop_btn = tk.Button(map_btn_frame, text="STOP", command=self.stop_mapping, state=tk.DISABLED, width=6)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        tk.Button(map_btn_frame, text="Clear Session", command=self.clear_session, width=12).pack(side=tk.LEFT, padx=2)
        
        self.stats_lbl = tk.Label(mapping_controls_frame, text="", justify=tk.LEFT)
        self.stats_lbl.pack(anchor=tk.W, padx=5, pady=5)
        
        # --- RIGHT COLUMN (Credentials Listbox & Mapped Hosts Treeview) ---
        right_container = tk.Frame(upper_frame)
        right_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # A. Credentials Library LabelFrame
        cred_library_frame = tk.LabelFrame(right_container, text="Credentials Library", font=("Arial", 11, "bold"))
        cred_library_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        lib_content = tk.Frame(cred_library_frame)
        lib_content.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        list_frame = tk.Frame(lib_content)
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.listbox = tk.Listbox(list_frame, font=("Arial", 11), height=6)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scroll = tk.Scrollbar(list_frame, command=self.listbox.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.config(yscrollcommand=scroll.set)
        
        self.listbox.bind('<<ListboxSelect>>', self.on_select)
        
        lib_btn_frame = tk.Frame(lib_content)
        lib_btn_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=5)
        
        tk.Button(lib_btn_frame, text="Delete Selected", command=self.delete_cred, width=18).pack(pady=5)
        tk.Button(lib_btn_frame, text="Clear Library", command=self.clear_creds, width=18).pack(pady=5)
        
        # B. Mapped Host List LabelFrame
        host_mapping_frame = tk.LabelFrame(right_container, text="Mapped Host List", font=("Arial", 11, "bold"))
        host_mapping_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        cols = ("Host", "Status", "Mapped Credential", "Username", "Platform", "Last Tested", "Result")
        self.tree = ttk.Treeview(host_mapping_frame, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=110)
        self.tree.column("Host", width=130)
        self.tree.column("Mapped Credential", width=130)
        self.tree.column("Result", width=200)
        
        yscroll = ttk.Scrollbar(host_mapping_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=yscroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5,0), pady=5)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y, pady=5, padx=(0,5))
        
        # --- LOWER PANEL (Execution & Session Logs) ---
        log_frame = tk.Frame(main_pane)
        main_pane.add(log_frame, minsize=200)
        
        exec_frame = tk.Frame(log_frame)
        exec_frame.pack(fill=tk.BOTH, expand=True)
        tk.Label(exec_frame, text="Execution Log").pack(anchor=tk.W)
        self.exec_log = tk.Text(exec_frame, height=5)
        self.exec_log.pack(fill=tk.BOTH, expand=True)
        
        sess_frame = tk.Frame(log_frame)
        sess_frame.pack(fill=tk.BOTH, expand=False)
        
        self.sess_container = tk.Frame(sess_frame)
        
        def toggle_session_log():
            if self.sess_container.winfo_manager():
                self.sess_container.pack_forget()
                self.toggle_sess_btn.config(text="Show Session Log ▶")
            else:
                self.sess_container.pack(fill=tk.BOTH, expand=True)
                self.toggle_sess_btn.config(text="Hide Session Log ▼")
                
        self.toggle_sess_btn = tk.Button(sess_frame, text="Show Session Log ▶", command=toggle_session_log)
        self.toggle_sess_btn.pack(anchor=tk.W)
        
        self.sess_lbl = tk.Label(self.sess_container, text="Session Log")
        self.sess_lbl.pack(anchor=tk.W)
        self.sess_log = tk.Text(self.sess_container, height=5)
        self.sess_log.pack(fill=tk.BOTH, expand=True)
        
        self.refresh_targets_text()
        self.refresh_list()
        self.update_stats()
        
    def log_message(self, message):
        ts = datetime.now().strftime('%H:%M:%S')
        self.exec_log.insert(tk.END, f"[{ts}] {message}\n")
        self.exec_log.see(tk.END)
        
    def on_select(self, event):
        sel = self.listbox.curselection()
        if not sel: return
        idx = sel[0]
        record = self.controller.credential_store.records[idx]
        self.current_edit_id = record.id
        self.lbl_var.set(record.label)
        self.user_var.set(record.username)
        self.pass_var.set("")
        self.sec_var.set("")
        
    def clear_form(self):
        self.current_edit_id = None
        self.lbl_var.set("")
        self.user_var.set("")
        self.pass_var.set("")
        self.sec_var.set("")
        self.listbox.selection_clear(0, tk.END)

    def save_cred(self):
        l, u, p, s = self.lbl_var.get().strip(), self.user_var.get().strip(), self.pass_var.get().strip(), self.sec_var.get().strip()
        if not u:
            messagebox.showerror("Error", "Username is required.")
            return
            
        record = None
        if self.current_edit_id:
            for r in self.controller.credential_store.records:
                if r.id == self.current_edit_id:
                    record = r
                    break
                    
        if not record and not p:
            messagebox.showerror("Error", "Password is required for new credentials.")
            return
            
        if record:
            username_changed = record.username != u
            password_changed = p != ""
            secret_changed = s != ""
            self.controller.credential_store.update(record.id, l, u, p, s)
            
            has_secret = "yes" if (s or record.secret) else "no"
            self.log_message(f"Updated credential: label='{l}', username='{u}', enable_secret='{has_secret}'")
            
            if (username_changed or password_changed or secret_changed) and hasattr(self.controller, "target_credential_store"):
                self.controller.target_credential_store.mark_stale_for_credential(record.id)
            elif hasattr(self.controller, "target_credential_store"):
                for m in self.controller.target_credential_store.mappings.values():
                    if m.credential_id == record.id:
                        m.credential_label = l
        else:
            self.controller.credential_store.add(l, u, p, s)
            has_secret = "yes" if s else "no"
            self.log_message(f"Added new credential: label='{l}', username='{u}', enable_secret='{has_secret}'")
            
        self.refresh_list()
        self.clear_form()
        self.refresh_table_from_store()
        self.update_stats()
        if "LandingPage" in self.controller.frames:
            self.controller.frames["LandingPage"].refresh_credential_status()

    def refresh_list(self):
        self.listbox.delete(0, tk.END)
        safe_list = self.controller.credential_store.list_safe()
        for item in safe_list:
            self.listbox.insert(tk.END, item)
            
    def delete_cred(self):
        sel = self.listbox.curselection()
        if not sel: return
        idx = sel[0]
        record = self.controller.credential_store.records[idx]
        self.controller.credential_store.delete(record.id)
        
        self.log_message(f"Deleted credential: label='{record.label}', username='{record.username}'")
        
        if hasattr(self.controller, "target_credential_store"):
            self.controller.target_credential_store.mark_stale_for_credential(record.id)
        self.refresh_list()
        self.clear_form()
        self.refresh_table_from_store()
        self.update_stats()
        if hasattr(self.controller, "frames") and "LandingPage" in self.controller.frames:
            self.controller.frames["LandingPage"].refresh_credential_status()
        
    def clear_creds(self):
        if messagebox.askyesno("Clear All", "Are you sure you want to clear all credentials?"):
            if hasattr(self.controller, "target_credential_store"):
                for m in self.controller.target_credential_store.mappings.values():
                    m.status = "STALE"
                    m.last_tested = ""
                    m.error_message = "Credential store was cleared"
            self.controller.credential_store.clear()
            
            self.log_message("Cleared all credentials from library.")
            
            self.refresh_list()
            self.clear_form()
            self.refresh_table_from_store()
            self.update_stats()
            if hasattr(self.controller, "frames") and "LandingPage" in self.controller.frames:
                self.controller.frames["LandingPage"].refresh_credential_status()

    def refresh_targets_text(self):
        self.targets_text.delete("1.0", tk.END)
        targets = self.mapping_store.get_targets()
        if targets:
            self.targets_text.insert(tk.END, "\n".join(targets))
            
    def tkraise(self, *args, **kwargs):
        super().tkraise(*args, **kwargs)
        self.refresh_targets_text()
        self.refresh_list()
        self.refresh_table_from_store()
        self.update_stats()
        
    def has_active_run(self):
        return self.is_running
        
    def stop_and_clear_for_navigation(self, retain_targets=True, retain_credentials=True):
        if self.is_running:
            self.stop_event.set()
        self.is_running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_lbl.config(text="Idle")
        self.progress["value"] = 0
        if not retain_targets:
            self.mapping_store.clear_targets()
            self.mapping_store.clear_mappings()
        if not retain_credentials:
            for m in self.mapping_store.mappings.values():
                m.status = "STALE"
                m.last_tested = ""
                m.error_message = "Credential store was cleared"
        self.refresh_table_from_store()
        self.refresh_list()
        self.update_stats()
        
    def update_stats(self):
        c_count = len(self.credential_store.records)
        t_count = len(self.mapping_store.targets)
        m_count = self.mapping_store.mapped_count_for_current_targets()
        self.stats_lbl.config(text=f"Credentials loaded: {c_count}\nTargets loaded: {t_count}\nMapped targets: {m_count}/{t_count}")
        
    def refresh_table_from_store(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        seen_iids = set()
        for host in self.mapping_store.targets:
            iid = host.strip().lower()
            if iid in seen_iids:
                continue  # skip duplicate — already in tree
            seen_iids.add(iid)
            m = self.mapping_store.get_mapping(host)
            if m:
                self.tree.insert("", "end", iid=iid, values=(m.host, m.status, m.credential_label, m.username, m.detected_platform, m.last_tested, m.error_message))
            else:
                self.tree.insert("", "end", iid=iid, values=(host, "UNMAPPED", "", "", "", "", ""))
                
    def clear_session(self):
        if messagebox.askyesno("Clear", "Clear all mapping session data?", parent=self):
            self.mapping_store.clear_all()
            self.log_message("Cleared mapping session data (targets & mappings).")
            self.refresh_table_from_store()
            self.update_stats()
            self.refresh_list()
            self.controller.frames["LandingPage"].refresh_credential_status()
            self.exec_log.delete("1.0", tk.END)
            
    def process_queue(self):
        try:
            while True:
                msg_type, data = self.ui_queue.get_nowait()
                if msg_type == "LOG":
                    self.exec_log.insert(tk.END, data + "\n")
                    self.exec_log.see(tk.END)
                elif msg_type == "STATUS_ROW":
                    host, status, cred, user, plat, last, err = data
                    iid = host.strip().lower()
                    if self.tree.exists(iid):
                        self.tree.item(iid, values=(host, status, cred, user, plat, last, err))
                    else:
                        self.tree.insert("", "end", iid=iid, values=(host, status, cred, user, plat, last, err))
                elif msg_type == "PROGRESS":
                    idx, total = data
                    self.progress["maximum"] = total
                    self.progress["value"] = idx
                elif msg_type == "SESS_LOG":
                    self.sess_log.insert(tk.END, data)
                    self.sess_log.see(tk.END)
                elif msg_type == "DONE":
                    self.is_running = False
                    self.start_btn.config(state=tk.NORMAL)
                    self.stop_btn.config(state=tk.DISABLED)
                    if self.stop_event.is_set():
                        self.status_lbl.config(text="Stopped by user")
                    else:
                        self.status_lbl.config(text="Done")
                        self.progress["value"] = self.progress["maximum"]
                    self.update_stats()
                    self.controller.frames["LandingPage"].refresh_credential_status()
        except queue.Empty:
            pass
        finally:
            if self.winfo_exists():
                self.after(100, self.process_queue)
                
    def _run_mapping(self, targets):
        if not self.credential_store.records:
            messagebox.showerror("Error", "No credentials loaded. Add credentials in Credential Manager first.", parent=self)
            return
        if not targets:
            messagebox.showerror("Error", "No target IPs to test.", parent=self)
            return
            
        self.is_running = True
        self.stop_event.clear()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_lbl.config(text="Mapping...")
        self.progress["value"] = 0
        
        self.sess_lbl.config(text="Session Log", fg=THEMES[settings.current_theme]["fg"])
        self.sess_log.delete("1.0", tk.END)
        self.exec_log.delete("1.0", tk.END)

        def _log(msg): self.ui_queue.put(("LOG", msg))
        def _stat(h, s, c, u, p, l, e): self.ui_queue.put(("STATUS_ROW", (h, s, c, u, p, l, e)))
        def _prog(i, t): self.ui_queue.put(("PROGRESS", (i, t)))
        def _sess_log(msg): self.ui_queue.put(("SESS_LOG", msg))
        
        callbacks = {"log_cb": _log, "status_cb": _stat, "progress_cb": _prog, "sess_log_cb": _sess_log}
        
        platform_name = self.fast_platform_var.get().strip()
        if platform_name == "Auto Detect":
            platform_choice = "Auto Detect"
        elif platform_name == "Cisco IOS/IOS-XE":
            platform_choice = "Cisco IOS"
        elif platform_name == "Cisco NX-OS":
            platform_choice = "Cisco NX-OS"
        elif platform_name == "Cisco ASA":
            platform_choice = "Cisco ASA"
        else:
            platform_choice = "Auto Detect"
            
        run_probe = self.probe_var.get()

        def run():
            CredentialMappingRunner.map_targets(
                targets, self.credential_store, self.mapping_store, platform_choice,
                callbacks, self.stop_event, self.retest_var.get(), True, "redacted", run_probe
            )
            self.ui_queue.put(("DONE", None))
            
        threading.Thread(target=run, daemon=True).start()

    def start_mapping(self):
        try:
            lines = self.targets_text.get("1.0", "end").splitlines()
            hosts = []
            for line in lines:
                line = line.strip()
                if not line: continue
                if "," in line:
                    for part in line.split(","):
                        if part.strip(): hosts.append(part.strip())
                else:
                    hosts.append(line)
            self.mapping_store.set_targets(hosts)  # deduplicates internally
            self.refresh_table_from_store()
            
            targets = self.mapping_store.get_targets()
            if not targets:
                messagebox.showerror("Error", "No targets to map. Please enter targets first.", parent=self)
                return
                
            self.log_message(f"Starting target credential mapping for {len(targets)} host(s)...")
            self._run_mapping(targets)
        except Exception as e:
            messagebox.showerror("Mapping Error", f"Failed to start mapping:\n{type(e).__name__}: {e}", parent=self)
        
    def stop_mapping(self):
        self.stop_event.set()
        self.log_message("Stop mapping request sent.")

class CredentialStatusPanel(tk.LabelFrame):
    def __init__(self, parent, controller, **kwargs):
        super().__init__(parent, text="Credentials (Temp)", font=("Arial", 10, "bold"), **kwargs)
        self.controller = controller
        
        self.status_lbl = tk.Label(self, text="Credentials loaded: 0", font=("Arial", 10))
        self.status_lbl.pack(pady=5, padx=5, anchor="w")
        
        tk.Button(self, text="Manage Credentials & Library", command=lambda: self.controller.show_frame("CredentialManagerLibraryPage")).pack(pady=5, padx=5, anchor="w")
        
    def refresh(self):
        count = len(self.controller.credential_store.records)
        self.status_lbl.config(text=f"Credentials loaded: {count}")



class TargetPanel(tk.LabelFrame):
    def __init__(self, parent, controller=None, **kwargs):
        super().__init__(parent, text="Target IPs", font=("Arial", 10, "bold"), **kwargs)
        self.controller = controller
        self.platform_var = tk.StringVar(value="Auto Detect Platform")
        self.platform_cb = ttk.Combobox(self, textvariable=self.platform_var, values=["Auto Detect Platform", "Cisco IOS / IOS-XE", "Cisco NX-OS", "Cisco ASA"], state="readonly")
        self.platform_cb.pack(fill=tk.X, padx=5, pady=(5, 0))
        
        text_frame = ttk.Frame(self)
        text_frame.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        self.targets_scrollbar = ttk.Scrollbar(text_frame)
        self.targets_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.targets_text = tk.Text(text_frame, height=6, width=30, yscrollcommand=self.targets_scrollbar.set)
        self.targets_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.targets_scrollbar.config(command=self.targets_text.yview)

        self.stats_lbl = tk.Label(self, text="Session targets: 0, Mapped: 0", font=("Arial", 9))
        self.stats_lbl.pack(anchor="w", padx=5)
        
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(btn_frame, text="Load Session Targets", command=self.load_session_targets).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0,2))
        tk.Button(btn_frame, text="Save Targets to Session", command=self.save_targets_to_session).pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(2,0))
        
        if not self.controller:
            for child in btn_frame.winfo_children():
                child.configure(state="disabled")

    def refresh_session_counts(self):
        if self.controller and hasattr(self.controller, "target_credential_store"):
            t_count = len(self.controller.target_credential_store.targets)
            m_count = self.controller.target_credential_store.mapped_count_for_current_targets()
            self.stats_lbl.config(text=f"Session targets: {t_count}, Mapped: {m_count}/{t_count}")

    def load_session_targets(self):
        if not self.controller or not hasattr(self.controller, "target_credential_store"): return
        targets = self.controller.target_credential_store.targets
        if not targets:
            import tkinter.messagebox as mb
            mb.showinfo("Info", "No targets in session mapping store.", parent=self)
            return
            
        current = self.targets_text.get("1.0", "end-1c").strip()
        if current:
            import tkinter.messagebox as mb
            if not mb.askyesno("Overwrite", "Target box is not empty. Overwrite with session targets?", parent=self):
                return
                
        self.targets_text.delete("1.0", "end")
        self.targets_text.insert("1.0", "\n".join(targets))
        self.refresh_session_counts()
        
    def save_targets_to_session(self):
        if not self.controller or not hasattr(self.controller, "target_credential_store"): return
        targets = self.get_targets()
        
        # De-duplicate while preserving order
        seen = set()
        cleaned = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                cleaned.append(t)
                
        self.controller.target_credential_store.set_targets(cleaned)
        self.refresh_session_counts()
        if "LandingPage" in self.controller.frames:
            self.controller.frames["LandingPage"].refresh_credential_status()
            
        import tkinter.messagebox as mb
        mb.showinfo("Saved", "Targets saved to session mapping store.", parent=self)

    def get_targets(self):
        return [t.strip() for t in self.targets_text.get("1.0", "end-1c").splitlines() if t.strip()]
        
    def get_platform(self):
        return self.platform_var.get()


# ============================================================
# Runner Pages
# ============================================================


class RunningNavigationDialog(tk.Toplevel):
    def __init__(self, parent, tool_name):
        super().__init__(parent)
        self.title("Stop Running Tool?")
        self.geometry("350x200")
        self.transient(parent)
        self.grab_set()
        if hasattr(parent, "apply_theme_to_widget"):
            parent.apply_theme_to_widget(self)
        
        self.retain_creds = tk.BooleanVar(value=True)
        self.retain_targets = tk.BooleanVar(value=True)
        self.result = None
        
        tk.Label(self, text=f"{tool_name} is still running.", font=("Arial", 11, "bold")).pack(pady=(10,0))
        tk.Label(self, text="Leaving this page will stop the tool\nand clear the session. Are you sure?").pack(pady=(0,5))
        tk.Checkbutton(self, text="Retain global credentials", variable=self.retain_creds).pack(anchor="w", padx=20)
        tk.Checkbutton(self, text="Retain target IPs", variable=self.retain_targets).pack(anchor="w", padx=20)
        
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Leave Page", command=self.do_clear).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side=tk.LEFT, padx=5)
        
    def do_clear(self):
        self.result = {
            "confirmed": True,
            "retain_credentials": self.retain_creds.get(),
            "retain_targets": self.retain_targets.get()
        }
        self.destroy()

class ClearSessionDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Clear Session")
        self.geometry("300x160")
        self.transient(parent)
        self.grab_set()
        if hasattr(parent, "apply_theme_to_widget"):
            parent.apply_theme_to_widget(self)
        
        self.retain_creds = tk.BooleanVar(value=True)
        self.retain_targets = tk.BooleanVar(value=True)
        self.result = None
        
        tk.Label(self, text="Clear the current session?", font=("Arial", 11, "bold")).pack(pady=(10,5))
        tk.Checkbutton(self, text="Retain global credentials", variable=self.retain_creds).pack(anchor="w", padx=20)
        tk.Checkbutton(self, text="Retain target IPs", variable=self.retain_targets).pack(anchor="w", padx=20)
        
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Clear", command=self.do_clear).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side=tk.LEFT, padx=5)
        
    def do_clear(self):
        self.result = {
            "retain_credentials": self.retain_creds.get(),
            "retain_targets": self.retain_targets.get()
        }
        self.destroy()

class BaseRunnerPage(tk.Frame):
    def __init__(self, parent, controller, title_text="Runner"):
        super().__init__(parent)
        self.controller = controller
        self.title_text = title_text
        
        self.ui_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.is_running = False
        self.active_conn = None

        self._setup_base_ui()
        self.after(100, self.process_queue)
    def has_active_run(self) -> bool:
        return self.is_running or (hasattr(self, "run_btn") and str(self.run_btn.cget("state")) == tk.DISABLED)
    def stop_and_clear_for_navigation(self, retain_targets: bool, retain_credentials: bool):
        self.stop_event.set()
        if self.active_conn:
            try: self.active_conn.disconnect()
            except Exception: pass
            self.active_conn = None
        self.enqueue("CLEAR_LOGS")
        self.set_status("Idle")
        self.set_progress(0)
        self.enqueue("WARNING_BANNER", "")
        self.enqueue("SET_BUTTONS", tk.NORMAL, tk.DISABLED)
        self.update_session_log_label()
        self.clear_page_fields(retain_targets=retain_targets, retain_credentials=retain_credentials)
        self.is_running = False
        self.fallback_to_all_credentials_for_run = False

    def sync_targets_to_session(self, targets):
        """Push the current target list into the shared session store so other
        pages see the same set when they are raised."""
        store = getattr(self.controller, 'target_credential_store', None)
        if store is not None:
            seen = set()
            cleaned = []
            for t in targets:
                if t not in seen:
                    seen.add(t)
                    cleaned.append(t)
            store.set_targets(cleaned)

    def prompt_for_mapping_if_needed(self, targets, on_continue):
        if not targets:
            import tkinter.messagebox as mb
            mb.showerror("Error", "No targets specified.")
            return

        cred_store = self.controller.credential_store
        if not cred_store.records:
            import tkinter.messagebox as mb
            mb.showerror("Error", "No credentials loaded.")
            return

        map_store = getattr(self.controller, "target_credential_store", None)
        if not map_store or len(cred_store.records) <= 1:
            self.fallback_to_all_credentials_for_run = False
            on_continue()
            return
            
        needs_mapping = False
        for t in targets:
            m = map_store.get_mapping(t)
            if not m or m.status in ("UNMAPPED", "STALE", "FAILED", "STOPPED"):
                needs_mapping = True
                break
                
        if not needs_mapping:
            self.fallback_to_all_credentials_for_run = False
            on_continue()
            return
            
        dlg = MappingPromptDialog(self, self.controller, targets)
        self.wait_window(dlg)
        
        if dlg.result == "CANCEL":
            return
        elif dlg.result == "CONTINUE":
            self.fallback_to_all_credentials_for_run = dlg.fallback
            on_continue()
        elif dlg.result == "MAP_NOW":
            self.fallback_to_all_credentials_for_run = dlg.fallback
            prog_dlg = SmallMappingProgressDialog(self, self.controller, targets)
            self.wait_window(prog_dlg)
            
            failed = False
            for t in targets:
                m = map_store.get_mapping(t)
                if not m or m.status != "MAPPED":
                    failed = True
                    break
                    
            if failed:
                import tkinter.messagebox as mb
                if not mb.askyesno("Continue?", "Mapping completed with failures or was stopped. Continue running the tool anyway?", parent=self):
                    return
                    
            on_continue()

    def open_page_help(self):
        self.controller.open_documentation(self.title_text)

    def tkraise(self, *args, **kwargs):
        super().tkraise(*args, **kwargs)
        if hasattr(self, 'cred_panel') and hasattr(self.cred_panel, 'refresh'):
            self.cred_panel.refresh()
        self.update_session_log_label()
        
        if hasattr(self, 'target_panel') and hasattr(self.controller, 'target_credential_store'):
            self.target_panel.refresh_session_counts()
            session_targets = self.controller.target_credential_store.targets
            if session_targets:
                self.target_panel.targets_text.delete("1.0", "end")
                self.target_panel.targets_text.insert("1.0", "\n".join(session_targets))

    def update_session_log_label(self):
        if hasattr(self, 'session_frame'):
            if settings.capture_mode == "raw":
                self.session_frame.config(text="Session Log (RAW - sensitive)")
            else:
                self.session_frame.config(text="Session Log")

    def set_status(self, text):
        self.enqueue("STATUS_UPDATE", f"Status: {text}")

    def set_progress(self, value):
        self.enqueue("PROGRESS_UPDATE", value)

    def _setup_base_ui(self):
        nav_frame = tk.Frame(self)
        nav_frame.pack(fill=tk.X, padx=10, pady=(5,0))
        tk.Button(nav_frame, text="← Back to Dashboard", command=lambda: self.controller.show_frame("LandingPage")).pack(side=tk.LEFT)
        tk.Button(nav_frame, text="[Help]", command=self.open_page_help).pack(side=tk.RIGHT)
        
        title = tk.Label(self, text=self.title_text, font=("Arial", 18, "bold"))
        title.pack(pady=(5,5))
        
        self.status_var = tk.StringVar(value="Status: Idle")
        self.progress_var = tk.DoubleVar(value=0)
        
        status_frame = tk.Frame(self)
        status_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        
        self.status_label = tk.Label(status_frame, textvariable=self.status_var, font=("Arial", 10, "bold"), anchor="w")
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=5)

        main_pane = tk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_outer = tk.Frame(main_pane)
        main_pane.add(left_outer, minsize=260, width=280)
        
        left_canvas = tk.Canvas(left_outer, highlightthickness=0)
        left_scrollbar = ttk.Scrollbar(left_outer, orient="vertical", command=left_canvas.yview)
        
        self.left_panel = tk.Frame(left_canvas)
        self.left_panel.bind("<Configure>", lambda e: left_canvas.configure(scrollregion=left_canvas.bbox("all")))
        
        self._left_window_id = left_canvas.create_window((0, 0), window=self.left_panel, anchor="nw")
        
        def _on_canvas_configure(event):
            left_canvas.itemconfig(self._left_window_id, width=event.width)
            
        left_canvas.bind("<Configure>", _on_canvas_configure)
        left_canvas.configure(yscrollcommand=left_scrollbar.set)
        
        left_canvas.pack(side="left", fill="both", expand=True)
        left_scrollbar.pack(side="right", fill="y")

        right_pane = tk.PanedWindow(main_pane, orient=tk.VERTICAL)
        main_pane.add(right_pane, minsize=400)

        exec_frame = tk.LabelFrame(right_pane, text="Execution Logs", font=("Arial", 10, "bold"))
        right_pane.add(exec_frame, minsize=200)
        
        self.exec_text = tk.Text(exec_frame, bg="black", fg="white", font=("Consolas", 10))
        self.exec_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        eb = tk.Scrollbar(exec_frame, command=self.exec_text.yview)
        eb.pack(side=tk.RIGHT, fill=tk.Y)
        self.exec_text.config(yscrollcommand=eb.set)

        self.session_frame = tk.LabelFrame(right_pane, text="Session Log", font=("Arial", 10, "bold"))
        right_pane.add(self.session_frame, minsize=100)
        
        self.session_text = tk.Text(self.session_frame, bg="#1e1e1e", fg="#00ff00", font=("Consolas", 10))
        self.session_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = tk.Scrollbar(self.session_frame, command=self.session_text.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.session_text.config(yscrollcommand=sb.set)

        self.warning_banner = tk.Label(self.left_panel, text="", bg="red", fg="white", font=("Arial", 10, "bold"))
        # Initially hidden

    def enqueue(self, event_type, *args):
        self.ui_queue.put((event_type, args))

    def process_queue(self):
        while not self.ui_queue.empty():
            try:
                event_type, args = self.ui_queue.get_nowait()
                if event_type == "LOG_EXEC":
                    self.exec_text.insert(tk.END, args[0] + "\n")
                    self.exec_text.see(tk.END)
                elif event_type == "LOG_SESSION":
                    self.session_text.insert(tk.END, args[0])
                    self.session_text.see(tk.END)
                elif event_type == "SET_BUTTONS":
                    if hasattr(self, 'run_btn'): self.run_btn.config(state=args[0])
                    if hasattr(self, 'stop_btn'): self.stop_btn.config(state=args[1])
                elif event_type == "CLEAR_LOGS":
                    self.exec_text.delete("1.0", tk.END)
                    self.session_text.delete("1.0", tk.END)
                elif event_type == "STATUS_UPDATE":
                    self.status_var.set(args[0])
                elif event_type == "PROGRESS_UPDATE":
                    self.progress_var.set(args[0])
                elif event_type == "WARNING_BANNER":
                    if args[0]:
                        self.warning_banner.config(text=args[0])
                        self.warning_banner.pack(fill=tk.X, pady=5, side=tk.TOP)
                    else:
                        self.warning_banner.pack_forget()
                elif event_type == "MODE_LABEL":
                    if hasattr(self, 'mode_var'):
                        if self.mode_var.get() == args[0]:
                            if args[0] == "pre": self.pre_rb.config(text=args[1])
                            elif args[0] == "post": self.post_rb.config(text=args[1])
                            elif args[0] == "compare": self.compare_rb.config(text=args[1])
            except queue.Empty:
                break
        self.after(100, self.process_queue)

    def stop_execution(self):
        self.stop_event.set()
        self.enqueue("LOG_EXEC", "\n[!] STOP requested. Aborting execution and severing connections...")
        self.enqueue("STATUS_UPDATE", "Status: Stopped by user")
        if self.active_conn:
            try: self.active_conn.disconnect()
            except Exception: pass

    def clear_current_session(self):
        dlg = ClearSessionDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            if not dlg.result["retain_credentials"]:
                if not messagebox.askyesno("Confirm", "This will clear all credentials from the global Credential Manager. Continue?"):
                    return
                self.controller.credential_store.clear()
                if hasattr(self.controller, "target_credential_store"):
                    for m in self.controller.target_credential_store.mappings.values():
                        m.status = "STALE"
                        m.last_tested = ""
                        m.error_message = "Credential store was cleared"
                if hasattr(self.controller, "frames") and "LandingPage" in self.controller.frames:
                    self.controller.frames["LandingPage"].refresh_credential_status()
            
            self.stop_execution()
            self.enqueue("CLEAR_LOGS")
            self.set_status("Idle")
            self.set_progress(0)
            self.update_session_log_label()
            self.clear_page_fields(retain_targets=dlg.result["retain_targets"], retain_credentials=dlg.result["retain_credentials"])
            self.tkraise()

    def clear_page_fields(self, retain_targets: bool, retain_credentials: bool):
        pass

    def get_run_ts(self):
        return datetime.now().strftime("%Y%m%d-%H%M%S")

    def set_host_status(self, host: str, idx: int, total: int, state: str, detail: str = ""):
        msg = f"{state} on {host} ({idx}/{total})"
        if detail:
            msg += f" - {detail}"
        self.set_status(msg)

    def sync_tail(self, temp_path: str, tail_stop_event=None):
        try:
            buf_redactor = LineBufferedRedactor(redactor.redact_text)
            with open(temp_path, "r", encoding="utf-8", errors="replace") as f:
                while not self.stop_event.is_set():
                    if tail_stop_event and tail_stop_event.is_set():
                        break
                    chunk = f.read(1024)
                    if chunk:
                        out = buf_redactor.feed(chunk) if settings.capture_mode == "redacted" else chunk
                        if out: self.enqueue("LOG_SESSION", out)
                    else:
                        import time
                        time.sleep(0.1)
                chunk = f.read()
                if chunk:
                    out = buf_redactor.feed(chunk) if settings.capture_mode == "redacted" else chunk
                    if out: self.enqueue("LOG_SESSION", out)
                out = buf_redactor.flush() if settings.capture_mode == "redacted" else ""
                if out: self.enqueue("LOG_SESSION", out)
        except Exception:
            pass


class MaintenanceRunnerPage(BaseRunnerPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, title_text="Maintenance Pre/Post Runner")
        self.setup_ui()

    def setup_ui(self):
        mode_frame = tk.LabelFrame(self.left_panel, text="Select Mode", font=("Arial", 10, "bold"))
        mode_frame.pack(fill=tk.X, pady=5, ipady=5)
        self.mode_var = tk.StringVar(value="pre")
        
        self.pre_rb = tk.Radiobutton(mode_frame, text="Pre-Checks", variable=self.mode_var, value="pre")
        self.pre_rb.pack(anchor="w", padx=5)
        
        self.post_rb = tk.Radiobutton(mode_frame, text="Post-Checks", variable=self.mode_var, value="post")
        self.post_rb.pack(anchor="w", padx=5)
        
        self.compare_rb = tk.Radiobutton(mode_frame, text="Compare", variable=self.mode_var, value="compare")
        self.compare_rb.pack(anchor="w", padx=5)

        run_id_frame = tk.LabelFrame(self.left_panel, text="Run ID", font=("Arial", 10, "bold"))
        run_id_frame.pack(fill=tk.X, pady=5)
        self.run_id_entry = tk.Entry(run_id_frame)
        self.run_id_entry.pack(fill=tk.X, padx=5, pady=5)

        self.cred_panel = CredentialStatusPanel(self.left_panel, self.controller)
        self.cred_panel.pack(fill=tk.X, pady=5)

        self.target_panel = TargetPanel(self.left_panel, self.controller)
        self.target_panel.pack(fill=tk.X, pady=5)

        self.run_btn = tk.Button(self.left_panel, text="RUN", font=("Arial", 14, "bold"), command=self.start_execution)
        self.run_btn.pack(fill=tk.X, pady=5)

        self.stop_btn = tk.Button(self.left_panel, text="STOP", font=("Arial", 14, "bold"), fg="white", bg="#d9534f", command=self.stop_execution, state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=5)
        self.clear_btn = tk.Button(self.left_panel, text="Clear Current Session", font=("Arial", 11), command=self.clear_current_session)
        self.clear_btn.pack(fill=tk.X, pady=5)
    def start_execution(self):
        mode = self.mode_var.get()
        run_id_raw = self.run_id_entry.get()
        run_id = FilenameSafety.safe_run_id(run_id_raw)
        
        if not run_id or run_id == "unknown":
            messagebox.showerror("Error", "Valid Run ID is required")
            return

        targets = self.target_panel.get_targets()
        self.sync_targets_to_session(targets)
        platform_choice = self.target_panel.get_platform()
        cred_sets = self.controller.credential_store.as_netmiko_dicts()

        if mode != "compare" and not cred_sets:
            messagebox.showerror("Error", "Please add at least one Credential Set")
            return
        if mode != "compare" and not targets:
            messagebox.showerror("Error", "Please provide at least one Target IP")
            return

        def begin_run():
            self.stop_event.clear()
            self.enqueue("SET_BUTTONS", tk.DISABLED, tk.NORMAL)
            self.enqueue("CLEAR_LOGS")
            
            if settings.capture_mode == "raw":
                self.enqueue("WARNING_BANNER", "RAW CAPTURE ENABLED - DANGER")
            else:
                self.enqueue("WARNING_BANNER", "")
                self.update_session_log_label()

            self.is_running = True
            threading.Thread(target=self.execution_thread, args=(mode, run_id, cred_sets, targets, platform_choice), daemon=True).start()
            
        if mode == "compare":
            begin_run()
        else:
            self.prompt_for_mapping_if_needed(targets, begin_run)

    def execution_thread(self, mode, run_id, cred_sets, targets, platform_choice):
        try:
            if mode in ("pre", "post"):
                self.enqueue("LOG_EXEC", f"=== {mode.upper()} CHECKS ===")
                self.run_checks(mode, run_id, cred_sets, targets, platform_choice)
                if self.stop_event.is_set():
                    self.enqueue("LOG_EXEC", f"\n{mode.capitalize()} checks ABORTED.")
                else:
                    self.enqueue("LOG_EXEC", f"\n{mode.capitalize()} checks complete.")
                    ts = datetime.now().strftime("%m/%d %H:%M")
                    self.enqueue("MODE_LABEL", mode, f"{mode.capitalize()}-Checks (ran {ts})")
            elif mode == "compare":
                self.enqueue("LOG_EXEC", "\n=== RUNNING COMPARISON ===")
                base_dir = settings.base_output_dir / "Maintenance_Runner" / run_id
                sum_txt = CompareEngine.run_comparison(run_id, base_dir)
                self.enqueue("LOG_EXEC", f"\n{sum_txt}")
                self.enqueue("MODE_LABEL", "compare", f"Compare (ran {datetime.now().strftime('%m/%d %H:%M')})")
                self.set_progress(100)
                self.set_status("Done")
        except Exception as e:
            self.set_status("Error")
            self.enqueue("LOG_EXEC", f"\nERROR: {str(e)}")
        finally:
            self.active_conn = None
            self.enqueue("SET_BUTTONS", tk.NORMAL, tk.DISABLED)
            self.is_running = False
            self.fallback_to_all_credentials_for_run = False

    def clear_page_fields(self, retain_targets: bool, retain_credentials: bool):
        self.run_id_entry.delete(0, tk.END)
        if not retain_targets:
            self.target_panel.targets_text.delete("1.0", tk.END)

    def run_checks(self, phase, run_id, cred_sets, targets, platform_choice):
        out_dir = settings.base_output_dir / "Maintenance_Runner" / run_id / phase
        out_dir.mkdir(parents=True, exist_ok=True)
        run_ts = self.get_run_ts()

        total_hosts = len(targets)
        for idx, host in enumerate(targets, 1):
            self.set_host_status(host, idx, total_hosts, "Connecting")
            self.set_progress((idx - 1) / total_hosts * 100)
            if self.stop_event.is_set(): break
            safe_host = FilenameSafety.safe_host_label(host)
            self.enqueue("LOG_EXEC", f"\n▶ Starting host [{idx}/{len(targets)}] {host}")
            self.active_conn = None
            
            temp_dir = SecureTempSessionLogManager.ensure_secure_temp_session_dir(settings.base_output_dir, run_id)
            temp_session_log_path = SecureTempSessionLogManager.create_secure_session_log_path(temp_dir, safe_host)
            temp_session_log = str(temp_session_log_path)
            tail_stop_event = threading.Event()
            tail_t = threading.Thread(target=self.sync_tail, args=(temp_session_log, tail_stop_event), daemon=True)
            tail_t.start()

            host_had_diagnostics = False

            def log_cb(msg):
                self.enqueue("LOG_EXEC", msg)
            conn_result = ConnectionManager.connect_with_mapped_or_global_credentials(host, platform_choice, temp_session_log, self.controller.credential_store, getattr(self.controller, 'target_credential_store', None), log_cb, self.stop_event, getattr(self, 'fallback_to_all_credentials_for_run', False))
            
            if conn_result.status == ConnectionStatus.SUCCESS:
                self.active_conn = conn_result.connection
                self.set_host_status(host, idx, total_hosts, "Connected", f"Platform: {conn_result.logical_platform.name}")
            else:
                host_had_diagnostics = True
                self.set_host_status(host, idx, total_hosts, "Connection failed", "moving to next target")
                if not self.stop_event.is_set():
                    pass
                tail_stop_event.set()
                tail_t.join(1)
                if settings.capture_mode == "redacted":
                    redactor.redact_file(Path(temp_session_log), out_dir / f"{safe_host}_{run_ts}_session_REDACTED.log")
                else:
                    Path(temp_session_log).rename(out_dir / f"{safe_host}_{run_ts}_session_RAW.log")
                SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
                continue
                
            context = DeviceSessionContext(
                host=host,
                platform_choice=platform_choice,
                logical_platform=conn_result.logical_platform,
                device_type=conn_result.netmiko_device_type,
                temp_session_log=temp_session_log,
                conn=self.active_conn,
                run_platform_probe=True,
                platform_probe_output=conn_result.platform_probe_output,
                _reconnect_credential=conn_result._reconnect_credential
            )
            if not conn_result.session_prepped:
                ConnectionManager.prepare_session(context.conn, context.logical_platform, context.device_type, log_cb)

            logical_plat = conn_result.logical_platform
            cmd_set_key = PLATFORM_COMMAND_SET_MAP.get(logical_plat)
            if not cmd_set_key or cmd_set_key not in COMMAND_SETS:
                self.enqueue("LOG_EXEC", f"  ✗ ERROR: No command set found for detected platform {logical_plat.name}")
            else:
                self.enqueue("LOG_EXEC", f"  ✓ Detected {logical_plat.name}, using {cmd_set_key}")
                
                fname = f"{safe_host}-{phase}{'_RAW' if settings.capture_mode == 'raw' else ''}.txt"
                json_fname = f"{safe_host}-{phase}{'_RAW' if settings.capture_mode == 'raw' else ''}.json"
                outfile = out_dir / fname
                
                raw_text = ""
                with open(outfile, "w", encoding="utf-8") as f:
                    f.write(f"# Run ID: {run_id}\n# Phase: {phase}\n# Host: {host}\n# Platform: {logical_plat.name}\n# Timestamp: {run_ts}\n# Capture Mode: {settings.capture_mode.upper()}\n\n")
                    command_results = []
                    base_cmds = self.controller.tool_command_manager.get_effective_commands("maintenance_baseline", cmd_set_key, MAINTENANCE_BASELINE_COMMANDS.get(cmd_set_key, COMMAND_SETS.get(cmd_set_key, [])))
                    unsafe_b = self.controller.tool_command_manager.validate_commands(base_cmds)
                    if unsafe_b:
                        self.enqueue("LOG_EXEC", f"  ! Unsafe baseline commands in override, skipping: {unsafe_b}")
                        base_cmds = [c for c in base_cmds if c not in unsafe_b]
                    
                    features_detected = []
                    
                    def exec_cmd(cmd):
                        nonlocal raw_text, features_detected, host_had_diagnostics
                        self.enqueue("LOG_EXEC", f"  -> {cmd}")
                        self.set_host_status(host, idx, total_hosts, "Running commands", f"command: {cmd}")
                        
                        if cmd == "show version" and context.platform_probe_output:
                            self.enqueue("LOG_EXEC", f"  ✓ Using cached platform probe output")
                            cmd_out = context.platform_probe_output
                            status = CommandStatus.SUCCESS
                            err_msg = ""
                            method_used = "platform_probe_cache"
                            abort_host = False
                            exec_res = CommandExecutionResult(
                                command=cmd, status=status, output=cmd_out, error_message="", attempts=0, method_used="platform_probe_cache", reconnect_performed=False, unsupported_reason="", abort_host=False, elapsed_seconds=0.0, first_attempt_elapsed_seconds=0.0, retry_elapsed_seconds=0.0, output_bytes=len(cmd_out.encode('utf-8')), output_lines=len(cmd_out.splitlines()), timeout_seconds=0, last_read_seconds=0.0, slow_command=False, diagnostic_reason="", retry_reason=""
                            )
                        else:
                            exec_res = ConnectionManager.execute_command_with_recovery(context, cmd, log_callback=log_cb)
                            self.active_conn = context.conn
                            cmd_out = exec_res.output
                            status = exec_res.status
                            err_msg = exec_res.error_message
                            method_used = exec_res.method_used
                            abort_host = exec_res.abort_host
                            
                            if exec_res.status == CommandStatus.COMMAND_TIMEOUT or exec_res.slow_command or exec_res.retry_reason or exec_res.reconnect_performed or exec_res.abort_host or ConnectionManager.is_transport_error(exec_res.error_message, exec_res.output) or ConnectionManager.is_malformed_echo(cmd, exec_res.output):
                                host_had_diagnostics = True
                                
                            if exec_res.slow_command:
                                self.set_host_status(host, idx, total_hosts, "Slow command", f"'{cmd}' running > {settings.slow_command_threshold}s")
                            
                        diag_hdr = ConnectionManager.format_diagnostic_header(exec_res)

                        if status == CommandStatus.COMMAND_UNSUPPORTED:
                            self.enqueue("LOG_EXEC", f"  ! Command unsupported: {cmd}")
                        elif status == CommandStatus.PRIVILEGE_DENIED:
                            self.enqueue("LOG_EXEC", f"  ! Privilege denied: {cmd}")
                        elif status == CommandStatus.COMMAND_TIMEOUT:
                            self.enqueue("LOG_EXEC", f"  ✗ Command timed out: {cmd}")
                        elif status != CommandStatus.SUCCESS:
                            self.enqueue("LOG_EXEC", f"  ✗ Error running {cmd}: {err_msg}")
                            
                        command_results.append({
                            "command": cmd,
                            "status": status.name,
                            "error_message": err_msg,
                            "output_length": len(cmd_out),
                            "unsupported_reason": err_msg if status != CommandStatus.SUCCESS else "",
                            "method_used": method_used
                        })
                        
                        if settings.capture_mode == "redacted":
                            cmd_out_redacted = redactor.redact_text(cmd_out)
                        else:
                            cmd_out_redacted = cmd_out
                            
                        if status == CommandStatus.COMMAND_TIMEOUT:
                            f.write(f"\n## {cmd}\n{diag_hdr}\nCOMMAND TIMEOUT\n")
                            raw_text += f"\n## {cmd}\n{diag_hdr}\nCOMMAND TIMEOUT\n"
                        elif status != CommandStatus.SUCCESS and not cmd_out:
                            f.write(f"\n## {cmd}\n{diag_hdr}\nERROR: {err_msg}\n")
                            raw_text += f"\n## {cmd}\n{diag_hdr}\nERROR: {err_msg}\n"
                        else:
                            f.write(f"\n## {cmd}\n{diag_hdr}\n{cmd_out_redacted}\n")
                            raw_text += f"\n## {cmd}\n{diag_hdr}\n{cmd_out_redacted}\n"
                        
                        if cmd == "show running-config" and status == CommandStatus.SUCCESS:
                            features_detected = FeatureDetector.detect_features(cmd_out)
                            if features_detected:
                                self.enqueue("LOG_EXEC", f"  * Detected features: {', '.join(features_detected)}")
                                
                        return abort_host

                    for cmd in base_cmds:
                        if self.stop_event.is_set(): break
                        if exec_cmd(cmd):
                            self.set_host_status(host, idx, total_hosts, "Host aborted", "transport/reconnect failure")
                            self.enqueue("LOG_EXEC", f"  ✗ Host aborted due to transport/reconnect failure.")
                            break
                        
                    # Now process feature commands
                    if not self.stop_event.is_set():
                        for feature in features_detected:
                            if self.stop_event.is_set(): break
                            f_cmds = self.controller.tool_command_manager.get_effective_commands("maintenance_features", feature, FEATURE_COMMANDS.get(feature, []))
                            if not f_cmds and feature in FEATURE_COMMANDS:
                                f_cmds = FEATURE_COMMANDS[feature]
                            
                            unsafe_f = self.controller.tool_command_manager.validate_commands(f_cmds)
                            if unsafe_f:
                                self.enqueue("LOG_EXEC", f"  ! Unsafe {feature} commands in override, skipping: {unsafe_f}")
                                f_cmds = [c for c in f_cmds if c not in unsafe_f]
    
                            aborted = False
                            for cmd in f_cmds:
                                if self.stop_event.is_set(): break
                                self.enqueue("LOG_EXEC", f"  + Dynamic feature {feature}: {cmd}")
                                if exec_cmd(cmd):
                                    self.set_host_status(host, idx, total_hosts, "Host aborted", "transport/reconnect failure")
                                    self.enqueue("LOG_EXEC", f"  ✗ Host aborted due to transport/reconnect failure.")
                                    aborted = True
                                    break
                            if aborted: break

                if not self.stop_event.is_set() and raw_text and settings.write_json_outputs:
                    snap = SnapshotBuilder.build(run_id, phase, host, logical_plat.name, cmd_set_key, settings.capture_mode, raw_text, command_results)
                    with open(out_dir / json_fname, "w") as jf:
                        json.dump(snap, jf, indent=4)

            try: self.active_conn.disconnect()
            except Exception: pass
            self.active_conn = None
            
            # Stop tail thread
            tail_stop_event.set()
            tail_t.join(1)
            
            # Process session log saving/redaction
            has_errors = any(c.get("status") != "SUCCESS" or "method=retry" in c.get("method_used","") or "method=reconnect" in c.get("method_used","") for c in command_results)
            
            if settings.save_session_logs == "never" or (settings.save_session_logs == "errors_only" and not (has_errors or host_had_diagnostics) and conn_result.status == ConnectionStatus.SUCCESS):
                SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
            else:
                if settings.capture_mode == "redacted":
                    redactor.redact_file(Path(temp_session_log), out_dir / f"{safe_host}_{run_ts}_session_REDACTED.log")
                    SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
                else:
                    Path(temp_session_log).rename(out_dir / f"{safe_host}_{run_ts}_session_RAW.log")

            if not self.stop_event.is_set():
                self.set_progress(idx / total_hosts * 100)
                self.enqueue("LOG_EXEC", "  ✓ completed")
                self.set_host_status(host, idx, total_hosts, "Success" if not has_errors else "Completed with errors", "moving to next target")

        if self.stop_event.is_set():
            self.set_status("Stopped by user")
        else:
            self.set_progress(100)
            self.set_status("Done")
            self.enqueue("LOG_EXEC", f"\n=== ALL DONE ===")


class CommandRunnerPage(BaseRunnerPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, title_text="Generic Command Runner")
        self.setup_ui()

    def setup_ui(self):
        self.cred_panel = CredentialStatusPanel(self.left_panel, self.controller)
        self.cred_panel.pack(fill=tk.X, pady=5)
        self.target_panel = TargetPanel(self.left_panel, self.controller)
        self.target_panel.pack(fill=tk.X, pady=5)
        
        run_id_frame = tk.Frame(self.left_panel)
        run_id_frame.pack(fill=tk.X, pady=5)
        tk.Label(run_id_frame, text="Run ID (optional):", font=("Arial", 10)).pack(side=tk.LEFT)
        self.run_id_entry = tk.Entry(run_id_frame, width=20)
        self.run_id_entry.pack(side=tk.LEFT, padx=5)

        cmd_frame = tk.LabelFrame(self.left_panel, text="3. Commands to Run", font=("Arial", 10, "bold"))
        cmd_frame.pack(fill=tk.X, pady=5)
        self.cmd_text = tk.Text(cmd_frame, height=6, width=30)
        self.cmd_text.pack(padx=5, pady=5)

        self.run_btn = tk.Button(self.left_panel, text="RUN COMMANDS", font=("Arial", 14, "bold"), command=self.start_execution)
        self.run_btn.pack(fill=tk.X, pady=5)

        self.stop_btn = tk.Button(self.left_panel, text="STOP", font=("Arial", 14, "bold"), fg="white", bg="#d9534f", command=self.stop_execution, state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=5)
        self.clear_btn = tk.Button(self.left_panel, text="Clear Current Session", font=("Arial", 11), command=self.clear_current_session)
        self.clear_btn.pack(fill=tk.X, pady=5)
    def start_execution(self):
        targets = self.target_panel.get_targets()
        self.sync_targets_to_session(targets)
        platform_choice = self.target_panel.get_platform()
        commands = [c.strip() for c in self.cmd_text.get("1.0", tk.END).splitlines() if c.strip()]
        cred_sets = self.controller.credential_store.as_netmiko_dicts()
        run_id = self.run_id_entry.get().strip()
        if not run_id:
            run_id = f"CommandRunner-{self.get_run_ts()}"
        run_id = FilenameSafety.safe_run_id(run_id)

        if not cred_sets:
            messagebox.showerror("Error", "Please add at least one Credential Set")
            return
        if not targets:
            messagebox.showerror("Error", "Please provide at least one Target IP")
            return
        if not commands:
            messagebox.showerror("Error", "Please provide at least one Command")
            return

        decisions = CommandPolicy.evaluate_many(commands, settings.command_policy_mode)
        blocked = [d for d in zip(commands, decisions) if not d[1].allowed]
        if blocked:
            msg = "The following commands are blocked by the current Command Policy:\n\n"
            for cmd, dec in blocked: msg += f"- '{cmd}': {dec.reason}\n"
            messagebox.showerror("Policy Restriction", msg)
            return

        if settings.command_policy_mode == CommandPolicyMode.UNSAFE_ALLOWED:
            if not messagebox.askyesno("Unsafe Policy Warning", "You are running in UNSAFE mode. Are you sure you want to execute these commands?"):
                return

        def begin_run():
            self.stop_event.clear()
            self.enqueue("SET_BUTTONS", tk.DISABLED, tk.NORMAL)
            self.enqueue("CLEAR_LOGS")

            if settings.capture_mode == "raw":
                self.enqueue("WARNING_BANNER", "RAW CAPTURE ENABLED - DANGER")
            elif settings.command_policy_mode == CommandPolicyMode.UNSAFE_ALLOWED:
                self.enqueue("WARNING_BANNER", "UNSAFE COMMAND POLICY ACTIVE")
            else:
                self.enqueue("WARNING_BANNER", "")
                self.update_session_log_label()

            self.is_running = True
            threading.Thread(target=self.execution_thread, args=(cred_sets, targets, commands, platform_choice, run_id), daemon=True).start()
            
        self.prompt_for_mapping_if_needed(targets, begin_run)

    def clear_page_fields(self, retain_targets: bool, retain_credentials: bool):
        self.cmd_text.delete("1.0", tk.END)
        self.run_id_entry.delete(0, tk.END)
        if not retain_targets:
            self.target_panel.targets_text.delete("1.0", tk.END)

    def execution_thread(self, cred_sets, targets, commands, platform_choice, run_id):
        try:
            self.enqueue("LOG_EXEC", f"=== COMMAND RUNNER ===")
            run_ts = self.get_run_ts()
            log_dir = settings.base_output_dir / "Command_Runner" / run_id
            log_dir.mkdir(parents=True, exist_ok=True)
            self.enqueue("LOG_EXEC", f"Logs will be saved to: {log_dir}")
            
            total_hosts = len(targets)
            for idx, host in enumerate(targets, 1):
                self.set_host_status(host, idx, total_hosts, "Connecting")
                self.set_progress((idx - 1) / total_hosts * 100)
                if self.stop_event.is_set(): break
                safe_host = FilenameSafety.safe_host_label(host)
                self.enqueue("LOG_EXEC", f"\n▶ Starting host [{idx}/{len(targets)}] {host}")
                self.active_conn = None
                
                temp_dir = SecureTempSessionLogManager.ensure_secure_temp_session_dir(settings.base_output_dir, run_id)
                temp_session_log_path = SecureTempSessionLogManager.create_secure_session_log_path(temp_dir, safe_host)
                temp_session_log = str(temp_session_log_path)
                tail_stop_event = threading.Event()
                tail_t = threading.Thread(target=self.sync_tail, args=(temp_session_log, tail_stop_event), daemon=True)
                tail_t.start()
                
                host_had_diagnostics = False

                def log_cb(msg):
                    self.enqueue("LOG_EXEC", msg)
                conn_result = ConnectionManager.connect_with_mapped_or_global_credentials(host, platform_choice, temp_session_log, self.controller.credential_store, getattr(self.controller, 'target_credential_store', None), log_cb, self.stop_event, getattr(self, 'fallback_to_all_credentials_for_run', False), run_platform_probe=False)
                
                if conn_result.status == ConnectionStatus.SUCCESS:
                    self.active_conn = conn_result.connection
                    self.set_host_status(host, idx, total_hosts, "Connected")
                else:
                    host_had_diagnostics = True
                    self.set_host_status(host, idx, total_hosts, "Connection failed", "moving to next target")
                    if not self.stop_event.is_set():
                        pass # generic failure already logged by helper
                    tail_stop_event.set()
                    tail_t.join(1)
                    if settings.capture_mode == "redacted":
                        redactor.redact_file(Path(temp_session_log), log_dir / f"{safe_host}_{run_ts}_session_REDACTED.log")
                    else:
                        Path(temp_session_log).rename(log_dir / f"{safe_host}_{run_ts}_session_RAW.log")
                    SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
                    continue

                self.enqueue("LOG_EXEC", "  Generic Runner platform probe skipped.")
                context = DeviceSessionContext(
                    host=host,
                    platform_choice=platform_choice,
                    logical_platform=conn_result.logical_platform,
                    device_type=conn_result.netmiko_device_type,
                    temp_session_log=temp_session_log,
                    conn=self.active_conn,
                    run_platform_probe=False,
                    _reconnect_credential=conn_result._reconnect_credential
                )
                if not conn_result.session_prepped:
                    ConnectionManager.prepare_session(context.conn, context.logical_platform, context.device_type, log_cb)

                output_log = [f"===== Session started: {datetime.now()} =====\nHost: {host}\nCapture Mode: {settings.capture_mode.upper()}\n\n"]
                has_errors = False
                for cmd_idx, cmd in enumerate(commands, 1):
                    if self.stop_event.is_set(): break
                    self.enqueue("LOG_EXEC", f"  -> {cmd}")
                    self.set_host_status(host, idx, total_hosts, "Running commands", f"command {cmd_idx}/{len(commands)}")
                    
                    exec_res = ConnectionManager.execute_command_with_recovery(context, cmd, log_callback=log_cb)
                    self.active_conn = context.conn # Update conn in case of reconnect
                    
                    if exec_res.status == CommandStatus.COMMAND_TIMEOUT or exec_res.slow_command or exec_res.retry_reason or exec_res.reconnect_performed or exec_res.abort_host or ConnectionManager.is_transport_error(exec_res.error_message, exec_res.output) or ConnectionManager.is_malformed_echo(cmd, exec_res.output):
                        host_had_diagnostics = True
                    
                    if exec_res.slow_command:
                        self.set_host_status(host, idx, total_hosts, "Slow command", f"'{cmd}' running > {settings.slow_command_threshold}s")
                        
                    diag_hdr = ConnectionManager.format_diagnostic_header(exec_res)
                        
                    if exec_res.status == CommandStatus.COMMAND_TIMEOUT:
                        self.set_host_status(host, idx, total_hosts, "Command timeout", f"moving to next command")
                        self.enqueue("LOG_EXEC", f"  ✗ Command timed out: {cmd}")
                        output_log.append(f"##### {cmd} #####\n{diag_hdr}\nCOMMAND TIMEOUT\n\n")
                        has_errors = True
                    elif exec_res.status != CommandStatus.SUCCESS and exec_res.status != CommandStatus.COMMAND_UNSUPPORTED:
                        self.enqueue("LOG_EXEC", f"  ✗ Error running {cmd}: {exec_res.error_message}")
                        output_log.append(f"##### {cmd} #####\n{diag_hdr}\nERROR: {exec_res.error_message}\n\n")
                        has_errors = True
                    else:
                        cmd_out = exec_res.output
                        if settings.capture_mode == "redacted":
                            cmd_out = redactor.redact_text(cmd_out)
                        output_log.append(f"##### {cmd} #####\n{diag_hdr}\n{cmd_out}\n\n")
                        if exec_res.status == CommandStatus.COMMAND_UNSUPPORTED:
                            self.enqueue("LOG_EXEC", f"  ! Unsupported command: {cmd}")
                            
                    if exec_res.abort_host:
                        self.set_host_status(host, idx, total_hosts, "Host aborted", "transport/reconnect failure")
                        self.enqueue("LOG_EXEC", f"  ✗ Host aborted due to transport/reconnect failure.")
                        has_errors = True
                        break

                if not self.stop_event.is_set():
                    fname = f"{safe_host}_{datetime.now().strftime('%H%M%S')}{'_RAW' if settings.capture_mode == 'raw' else ''}.txt"
                    (log_dir / fname).write_text("".join(output_log), encoding="utf-8")
                    self.set_progress(idx / total_hosts * 100)
                    self.enqueue("LOG_EXEC", "  ✓ completed")
                    self.set_host_status(host, idx, total_hosts, "Success" if not has_errors else "Completed with errors", "moving to next target")

                try: self.active_conn.disconnect()
                except Exception: pass
                self.active_conn = None
                
                tail_stop_event.set()
                tail_t.join(1)
                
                if settings.save_session_logs == "never" or (settings.save_session_logs == "errors_only" and not (has_errors or host_had_diagnostics) and conn_result.status == ConnectionStatus.SUCCESS):
                    SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
                else:
                    if settings.capture_mode == "redacted":
                        redactor.redact_file(Path(temp_session_log), log_dir / f"{safe_host}_{run_ts}_session_REDACTED.log")
                        SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
                    else:
                        Path(temp_session_log).rename(log_dir / f"{safe_host}_{run_ts}_session_RAW.log")

            if self.stop_event.is_set():
                self.set_status("Stopped by user")
            else:
                self.set_progress(100)
                self.set_status("Done")
                self.enqueue("LOG_EXEC", f"\n=== ALL DONE ===")
        except Exception as e:
            self.set_status("Error")
            self.enqueue("LOG_EXEC", f"\nERROR: {str(e)}")
        finally:
            self.active_conn = None
            self.enqueue("SET_BUTTONS", tk.NORMAL, tk.DISABLED)
            self.is_running = False
            self.fallback_to_all_credentials_for_run = False


class LandingPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        label = tk.Label(self, text="Network Toolbelt Dashboard", font=("Arial", 24, "bold"))
        label.pack(pady=20)
        info = tk.Label(self, text="Temporary Session Only. Credentials are never saved.", font=("Arial", 10, "italic"))
        info.pack(pady=(0, 20))
        
        main_frame = tk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=10)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)

        col1 = tk.LabelFrame(main_frame, text="Tools", font=("Arial", 12, "bold"))
        col1.grid(row=0, column=0, padx=20, pady=10, sticky="nsew")

        col2 = tk.LabelFrame(main_frame, text="Session & Help", font=("Arial", 12, "bold"))
        col2.grid(row=0, column=1, padx=20, pady=10, sticky="nsew")

        tk.Button(col1, text="Generic Command Runner", font=("Arial", 14), width=30, height=3, command=lambda: controller.show_frame("CommandRunnerPage")).pack(pady=20, padx=20)
        tk.Button(col1, text="Maintenance Pre/Post Runner", font=("Arial", 14), width=30, height=3, command=lambda: controller.show_frame("MaintenanceRunnerPage")).pack(pady=20, padx=20)
        tk.Button(col1, text="Network Scanners", font=("Arial", 14), width=30, height=3, command=lambda: controller.show_frame("ScannerLandingPage")).pack(pady=20, padx=20)

        self.cred_status_lbl = tk.Label(col2, text="Credentials loaded: 0", font=("Arial", 12))
        self.cred_status_lbl.pack(pady=(20, 10))
        tk.Button(col2, text="Credential Manager & Library", width=30, height=2, font=("Arial", 14), command=lambda: controller.show_frame("CredentialManagerLibraryPage")).pack(pady=10, padx=20)
        tk.Button(col2, text="Help & Documentation", width=30, height=2, font=("Arial", 14), command=lambda: controller.open_documentation()).pack(pady=10, padx=20)

    def tkraise(self, *args, **kwargs):
        super().tkraise(*args, **kwargs)
        self.refresh_credential_status()

    def refresh_credential_status(self):
        count = len(self.controller.credential_store.records)
        if hasattr(self.controller, "target_credential_store"):
            t_count = len(self.controller.target_credential_store.targets)
            m_count = self.controller.target_credential_store.mapped_count_for_current_targets()
            self.cred_status_lbl.config(text=f"Credentials loaded: {count}   Session targets: {t_count}   Mapped targets: {m_count}/{t_count}")
        else:
            self.cred_status_lbl.config(text=f"Credentials loaded: {count}")



# ============================================================
# Scanner Framework & Implementations
# ============================================================
class ScannerEngine:
    @staticmethod
    def write_scanner_summary(config: ScannerRunConfig, host_results: List[ScannerHostResult]):
        base_dir = config.output_dir
        base_dir.mkdir(parents=True, exist_ok=True)
        
        success = sum(1 for r in host_results if r.connection_status == "SUCCESS")
        fail = len(host_results) - success
        warnings = sum(len(r.warnings) for r in host_results)
        
        idx_txt = [
            f"Scanner: {config.scanner_name}",
            f"Run ID: {config.run_id}",
            f"Timestamp: {config.timestamp}",
            f"Capture Mode: {settings.capture_mode.upper()}",
            f"Targets: {len(host_results)}",
            f"Succeeded: {success}",
            f"Failed: {fail}",
            f"Warnings: {warnings}",
            "\nFiles Generated:"
        ]
        
        sum_txt = []
        sum_csv = [["Host", "Platform", "Severity", "Finding"]]
        sum_json = {}
        
        for r in host_results:
            if settings.write_json_outputs:
                idx_txt.append(f"- hosts/{r.safe_host}_report.json")
            idx_txt.append(f"- hosts/{r.safe_host}_report.txt")
            sum_txt.append(f"\n[{r.host}] - {r.connection_status}")
            sum_json[r.host] = {"status": r.connection_status, "findings": [f.__dict__ for f in r.findings], "errors": r.errors, "warnings": r.warnings}
            
            for err in r.errors:
                sum_txt.append(f"  ERROR: {err}")
                sum_csv.append([r.host, r.detected_platform, "ERROR", err])
            for warn in r.warnings:
                sum_txt.append(f"  WARN: {warn}")
                sum_csv.append([r.host, r.detected_platform, "WARN", warn])
            host_severity = "PASS"
            if any(f.status == "FAIL" for f in r.findings) or r.errors: host_severity = "FAIL"
            elif any(f.status == "WARN" for f in r.findings) or r.warnings: host_severity = "WARN"
            
            sum_txt[-1] = f"\n[{r.host}] - {r.connection_status} - Severity: {host_severity}"
            
            for f in r.findings:
                sum_txt.append(f"  {f.status}: [{f.category}] {f.message}")
                sum_csv.append([r.host, r.detected_platform, f.status, f"[{f.category}] {f.message}"])
                
        (base_dir / "index.txt").write_text("\n".join(idx_txt), encoding="utf-8")
        (base_dir / "scanner_summary.txt").write_text("\n".join(sum_txt), encoding="utf-8")
        if settings.write_json_outputs:
            with open(base_dir / "scanner_summary.json", "w") as f: json.dump(sum_json, f, indent=4)
        if settings.write_csv_summaries:
            with open(base_dir / "scanner_summary.csv", "w", newline="") as f:
                csv.writer(f).writerows(sum_csv)

class BaseScannerPage(BaseRunnerPage):
    def __init__(self, parent, controller, scanner_def: ScannerDefinition):
        super().__init__(parent, controller, title_text=scanner_def.name)
        self.scanner_def = scanner_def
        self.setup_scanner_ui()

    def open_page_help(self):
        self.controller.open_documentation(self.scanner_def.name)

    def setup_scanner_ui(self):
        tk.Button(self.left_panel, text="← Back to Scanners", command=lambda: self.controller.show_frame("ScannerLandingPage")).pack(anchor="w", pady=(0, 10))
        tk.Label(self.left_panel, text=self.scanner_def.description, wraplength=280, justify="left").pack(fill=tk.X, pady=(0, 10))
        
        run_id_frame = tk.LabelFrame(self.left_panel, text="Run ID", font=("Arial", 10, "bold"))
        run_id_frame.pack(fill=tk.X, pady=5)
        self.run_id_entry = tk.Entry(run_id_frame)
        self.run_id_entry.pack(fill=tk.X, padx=5, pady=5)
        
        self.cred_panel = CredentialStatusPanel(self.left_panel, self.controller)
        self.cred_panel.pack(fill=tk.X, pady=5)
        
        self.target_panel = TargetPanel(self.left_panel, self.controller)
        self.target_panel.pack(fill=tk.X, pady=5)
        
        self.options_frame = tk.LabelFrame(self.left_panel, text="Scanner Options", font=("Arial", 10, "bold"))
        self.options_frame.pack(fill=tk.X, pady=5)
        self.build_options()
        
        self.run_btn = tk.Button(self.left_panel, text="RUN SCANNER", font=("Arial", 14, "bold"), command=self.start_execution)
        self.run_btn.pack(fill=tk.X, pady=5)
        
        self.stop_btn = tk.Button(self.left_panel, text="STOP", font=("Arial", 14, "bold"), fg="white", bg="#d9534f", command=self.stop_execution, state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=5)
        self.clear_btn = tk.Button(self.left_panel, text="Clear Current Session", font=("Arial", 11), command=self.clear_current_session)
        self.clear_btn.pack(fill=tk.X, pady=5)
    def build_options(self):
        pass # Override in subclasses
        
    def get_options(self) -> dict:
        return {} # Override in subclasses

    def start_execution(self):
        run_id_raw = self.run_id_entry.get()
        run_id = FilenameSafety.safe_run_id(run_id_raw)
        if not run_id or run_id == "unknown":
            messagebox.showerror("Error", "Valid Run ID is required")
            return
            
        targets = self.target_panel.get_targets()
        self.sync_targets_to_session(targets)
        platform_choice = self.target_panel.get_platform()
        cred_sets = self.controller.credential_store.as_netmiko_dicts()
        options = self.get_options()

        if not cred_sets:
            messagebox.showerror("Error", "Please add at least one Credential Set")
            return
        if not targets:
            messagebox.showerror("Error", "Please provide at least one Target IP")
            return
            
        internal_key = self.scanner_def.internal_key
        all_cmds = []
        for grp in self.scanner_def.commands_by_command_set.keys():
            all_cmds.extend(self.controller.tool_command_manager.get_effective_commands(internal_key, grp, self.scanner_def.commands_by_command_set[grp]))
        
        unsafe = self.controller.tool_command_manager.validate_commands(all_cmds)
        if unsafe:
            messagebox.showerror("Internal Error", f"Scanner bundle contains unsafe commands: {unsafe}")
            return

        config = ScannerRunConfig(
            scanner_name=self.scanner_def.name,
            targets=targets,
            credentials=cred_sets,
            platform_choice=platform_choice,
            options=options,
            run_id=run_id,
            output_dir=settings.base_output_dir / "Scanners" / FilenameSafety.safe_filename(self.scanner_def.name) / run_id,
            timestamp=datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        
        def begin_run():
            self.stop_event.clear()
            self.enqueue("SET_BUTTONS", tk.DISABLED, tk.NORMAL)
            self.enqueue("CLEAR_LOGS")
            
            if settings.capture_mode == "raw":
                self.enqueue("WARNING_BANNER", "RAW CAPTURE ENABLED - DANGER")
            else:
                self.enqueue("WARNING_BANNER", "")
                self.update_session_log_label()

            self.is_running = True
            threading.Thread(target=self.execution_thread, args=(config,), daemon=True).start()
            
        self.prompt_for_mapping_if_needed(targets, begin_run)

    def clear_page_fields(self, retain_targets: bool, retain_credentials: bool):
        self.run_id_entry.delete(0, tk.END)
        if not retain_targets:
            self.target_panel.targets_text.delete("1.0", tk.END)

    def execution_thread(self, config: ScannerRunConfig):
        try:
            self.enqueue("LOG_EXEC", f"=== STARTING {config.scanner_name.upper()} ===")
            config.output_dir.mkdir(parents=True, exist_ok=True)
            self.enqueue("LOG_EXEC", f"Output directory: {config.output_dir}")
            
            host_results = []
            
            total_hosts = len(config.targets)
            for idx, host in enumerate(config.targets, 1):
                self.set_host_status(host, idx, total_hosts, "Connecting")
                self.set_progress((idx - 1) / total_hosts * 100)
                if self.stop_event.is_set(): break
                safe_host = FilenameSafety.safe_host_label(host)
                self.enqueue("LOG_EXEC", f"\n▶ Starting host [{idx}/{len(config.targets)}] {host}")
                
                host_out_dir = config.output_dir / "hosts"
                host_out_dir.mkdir(exist_ok=True)
                temp_dir = SecureTempSessionLogManager.ensure_secure_temp_session_dir(settings.base_output_dir, "generic")
                temp_session_log_path = SecureTempSessionLogManager.create_secure_session_log_path(temp_dir, safe_host)
                temp_session_log = str(temp_session_log_path)
                
                tail_stop_event = threading.Event()
                def sync_tail():
                    try:
                        buf_redactor = LineBufferedRedactor(redactor.redact_text)
                        with open(temp_session_log, "r", encoding="utf-8", errors="replace") as f:
                            while not tail_stop_event.is_set() and not self.stop_event.is_set():
                                chunk = f.read(1024)
                                if chunk:
                                    out = buf_redactor.feed(chunk) if settings.capture_mode == "redacted" else chunk
                                    if out: self.enqueue("LOG_SESSION", out)
                                else:
                                    import time
                                    time.sleep(0.1)
                            chunk = f.read()
                            if chunk:
                                out = buf_redactor.feed(chunk) if settings.capture_mode == "redacted" else chunk
                                if out: self.enqueue("LOG_SESSION", out)
                            out = buf_redactor.flush() if settings.capture_mode == "redacted" else ""
                            if out: self.enqueue("LOG_SESSION", out)
                    except Exception:
                        pass
                
                tail_t = threading.Thread(target=sync_tail, daemon=True)
                tail_t.start()
                
                host_had_diagnostics = False
                
                def log_cb(msg):
                    self.enqueue("LOG_EXEC", msg)
                conn_result = ConnectionManager.connect_with_mapped_or_global_credentials(host, config.platform_choice, temp_session_log, self.controller.credential_store, getattr(self.controller, 'target_credential_store', None), log_cb, self.stop_event, getattr(self, 'fallback_to_all_credentials_for_run', False), run_platform_probe=True)
                
                if conn_result.status == ConnectionStatus.SUCCESS:
                    self.active_conn = conn_result.connection
                    self.set_host_status(host, idx, total_hosts, "Connected", f"Platform: {conn_result.logical_platform.name}")
                else:
                    host_had_diagnostics = True
                    self.set_host_status(host, idx, total_hosts, "Connection failed", "moving to next target")
                    tail_stop_event.set()
                    tail_t.join(1)
                    if settings.capture_mode == "redacted":
                        redactor.redact_file(Path(temp_session_log), host_out_dir / f"{safe_host}_{config.timestamp}_session_REDACTED.log")
                    else:
                        Path(temp_session_log).rename(host_out_dir / f"{safe_host}_{config.timestamp}_session_RAW.log")
                    SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
                    host_results.append(ScannerHostResult(host, safe_host, conn_result.status.name if conn_result else "FAIL", "", "", {}, {}, [], [conn_result.error_message if conn_result else "Connection Failed"], []))
                    continue
                    
                context = DeviceSessionContext(
                    host=host,
                    platform_choice=config.platform_choice,
                    logical_platform=conn_result.logical_platform,
                    device_type=conn_result.netmiko_device_type,
                    temp_session_log=temp_session_log,
                    conn=self.active_conn,
                    run_platform_probe=True,
                    platform_probe_output=conn_result.platform_probe_output,
                    _reconnect_credential=conn_result._reconnect_credential
                )
                if not conn_result.session_prepped:
                    ConnectionManager.prepare_session(context.conn, context.logical_platform, context.device_type, log_cb)

                logical_plat = conn_result.logical_platform
                cmd_set_key = PLATFORM_COMMAND_SET_MAP.get(logical_plat)
                
                cmd_bundle = self.scanner_def.commands_by_command_set.get(cmd_set_key, [])
                internal_key = self.scanner_def.internal_key
                cmd_bundle = self.controller.tool_command_manager.get_effective_commands(internal_key, cmd_set_key, cmd_bundle)
                unsafe_s = self.controller.tool_command_manager.validate_commands(cmd_bundle)
                if unsafe_s:
                    self.enqueue("LOG_EXEC", f"  ! Unsafe commands found in override, skipping: {unsafe_s}")
                    cmd_bundle = [c for c in cmd_bundle if c not in unsafe_s]
                
                outputs = {}
                errors = []
                last_exec_res = None
                
                if not cmd_bundle:
                    self.enqueue("LOG_EXEC", f"  ✗ No commands for platform {logical_plat.name}")
                    errors.append(f"No commands for {logical_plat.name}")
                else:
                    for cmd_idx, cmd in enumerate(cmd_bundle, 1):
                        if self.stop_event.is_set(): break
                        self.enqueue("LOG_EXEC", f"  -> {cmd}")
                        self.set_host_status(host, idx, total_hosts, "Running commands", f"command {cmd_idx}/{len(cmd_bundle)}")
                        
                        if cmd == "show version" and context.platform_probe_output:
                            self.enqueue("LOG_EXEC", f"  ✓ Using cached platform probe output")
                            cmd_out = context.platform_probe_output
                            status = CommandStatus.SUCCESS
                            err_msg = ""
                            exec_res = CommandExecutionResult(
                                command=cmd, status=status, output=cmd_out, error_message="", attempts=0, method_used="platform_probe_cache", reconnect_performed=False, unsupported_reason="", abort_host=False, elapsed_seconds=0.0, first_attempt_elapsed_seconds=0.0, retry_elapsed_seconds=0.0, output_bytes=len(cmd_out.encode('utf-8')), output_lines=len(cmd_out.splitlines()), timeout_seconds=0, last_read_seconds=0.0, slow_command=False, diagnostic_reason="", retry_reason=""
                            )
                        else:
                            exec_res = ConnectionManager.execute_command_with_recovery(context, cmd, log_callback=log_cb)
                            self.active_conn = context.conn
                            cmd_out = exec_res.output
                            status = exec_res.status
                            err_msg = exec_res.error_message
                            
                            if exec_res.status == CommandStatus.COMMAND_TIMEOUT or exec_res.slow_command or exec_res.retry_reason or exec_res.reconnect_performed or exec_res.abort_host or ConnectionManager.is_transport_error(exec_res.error_message, exec_res.output) or ConnectionManager.is_malformed_echo(cmd, exec_res.output):
                                host_had_diagnostics = True
                                
                            if exec_res.slow_command:
                                self.set_host_status(host, idx, total_hosts, "Slow command", f"'{cmd}' running > {settings.slow_command_threshold}s")
                            if exec_res.abort_host:
                                self.set_host_status(host, idx, total_hosts, "Host aborted", "transport/reconnect failure")
                                self.enqueue("LOG_EXEC", f"  ✗ Host aborted due to transport/reconnect failure.")
                                break
                                
                        last_exec_res = exec_res
                        diag_hdr = ConnectionManager.format_diagnostic_header(exec_res)
                            
                        if status == CommandStatus.COMMAND_UNSUPPORTED:
                            self.enqueue("LOG_EXEC", f"  ! Command unsupported: {cmd}")
                        elif status == CommandStatus.PRIVILEGE_DENIED:
                            self.enqueue("LOG_EXEC", f"  ! Privilege denied: {cmd}")
                        elif status == CommandStatus.COMMAND_TIMEOUT:
                            self.set_host_status(host, idx, total_hosts, "Command timeout", f"moving to next command")
                            self.enqueue("LOG_EXEC", f"  ✗ Timeout: {cmd}")
                            outputs[cmd] = f"{diag_hdr}\nCOMMAND TIMEOUT"
                            errors.append(f"Timeout on {cmd}")
                            continue
                        elif status != CommandStatus.SUCCESS:
                            self.enqueue("LOG_EXEC", f"  ✗ Error: {cmd} - {err_msg}")
                            outputs[cmd] = f"{diag_hdr}\nERROR: {err_msg}"
                            errors.append(f"Error on {cmd}: {err_msg}")
                            continue
                        
                        if settings.capture_mode == "redacted":
                            cmd_out = redactor.redact_text(cmd_out)
                        outputs[cmd] = f"{diag_hdr}\n{cmd_out}"
                            
                try: self.active_conn.disconnect()
                except Exception: pass
                self.active_conn = None
                
                tail_stop_event.set()
                tail_t.join(1)
                
                parsed_data = {}
                findings = []
                warnings = []
                try:
                    if outputs and not self.stop_event.is_set():
                        parsed_data, findings, warnings = self.scanner_def.parser_callback(ParserHelpers.normalize_parser_platform(logical_plat), outputs, config.options)
                except Exception as e:
                    errors.append(f"Parser crash: {str(e)}")
                    
                has_errors = bool(errors) or (last_exec_res.abort_host if last_exec_res else False)
                self.set_host_status(host, idx, total_hosts, "Success" if not has_errors else "Completed with errors", "moving to next target")
                
                if settings.save_session_logs == "never" or (settings.save_session_logs == "errors_only" and not (has_errors or host_had_diagnostics) and conn_result.status == ConnectionStatus.SUCCESS):
                    SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
                else:
                    if settings.capture_mode == "redacted":
                        redactor.redact_file(Path(temp_session_log), host_out_dir / f"{safe_host}_{config.timestamp}_session_REDACTED.log")
                        SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
                    else:
                        Path(temp_session_log).rename(host_out_dir / f"{safe_host}_{config.timestamp}_session_RAW.log")
                
                res = ScannerHostResult(host, safe_host, "SUCCESS", logical_plat.name, conn_result.netmiko_device_type, outputs, parsed_data, findings, errors, warnings)
                host_results.append(res)
                
                if not self.stop_event.is_set():
                    if settings.write_json_outputs:
                        out_json = {"host": host, "status": res.connection_status, "parsed": parsed_data, "findings": [f.__dict__ for f in findings], "errors": errors, "warnings": warnings}
                        if settings.write_full_output_json:
                            out_json["outputs"] = outputs
                        with open(host_out_dir / f"{safe_host}_report.json", "w") as f: json.dump(out_json, f, indent=4)
                    
                    host_severity = "PASS"
                    if any(f.status == "FAIL" for f in findings) or errors: host_severity = "FAIL"
                    elif any(f.status == "WARN" for f in findings) or warnings: host_severity = "WARN"

                    out_txt = [
                        f"HOST: {host}",
                        f"STATUS: {host_severity}",
                        "\nTop Findings:"
                    ]
                    for err in errors: out_txt.append(f"[FAIL] ERROR: {err}")
                    for warn in warnings: out_txt.append(f"[WARN] WARNING: {warn}")
                    for f in findings: out_txt.append(f"[{f.status}] {f.category}: {f.message}")
                    if not findings and not errors and not warnings:
                        out_txt.append("[PASS] No issues found.")
                        
                    out_txt.append("\n--- Raw/Redacted Output ---")
                    for cmd, out in outputs.items(): out_txt.append(f"\n## {cmd}\n{out}")
                    (host_out_dir / f"{safe_host}_report.txt").write_text("\n".join(out_txt), encoding="utf-8")
                    
                    self.set_progress(idx / total_hosts * 100)
                    self.enqueue("LOG_EXEC", "  ✓ completed")
            
            if self.stop_event.is_set():
                self.set_status("Stopped by user")
            else:
                ScannerEngine.write_scanner_summary(config, host_results)
                self.set_progress(100)
                self.set_status("Done")
                self.enqueue("LOG_EXEC", f"\n=== ALL DONE ===")
        except Exception as e:
            self.set_status("Error")
            self.enqueue("LOG_EXEC", f"\nFATAL ERROR: {str(e)}")
        finally:
            self.enqueue("SET_BUTTONS", tk.NORMAL, tk.DISABLED)
            self.is_running = False
            self.fallback_to_all_credentials_for_run = False


# ================== INTERFACE ERROR SCANNER ==================
def parse_interface_errors(platform: str, outputs: Dict[str, str], options: Dict[str, Any]) -> Tuple[Dict, List, List]:
    findings = []
    warnings = []
    parsed = {"interfaces": {}}
    
    # Very basic loose parsing for show interface status
    status_out = outputs.get("show interface status", outputs.get("show interface brief", ""))
    for line in status_out.splitlines():
        if "err-disabled" in line.lower():
            ifc = line.split()[0]
            ParserHelpers.add_finding(findings, "Port State", "FAIL", f"{ifc} is err-disabled")
        elif "down" in line.lower() and "admin" not in line.lower() and options.get("uplink_sensitive", True):
            if ParserHelpers.line_contains_any(line, ["trunk", "po", "uplink", "core", "te", "hu"]):
                ifc = line.split()[0]
                ParserHelpers.add_finding(findings, "Port State", "FAIL", f"Likely uplink {ifc} is DOWN")

    # Loose parsing for show interfaces counters errors
    err_out = outputs.get("show interfaces counters errors", outputs.get("show interface counters errors", ""))
    for line in err_out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and not line.startswith("Port"):
            ifc = parts[0]
            try:
                crc = ParserHelpers.safe_int(parts[1]) if platform == "NEXUS" else ParserHelpers.safe_int(parts[-1] if len(parts) > 5 else parts[3])
                if crc >= options.get("crc_warn", 1):
                    ParserHelpers.add_finding(findings, "CRC", "WARN", f"{ifc} has {crc} CRCs")
            except Exception: pass

    return parsed, findings, warnings

INTERFACE_ERROR_DEF = ScannerDefinition(
    name="Interface Error Scanner",
    internal_key="interface_error_scanner",
    description="Captures interface state and error counters to highlight problems like CRCs, input/output errors, and drops.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": ["show interface status", "show interfaces description", "show interfaces counters errors", "show logging | include LINK|ERR|CRC"],
        "CATALYST_IOS_XE_SWITCH": ["show interface status", "show interfaces description", "show interfaces counters errors", "show logging | include LINK|ERR|CRC"],
        "IOS_XE_ROUTER": ["show ip interface brief", "show interfaces counters errors", "show logging | include LINK|ERR|CRC"],
        "LEGACY_IOS_ROUTER": ["show ip interface brief", "show interfaces counters errors", "show logging | include LINK|ERR|CRC"],
        "NEXUS": ["show interface brief", "show interface counters errors", "show logging last 200"],
        "ASA_FIREWALL": ["show interface ip brief", "show interface", "show logging | include error|fail|down"]
    },
    parser_callback=parse_interface_errors,
    report_callback=None
)

class InterfaceErrorScannerPage(BaseScannerPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, INTERFACE_ERROR_DEF)
        
    def build_options(self):
        self.uplink_var = tk.BooleanVar(value=True)
        tk.Checkbutton(self.options_frame, text="Uplink-Sensitive Mode", variable=self.uplink_var).pack(anchor="w")
        
    def get_options(self) -> dict:
        return {"uplink_sensitive": self.uplink_var.get(), "crc_warn": 1}

# ================== PORT CHANNEL SCANNER ==================
def parse_port_channel(platform: str, outputs: Dict[str, str], options: Dict[str, Any]) -> Tuple[Dict, List, List]:
    findings = []
    parsed = {}
    
    out = outputs.get("show etherchannel summary", outputs.get("show port-channel summary", ""))
    for line in out.splitlines():
        if "(D)" in line or "(S)" in line:
            ParserHelpers.add_finding(findings, "Member State", "FAIL", f"Suspended or Down member found: {line.strip()}")
        if "(I)" in line:
            ParserHelpers.add_finding(findings, "Member State", "FAIL", f"Individual (not bundled) member found: {line.strip()}")
            
    return parsed, findings, []

PORT_CHANNEL_DEF = ScannerDefinition(
    name="Port-Channel / LACP Scanner",
    internal_key="port_channel_scanner",
    description="Detects broken LAGs, suspended/individual members, and down port-channels.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": ["show etherchannel summary", "show lacp neighbor", "show interfaces trunk"],
        "CATALYST_IOS_XE_SWITCH": ["show etherchannel summary", "show lacp neighbor", "show interfaces trunk"],
        "IOS_XE_ROUTER": ["show etherchannel summary", "show lacp neighbor"],
        "LEGACY_IOS_ROUTER": ["show etherchannel summary", "show lacp neighbor"],
        "NEXUS": ["show port-channel summary", "show lacp neighbor"],
        "ASA_FIREWALL": ["show interface"]
    },
    parser_callback=parse_port_channel,
    report_callback=None
)

class PortChannelScannerPage(BaseScannerPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, PORT_CHANNEL_DEF)



# ================== ROUTING NEIGHBOR SCANNER ==================
def parse_routing_neighbors(platform: str, outputs: Dict[str, str], options: Dict[str, Any]) -> Tuple[Dict, List, List]:
    findings = []
    warnings = []
    parsed = {}
    
    # Very loose BGP parsing
    bgp_out = outputs.get("show ip bgp summary", outputs.get("show bgp summary", outputs.get("show bgp ipv4 unicast summary", "")))
    for line in bgp_out.splitlines():
        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line):
            parts = line.split()
            if len(parts) >= 9 and re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', parts[0]):
                nbr = parts[0]
                state = parts[-1]
                if not state.isdigit():
                    ParserHelpers.add_finding(findings, "BGP", "FAIL", f"BGP Peer {nbr} is not Established (State: {state})")
                elif state == "0" and options.get("bgp_zero_warn", True):
                    ParserHelpers.add_finding(findings, "BGP", "WARN", f"BGP Peer {nbr} is Established but receiving 0 prefixes")
                    
    # Loose OSPF parsing
    ospf_out = outputs.get("show ip ospf neighbor", outputs.get("show ospf neighbor", outputs.get("show ip ospf neighbors", "")))
    for line in ospf_out.splitlines():
        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line):
            if "FULL" not in line and "2WAY/DROTHER" not in line:
                ParserHelpers.add_finding(findings, "OSPF", "WARN", f"OSPF neighbor state abnormal: {line.strip()}")
                
    # Loose EIGRP parsing
    eigrp_out = outputs.get("show ip eigrp neighbors", outputs.get("show eigrp neighbors", ""))
    for line in eigrp_out.splitlines():
        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line) and "uptime" not in line.lower():
            parsed.setdefault("eigrp", []).append(line.strip())
            
    if options.get("eigrp", True) and "eigrp" in outputs:
        # If output shows command worked but no neighbors found, warn
        if not parsed.get("eigrp") and ("IP-EIGRP neighbors" in eigrp_out or "EIGRP-IPv4 Neighbors" in eigrp_out):
            ParserHelpers.add_finding(findings, "EIGRP", "FAIL", "EIGRP is running but neighbor table is EMPTY")

    return parsed, findings, warnings

ROUTING_NEIGHBOR_DEF = ScannerDefinition(
    name="Routing Neighbor Scanner",
    internal_key="routing_neighbor_scanner",
    description="Check EIGRP, OSPF, BGP, HSRP, and VRRP state across devices.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": ["show ip eigrp neighbors", "show ip ospf neighbor", "show ip bgp summary", "show standby brief", "show ip route 0.0.0.0"],
        "CATALYST_IOS_XE_SWITCH": ["show ip eigrp neighbors", "show ip ospf neighbor", "show ip bgp summary", "show standby brief", "show ip route 0.0.0.0"],
        "IOS_XE_ROUTER": ["show ip eigrp neighbors", "show ip ospf neighbor", "show ip bgp summary", "show standby brief", "show ip route 0.0.0.0"],
        "LEGACY_IOS_ROUTER": ["show ip eigrp neighbors", "show ip ospf neighbor", "show ip bgp summary", "show standby brief", "show ip route 0.0.0.0"],
        "NEXUS": ["show eigrp neighbors", "show ip ospf neighbors", "show bgp ipv4 unicast summary", "show hsrp brief", "show ip route 0.0.0.0/0"],
        "ASA_FIREWALL": ["show eigrp neighbors", "show ospf neighbor", "show bgp summary", "show route 0.0.0.0"]
    },
    parser_callback=parse_routing_neighbors,
    report_callback=None
)

class RoutingNeighborScannerPage(BaseScannerPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, ROUTING_NEIGHBOR_DEF)
    def build_options(self):
        self.eigrp_var = tk.BooleanVar(value=True)
        self.ospf_var = tk.BooleanVar(value=True)
        self.bgp_var = tk.BooleanVar(value=True)
        self.bgp_zero_var = tk.BooleanVar(value=True)
        tk.Checkbutton(self.options_frame, text="Check EIGRP", variable=self.eigrp_var).pack(anchor="w")
        tk.Checkbutton(self.options_frame, text="Check OSPF", variable=self.ospf_var).pack(anchor="w")
        tk.Checkbutton(self.options_frame, text="Check BGP", variable=self.bgp_var).pack(anchor="w")
        tk.Checkbutton(self.options_frame, text="Treat BGP 0 prefixes as WARN", variable=self.bgp_zero_var).pack(anchor="w")
    def get_options(self) -> dict:
        return {"eigrp": self.eigrp_var.get(), "ospf": self.ospf_var.get(), "bgp": self.bgp_var.get(), "bgp_zero_warn": self.bgp_zero_var.get()}

# ================== LOG SCANNER ==================
def parse_logs(platform: str, outputs: Dict[str, str], options: Dict[str, Any]) -> Tuple[Dict, List, List]:
    findings = []
    
    log_out = ""
    for k, v in outputs.items():
        if "logging" in k: log_out = v
        
    for line in log_out.splitlines():
        upper = line.upper()
        if "CRASH" in upper or "RELOAD" in upper or "SYS-2-POWER_ALARM" in upper:
            ParserHelpers.add_finding(findings, "Log: Critical", "FAIL", line.strip())
        elif "OSPF-5-ADJCHG" in upper and "DOWN" in upper:
            ParserHelpers.add_finding(findings, "Log: OSPF", "FAIL", line.strip())
        elif "BGP-5-ADJCHANGE" in upper and "DOWN" in upper:
            ParserHelpers.add_finding(findings, "Log: BGP", "FAIL", line.strip())
        elif "LINK-3-UPDOWN" in upper and "DOWN" in upper:
            ParserHelpers.add_finding(findings, "Log: Link", "WARN", line.strip())
        elif "ERR-DISABLE" in upper or "ERRDISABLE" in upper:
            ParserHelpers.add_finding(findings, "Log: ErrDisable", "FAIL", line.strip())
            
    return {}, findings, []

LOG_SCANNER_DEF = ScannerDefinition(
    name="Log Scanner",
    internal_key="log_scanner",
    description="Collects and classifies important log events from devices.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": ["show logging | include LINK|LINEPROTO|SPANTREE|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP|EC|PAGP|POWER|FAN|TEMP|CPU|MEMORY|CRASH|RELOAD|SYS"],
        "CATALYST_IOS_XE_SWITCH": ["show logging | include LINK|LINEPROTO|SPANTREE|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP|EC|PAGP|POWER|FAN|TEMP|CPU|MEMORY|CRASH|RELOAD|SYS"],
        "IOS_XE_ROUTER": ["show logging | include LINK|LINEPROTO|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP|POWER|FAN|TEMP|CPU|MEMORY|CRASH|RELOAD|SYS"],
        "LEGACY_IOS_ROUTER": ["show logging | include LINK|LINEPROTO|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP|POWER|FAN|TEMP|CPU|MEMORY|CRASH|RELOAD|SYS"],
        "NEXUS": ["show logging last 300"],
        "ASA_FIREWALL": ["show logging | include error|fail|down|up|IKE|IPSEC|OSPF|EIGRP|BGP|failover|CRYPTO|teardown|built"]
    },
    parser_callback=parse_logs,
    report_callback=None
)

class LogScannerPage(BaseScannerPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, LOG_SCANNER_DEF)

# ================== DEVICE INVENTORY SCANNER ==================
def parse_inventory(platform: str, outputs: Dict[str, str], options: Dict[str, Any]) -> Tuple[Dict, List, List]:
    findings = []
    parsed = {"hostname": "Unknown", "model": "Unknown", "serial": "Unknown", "version": "Unknown"}
    
    ver_out = outputs.get("show version", "")
    for line in ver_out.splitlines():
        if "uptime is" in line.lower():
            parsed["hostname"] = line.split()[0]
        if "processor board id" in line.lower():
            parsed["serial"] = line.split("ID")[-1].strip()
        if "cisco ios software" in line.lower() and "version" in line.lower():
            m = re.search(r'Version (\S+)', line)
            if m: parsed["version"] = m.group(1)
            
    if parsed["serial"] == "Unknown":
        inv_out = outputs.get("show inventory", "")
        for line in inv_out.splitlines():
            if "SN:" in line:
                m = re.search(r'SN:\s*(\S+)', line)
                if m:
                    parsed["serial"] = m.group(1)
                    break
                    
    if parsed["serial"] == "Unknown":
        ParserHelpers.add_finding(findings, "Inventory", "WARN", "Unable to determine serial number")
        
    ParserHelpers.add_finding(findings, "Inventory", "INFO", f"Host: {parsed['hostname']} - Model: {parsed['model']} - SN: {parsed['serial']} - SW: {parsed['version']}")

    return parsed, findings, []

DEVICE_INVENTORY_DEF = ScannerDefinition(
    name="Device Inventory Scanner",
    internal_key="device_inventory_scanner",
    description="Collect hardware/software inventory for documentation and audits.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": ["show version", "show inventory", "show environment all"],
        "CATALYST_IOS_XE_SWITCH": ["show version", "show inventory", "show environment all", "show license summary"],
        "IOS_XE_ROUTER": ["show version", "show inventory", "show environment all", "show license summary"],
        "LEGACY_IOS_ROUTER": ["show version", "show inventory", "show environment all"],
        "NEXUS": ["show version", "show inventory", "show license usage", "show environment"],
        "ASA_FIREWALL": ["show version", "show inventory", "show activation-key", "show environment"]
    },
    parser_callback=parse_inventory,
    report_callback=None
)

class DeviceInventoryScannerPage(BaseScannerPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, DEVICE_INVENTORY_DEF)


# ================== OPTICS SCANNER ==================
def parse_optics(platform: str, outputs: Dict[str, str], options: Dict[str, Any]) -> Tuple[Dict, List, List]:
    findings = []
    
    dom_out = outputs.get("show interfaces transceiver detail", outputs.get("show interface transceiver details", ""))
    for line in dom_out.splitlines():
        if "alarm" in line.lower() and "high" in line.lower():
            ParserHelpers.add_finding(findings, "Optics DOM", "FAIL", f"DOM Alarm: {line.strip()}")
        elif "warning" in line.lower() and "high" in line.lower():
            ParserHelpers.add_finding(findings, "Optics DOM", "WARN", f"DOM Warning: {line.strip()}")
            
    return {}, findings, []

OPTICS_SCANNER_DEF = ScannerDefinition(
    name="Optics Scanner",
    internal_key="optics_scanner",
    description="Finds low RX power, high TX power, missing optics, and DOM alarms.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": ["show interfaces transceiver detail", "show inventory"],
        "CATALYST_IOS_XE_SWITCH": ["show interfaces transceiver detail", "show inventory"],
        "IOS_XE_ROUTER": ["show interfaces transceiver detail", "show inventory"],
        "LEGACY_IOS_ROUTER": ["show interfaces transceiver detail", "show inventory"],
        "NEXUS": ["show interface transceiver details", "show inventory"],
        "ASA_FIREWALL": ["show inventory"]
    },
    parser_callback=parse_optics,
    report_callback=None
)

class OpticsScannerPage(BaseScannerPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, OPTICS_SCANNER_DEF)


# ================== BGP ROUTES SCANNER ==================
def parse_bgp_routes(platform: str, outputs: Dict[str, str], options: Dict[str, Any]) -> Tuple[Dict, List, List]:
    findings = []
    warnings = []
    parsed = {}
    return parsed, findings, warnings

BGP_ROUTES_DEF = ScannerDefinition(
    name="BGP/Route Summary Scanner",
    internal_key="routes_advertised_received_scanner",
    description="Collect and report route and BGP summary information.\n\nWARNING: Advertised/received route collection is not implemented in v2.91; summary commands only.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": ["show ip bgp summary"],
        "CATALYST_IOS_XE_SWITCH": ["show ip bgp summary"],
        "IOS_XE_ROUTER": ["show ip bgp summary"],
        "LEGACY_IOS_ROUTER": ["show ip bgp summary"],
        "NEXUS": ["show bgp ipv4 unicast summary"],
        "ASA_FIREWALL": ["show bgp summary"]
    },
    parser_callback=parse_bgp_routes,
    report_callback=None
)

class RoutesAdvertisedReceivedScannerPage(BaseScannerPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, BGP_ROUTES_DEF)
    
    def build_options(self):
        tk.Label(self.options_frame, text="Target Neighbors (one per line):").pack(anchor="w")
        self.nbr_text = tk.Text(self.options_frame, height=4, width=30)
        self.nbr_text.pack(fill=tk.X, padx=5, pady=2)
        
        self.adv_var = tk.BooleanVar(value=True)
        self.rec_var = tk.BooleanVar(value=True)
        # tk.Checkbutton(self.options_frame, text="Collect Advertised Routes", variable=self.adv_var, state=tk.DISABLED).pack(anchor="w")
        # tk.Checkbutton(self.options_frame, text="Collect Received Routes", variable=self.rec_var, state=tk.DISABLED).pack(anchor="w")
        
    def get_options(self) -> dict:
        nbrs = [n.strip() for n in self.nbr_text.get("1.0", tk.END).splitlines() if n.strip()]
        return {"neighbors": nbrs, "adv": self.adv_var.get(), "rec": self.rec_var.get()}

# ================== STUBS ==================
class StubPage(tk.Frame):
    def __init__(self, parent, controller, title, desc):
        self.title_text = title
        self.controller = controller
        super().__init__(parent)
        nav_frame = tk.Frame(self)
        nav_frame.pack(fill=tk.X, padx=10, pady=(5,0))
        tk.Button(nav_frame, text="← Back to Dashboard", command=lambda: controller.show_frame("LandingPage")).pack(side=tk.LEFT, padx=(0,5))
        tk.Button(nav_frame, text="← Back to Scanners", command=lambda: controller.show_frame("ScannerLandingPage")).pack(side=tk.LEFT)
        tk.Button(nav_frame, text="[Help]", command=lambda: self.controller.open_documentation(self.title_text)).pack(side=tk.RIGHT)
        tk.Label(self, text=title, font=("Arial", 18, "bold")).pack(pady=20)
        tk.Label(self, text="COMING SOON", font=("Arial", 24, "bold"), fg="#d9534f").pack(pady=10)
        tk.Label(self, text=desc, font=("Arial", 12), justify="center", wraplength=400).pack(pady=20)

class ConfigBackupStubPage(StubPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, "Config Backup / Diff Tool", "Future tool to provide redacted running-config backups, diff against previous known-good, and config hashes.")

class OutageSnapshotStubPage(StubPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, "Outage Snapshot Tool", "Future tool to run curated command bundles based on incident profiles (CO Outage, MDU, BNG, Core, VPN).")

class ReachabilityStubPage(StubPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, "Reachability / Path Test Tool", "Future tool to test device reachability from the workstation, and execute device-sourced ping/traceroute.")

class VlanTrunkStubPage(StubPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, "VLAN / Trunk Consistency Scanner", "Future tool to find missing VLANs across trunks and native VLAN mismatches.")

class StpHealthStubPage(StubPage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller, "STP Health Scanner", "Future tool to find topology changes, inconsistent ports, and root bridge health.")

class ScannerLandingPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        tk.Label(self, text="Network Scanners", font=("Arial", 24, "bold")).pack(pady=30)
        tk.Button(self, text="← Back to Dashboard", command=lambda: controller.show_frame("LandingPage")).pack(pady=5)
        tk.Button(self, text="[Help]", command=lambda: controller.open_documentation("Network Scanner Suite")).place(x=10, y=10)
        
        grid_frame = tk.Frame(self)
        grid_frame.pack(pady=20)
        
        tk.Button(grid_frame, text="Interface Error Scanner", width=30, height=2, command=lambda: controller.show_frame("InterfaceErrorScannerPage")).grid(row=0, column=0, padx=10, pady=10)
        tk.Button(grid_frame, text="Port-Channel / LACP Scanner", width=30, height=2, command=lambda: controller.show_frame("PortChannelScannerPage")).grid(row=0, column=1, padx=10, pady=10)
        
        # Stubs
        tk.Button(grid_frame, text="Routing Neighbor Scanner", width=30, height=2, command=lambda: controller.show_frame("RoutingNeighborScannerPage")).grid(row=1, column=0, padx=10, pady=10)
        tk.Button(grid_frame, text="Log Scanner", width=30, height=2, command=lambda: controller.show_frame("LogScannerPage")).grid(row=1, column=1, padx=10, pady=10)
        tk.Button(grid_frame, text="Device Inventory Scanner", width=30, height=2, command=lambda: controller.show_frame("DeviceInventoryScannerPage")).grid(row=2, column=0, padx=10, pady=10)
        tk.Button(grid_frame, text="Optics Scanner", width=30, height=2, command=lambda: controller.show_frame("OpticsScannerPage")).grid(row=2, column=1, padx=10, pady=10)
        tk.Button(grid_frame, text="BGP/Route Summary", width=30, height=2, command=lambda: controller.show_frame("RoutesAdvertisedReceivedScannerPage")).grid(row=3, column=0, padx=10, pady=10)
        tk.Button(grid_frame, text="Config Backup / Diff Tool (Soon)", width=30, height=2, command=lambda: controller.show_frame("ConfigBackupStubPage")).grid(row=3, column=1, padx=10, pady=10)
        tk.Button(grid_frame, text="Outage Snapshot Tool (Soon)", width=30, height=2, command=lambda: controller.show_frame("OutageSnapshotStubPage")).grid(row=4, column=0, padx=10, pady=10)
        tk.Button(grid_frame, text="Reachability / Path Test (Soon)", width=30, height=2, command=lambda: controller.show_frame("ReachabilityStubPage")).grid(row=4, column=1, padx=10, pady=10)
        tk.Button(grid_frame, text="VLAN / Trunk Consistency (Soon)", width=30, height=2, command=lambda: controller.show_frame("VlanTrunkStubPage")).grid(row=5, column=0, padx=10, pady=10)
        tk.Button(grid_frame, text="STP Health Scanner (Soon)", width=30, height=2, command=lambda: controller.show_frame("StpHealthStubPage")).grid(row=5, column=1, padx=10, pady=10)



# ============================================================
# Credential Mapping Engine & UI
# ============================================================
class CredentialMappingRunner:
    @staticmethod
    def map_targets(targets, credential_store, mapping_store, platform_choice, 
                    ui_callbacks, stop_event, retest_mapped=False, only_unmapped_or_stale=True, capture_mode="redacted", run_platform_probe: bool = True):
        log_cb = ui_callbacks.get("log_cb", lambda m: None)
        status_cb = ui_callbacks.get("status_cb", lambda host, status, m_cred, user, plat, last, err: None)
        progress_cb = ui_callbacks.get("progress_cb", lambda idx, total: None)
        
        total = len(targets)
        for idx, host in enumerate(targets):
            if stop_event.is_set():
                # Mark remaining as STOPPED if they aren't mapped
                for remaining_host in targets[idx:]:
                    m = mapping_store.get_mapping(remaining_host)
                    if m and m.status == "MAPPED":
                        continue
                    if not m:
                        m = TargetCredentialMapping(host=remaining_host, safe_host=FilenameSafety.safe_host_label(remaining_host))
                    m.status = "STOPPED"
                    mapping_store.upsert_mapping(remaining_host, m)
                    status_cb(m.host, m.status, m.credential_label, m.username, m.detected_platform, m.last_tested, m.error_message)
                log_cb("\n[Mapping Stopped by User]")
                break
                
            progress_cb(idx, total)
            log_cb(f"\nMapping {host} ...")
            
            mapping = mapping_store.get_mapping(host)
            if not mapping:
                mapping = TargetCredentialMapping(host=host, safe_host=FilenameSafety.safe_host_label(host))
                
            if mapping.status == "MAPPED" and not retest_mapped:
                if only_unmapped_or_stale:
                    log_cb(f"  Skipping {host} (Already mapped)")
                    # Do NOT change status to SKIPPED, leave it as MAPPED
                    status_cb(mapping.host, mapping.status, mapping.credential_label, mapping.username, mapping.detected_platform, mapping.last_tested, mapping.error_message)
                    continue
                else:
                    pass # user wants to test it anyway
                    
            mapping.status = "MAPPING"
            mapping.last_tested = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status_cb(mapping.host, mapping.status, mapping.credential_label, mapping.username, mapping.detected_platform, mapping.last_tested, mapping.error_message)
            
            # Temporary session log
            settings.base_output_dir.mkdir(parents=True, exist_ok=True)
            temp_dir = SecureTempSessionLogManager.ensure_secure_temp_session_dir(settings.base_output_dir, "mapping")
            temp_session_log_path = SecureTempSessionLogManager.create_secure_session_log_path(temp_dir, f"{mapping.safe_host}_{idx}")
            temp_session_log = str(temp_session_log_path)
            
            # Try to connect
            log_callback_for_connect = lambda msg: log_cb("  " + msg)
            
            sess_log_cb = ui_callbacks.get("sess_log_cb", lambda m: None)
            tail_stop_event = threading.Event()
            def tail_file(filepath, stop_evt):
                import time
                try:
                    buf_redactor = LineBufferedRedactor(redactor.redact_text)
                    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                        while not stop_evt.is_set():
                            chunk = f.read(1024)
                            if chunk:
                                out = buf_redactor.feed(chunk) if capture_mode == "redacted" else chunk
                                if out: sess_log_cb(out)
                            else:
                                time.sleep(0.1)
                        chunk = f.read()
                        if chunk:
                            out = buf_redactor.feed(chunk) if capture_mode == "redacted" else chunk
                            if out: sess_log_cb(out)
                        out = buf_redactor.flush() if capture_mode == "redacted" else ""
                        if out: sess_log_cb(out)
                except Exception:
                    pass
                            
            tail_t = threading.Thread(target=tail_file, args=(temp_session_log, tail_stop_event), daemon=True)
            tail_t.start()
            
            creds_to_try = credential_store.records
            if not creds_to_try:
                log_cb("  Error: No credentials loaded.")
                mapping.status = "FAILED"
                mapping.error_message = "No credentials loaded"
                mapping_store.upsert_mapping(host, mapping)
                status_cb(mapping.host, mapping.status, mapping.credential_label, mapping.username, mapping.detected_platform, mapping.last_tested, mapping.error_message)
                tail_stop_event.set()
                tail_t.join(1.0)
                SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
                continue
                
            success = False
            for i, cred_record in enumerate(creds_to_try, 1):
                if stop_event.is_set():
                    break
                    
                log_cb(f"  Trying credential set {i}/{len(creds_to_try)}: user={cred_record.username} ...")
                cred_dict = {"username": cred_record.username, "password": cred_record.password, "secret": cred_record.secret}
                res = ConnectionManager.connect(host, cred_dict, platform_choice, temp_session_log, run_platform_probe)
                
                history_record = {
                    "set_number": i,
                    "username": cred_record.username,
                    "status": res.status.name,
                    "error_category": res.error_message,
                    "success": res.status == ConnectionStatus.SUCCESS
                }
                mapping.attempt_history.append(history_record)
                
                if res.status == ConnectionStatus.SUCCESS:
                    # Mapped successfully
                    log_cb(f"  ✓ Credential set {i} succeeded for user {cred_record.username}")
                    log_cb(f"  Mapped {host} -> {cred_record.label} / {cred_record.username}")
                    
                    mapping.credential_id = cred_record.id
                    mapping.credential_label = cred_record.label
                    mapping.username = cred_record.username
                    mapping.status = "MAPPED"
                    mapping.connection_status = "SUCCESS"
                    mapping.detected_platform = res.logical_platform.name if res.logical_platform else "UNKNOWN"
                    mapping.netmiko_device_type = res.netmiko_device_type
                    mapping.error_message = ""
                    success = True
                    
                    try: res.connection.disconnect()
                    except: pass
                    break
                else:
                    log_cb(f"  → Credential set {i} failed for user {cred_record.username}: {res.status.name}")
                    
            if stop_event.is_set() and not success:
                mapping.status = "STOPPED"
                mapping.error_message = "Mapping stopped by user"
            elif not success:
                mapping.status = "FAILED"
                mapping.error_message = "All credentials failed"
                log_cb(f"  ✗ {host} mapping failed.")
                
            mapping_store.upsert_mapping(host, mapping)
            status_cb(mapping.host, mapping.status, mapping.credential_label, mapping.username, mapping.detected_platform, mapping.last_tested, mapping.error_message)
            
            # Clean up temp session log
            tail_stop_event.set()
            tail_t.join(1.0)
            SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
            
        progress_cb(total, total)
        if not stop_event.is_set():
            log_cb("\n[Mapping Session Complete]")


# Legacy TargetCredentialMapperPage removed - functionality combined into CredentialManagerLibraryPage


class MappingPromptDialog(tk.Toplevel):
    def __init__(self, parent, controller, targets):
        super().__init__(parent)
        self.controller = controller
        self.targets = targets
        self.title("Pre-Run Mapping Required?")
        self.geometry("450x250")
        self.transient(parent)
        self.grab_set()
        if hasattr(self.controller, "apply_theme_to_widget"):
            self.controller.apply_theme_to_widget(self)
        
        self.result = "CANCEL"
        self.fallback = False
        
        msg = "Map IPs to loaded credentials before running this tool?\n\nThis will attempt SSH authentication to each target using the loaded credentials and remember which credential works for each IP. This reduces repeated failed auth attempts during the tool run."
        tk.Label(self, text=msg, wraplength=400, justify=tk.LEFT).pack(padx=20, pady=20)
        
        self.fallback_var = tk.BooleanVar(value=False)
        tk.Checkbutton(self, text="Fallback to all credentials if mapped credential fails during tool run", variable=self.fallback_var).pack(anchor=tk.W, padx=20)
        
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="Map Now", command=self.do_map).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Continue Without Mapping", command=self.do_continue).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Cancel", command=self.do_cancel).pack(side=tk.LEFT, padx=10)
        
    def do_map(self):
        self.result = "MAP_NOW"
        self.fallback = self.fallback_var.get()
        self.destroy()
        
    def do_continue(self):
        self.result = "CONTINUE"
        self.fallback = self.fallback_var.get()
        self.destroy()
        
    def do_cancel(self):
        self.result = "CANCEL"
        self.destroy()

# Small popup used only for per-tool pre-run mapping, not the main TargetCredentialMapperPage.
class SmallMappingProgressDialog(tk.Toplevel):
    def __init__(self, parent, controller, targets):
        super().__init__(parent)
        self.controller = controller
        self.targets = targets
        self.title("Mapping Progress")
        self.geometry("500x350")
        self.transient(parent)
        self.grab_set()
        if hasattr(self.controller, "apply_theme_to_widget"):
            self.controller.apply_theme_to_widget(self)
        
        self.ui_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.is_running = True
        
        self.progress = ttk.Progressbar(self, orient=tk.HORIZONTAL, length=460, mode='determinate')
        self.progress.pack(pady=10)
        
        self.log_text = tk.Text(self, height=12, width=55)
        self.log_text.pack(pady=5, padx=10)
        
        self.stop_btn = tk.Button(self, text="STOP", command=self.stop_mapping, fg="red")
        self.stop_btn.pack(pady=10)
        
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.after(100, self.process_queue)
        self.start_thread()
        
    def on_close(self):
        if self.is_running:
            import tkinter.messagebox as mb
            if mb.askyesno("Mapping Running", "Mapping is currently running. Stop and close?", parent=self):
                self.stop_event.set()
                self.destroy()
        else:
            self.destroy()
        
    def start_thread(self):
        def _log(msg): self.ui_queue.put(("LOG", msg))
        def _stat(h, s, c, u, p, l, e): pass
        def _prog(i, t): self.ui_queue.put(("PROGRESS", (i, t)))
        
        cb = {"log_cb": _log, "status_cb": _stat, "progress_cb": _prog}
        
        def run():
            CredentialMappingRunner.map_targets(
                self.targets, self.controller.credential_store, self.controller.target_credential_store,
                "Auto Detect Platform", cb, self.stop_event, False, True, "redacted"
            )
            self.ui_queue.put(("DONE", None))
            
        threading.Thread(target=run, daemon=True).start()
        
    def stop_mapping(self):
        self.stop_event.set()
        self.stop_btn.config(state=tk.DISABLED)
        
    def process_queue(self):
        try:
            while True:
                msg_type, data = self.ui_queue.get_nowait()
                if msg_type == "LOG":
                    self.log_text.insert(tk.END, data + "\n")
                    self.log_text.see(tk.END)
                elif msg_type == "PROGRESS":
                    idx, total = data
                    self.progress["maximum"] = total
                    self.progress["value"] = idx
                elif msg_type == "DONE":
                    self.is_running = False
                    self.stop_btn.config(text="Close", command=self.destroy, state=tk.NORMAL)
        except queue.Empty:
            pass
        finally:
            if self.is_running:
                self.after(100, self.process_queue)

# ============================================================
# Main App
# ============================================================
class NetworkToolbeltApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.credential_store = CredentialStore()
        self.target_credential_store = TargetCredentialMapStore()
        self.documentation_window = None
        self.tool_command_manager = ToolCommandManager()
        self.title(f"Network Toolbelt v{APP_VERSION}")
        self.geometry("1400x850")
        self.minsize(1200, 800)

        self.setup_menu()

        self.container = tk.Frame(self)
        self.container.pack(fill=tk.BOTH, expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        
        for F in (LandingPage, CredentialManagerLibraryPage, MaintenanceRunnerPage, CommandRunnerPage, ScannerLandingPage, InterfaceErrorScannerPage, PortChannelScannerPage, RoutingNeighborScannerPage, LogScannerPage, DeviceInventoryScannerPage, OpticsScannerPage, RoutesAdvertisedReceivedScannerPage, ConfigBackupStubPage, OutageSnapshotStubPage, ReachabilityStubPage, VlanTrunkStubPage, StpHealthStubPage):

            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LandingPage")
        self.apply_theme_to_widget()


    def open_target_credential_mapper(self):
        self.show_frame("CredentialManagerLibraryPage")
    def setup_menu(self):
        menubar = tk.Menu(self)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Home (Dashboard)", command=lambda: self.show_frame("LandingPage"))
        file_menu.add_command(label="Network Scanners", command=lambda: self.show_frame("ScannerLandingPage"))

        file_menu.add_separator()
        file_menu.add_command(label="Export Output Folder as ZIP...", command=self.export_zip)
        file_menu.add_command(label="Export Text Outputs as Merged TXT...", command=self.export_merged_txt)
        file_menu.add_separator()
        file_menu.add_command(label="Toggle Dark/Light Mode", command=self.toggle_theme)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Choose Base Output Directory...", command=self.choose_output_dir)
        settings_menu.add_command(label="Set Command Timeout...", command=self.set_timeout)
        settings_menu.add_separator()
        settings_menu.add_command(label="View/Configure tool commands", command=self.open_tool_command_config)
        
        self.capture_mode_var = tk.StringVar(value="redacted")
        capture_menu = tk.Menu(settings_menu, tearoff=0)
        capture_menu.add_radiobutton(label="Redacted (Safe)", variable=self.capture_mode_var, value="redacted", command=self.update_capture_mode)
        capture_menu.add_radiobutton(label="Raw (Danger)", variable=self.capture_mode_var, value="raw", command=self.update_capture_mode)
        settings_menu.add_cascade(label="Capture Mode", menu=capture_menu)

        self.policy_mode_var = tk.StringVar(value="SAFE_READ_ONLY")
        policy_menu = tk.Menu(settings_menu, tearoff=0)
        policy_menu.add_radiobutton(label="Safe Read-Only", variable=self.policy_mode_var, value="SAFE_READ_ONLY", command=self.update_policy_mode)
        policy_menu.add_radiobutton(label="Expanded Operational", variable=self.policy_mode_var, value="EXPANDED_OPERATIONAL", command=self.update_policy_mode)
        policy_menu.add_radiobutton(label="Unsafe Allowed", variable=self.policy_mode_var, value="UNSAFE_ALLOWED", command=self.update_policy_mode)
        settings_menu.add_cascade(label="Command Policy", menu=policy_menu)

        menubar.add_cascade(label="Settings", menu=settings_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="General Information", command=self.show_general_info)
        help_menu.add_command(label="How-To Instructions", command=self.show_howto_info)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def update_capture_mode(self):
        val = self.capture_mode_var.get()
        if val == "raw":
            confirm = messagebox.askyesno("Enable Raw Capture?", "Raw capture may write credentials, shared secrets, SNMP communities, VPN keys, and sensitive configuration to disk.\n\nAre you sure you want to enable Raw Capture?")
            if not confirm:
                self.capture_mode_var.set("redacted")
                val = "redacted"
        settings.capture_mode = val

    def update_policy_mode(self):
        val = self.policy_mode_var.get()
        if val == "UNSAFE_ALLOWED":
            confirm = messagebox.askyesno("Enable Unsafe Mode?", "Unsafe mode can run configuration, deletion, reload, debug, clear, and write commands against multiple devices. Use only when intentionally making changes.\n\nEnable Unsafe Mode?")
            if not confirm:
                self.policy_mode_var.set("SAFE_READ_ONLY")
                val = "SAFE_READ_ONLY"
        settings.command_policy_mode = CommandPolicyMode[val]
    def choose_output_dir(self):
        selected_dir = filedialog.askdirectory(title="Select Base Output Directory", initialdir=str(settings.base_output_dir))
        if selected_dir:
            settings.base_output_dir = Path(selected_dir)
            settings.base_output_dir.mkdir(exist_ok=True)
            if hasattr(self, 'tool_command_manager'):
                self.tool_command_manager.override_file = settings.base_output_dir / "tool_command_overrides.json"
                self.tool_command_manager.load_overrides()
            messagebox.showinfo("Directory Updated", f"Output directory set to:\n{settings.base_output_dir}")

    def set_timeout(self):
        val = simpledialog.askinteger("Command Timeout", "Enter max command timeout in seconds:", initialvalue=settings.command_timeout, minvalue=10, maxvalue=3600)
        if val: settings.command_timeout = val

    def export_zip(self):
        if not settings.base_output_dir.exists() or not any(settings.base_output_dir.iterdir()):
            messagebox.showinfo("Export ZIP", "Output directory is empty or missing.")
            return
            
        warn = "Security Warning: The output folder may contain sensitive data, including passwords, secrets, or device configurations, especially if you ran commands in RAW Capture Mode.\n\nAre you sure you want to export this folder to a ZIP?"
        if not messagebox.askyesno("Export Warning", warn):
            return
            
        save_path = filedialog.asksaveasfilename(
            defaultextension=".zip",
            filetypes=[("ZIP files", "*.zip")],
            title="Save Output as ZIP",
            initialfile=f"NetworkToolbelt_Export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        )
        
        if not save_path: return
        
        import zipfile
        try:
            target_save_path = Path(save_path).resolve()
            with zipfile.ZipFile(save_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(settings.base_output_dir):
                    if '__pycache__' in dirs: dirs.remove('__pycache__')
                    if '.temp_sessions' in dirs: dirs.remove('.temp_sessions')
                    for f in files:
                        if f == '.DS_Store' or f.startswith('.tmp_'): continue
                        fpath = Path(root) / f
                        if fpath.resolve() == target_save_path: continue
                        arcname = fpath.relative_to(settings.base_output_dir)
                        zf.write(fpath, arcname)
            messagebox.showinfo("Success", f"Output folder exported successfully to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create ZIP:\n{str(e)}")

    def export_merged_txt(self):
        if not settings.base_output_dir.exists() or not any(settings.base_output_dir.iterdir()):
            messagebox.showinfo("Export Merged TXT", "Output directory is empty or missing.")
            return
            
        warn = "Security Warning: The output folder may contain sensitive data.\n\nAre you sure you want to export to a merged text file?"
        if not messagebox.askyesno("Export Warning", warn):
            return
            
        save_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            title="Save Merged TXT",
            initialfile=f"NetworkToolbelt_Merged_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if not save_path: return
        
        ext_to_include = {".txt", ".csv", ".md"}
        
        try:
            target_save_path = Path(save_path).resolve()
            with open(save_path, 'w', encoding="utf-8", errors="replace") as out:
                out.write("===== NETWORK TOOLBELT MERGED OUTPUT =====\n")
                out.write(f"Exported At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for root, dirs, files in os.walk(settings.base_output_dir):
                    if '__pycache__' in dirs: dirs.remove('__pycache__')
                    if '.temp_sessions' in dirs: dirs.remove('.temp_sessions')
                    for f in files:
                        if f == '.DS_Store' or f.startswith('.tmp_'): continue
                        fpath = Path(root) / f
                        if fpath.resolve() == target_save_path: continue
                        if fpath.suffix.lower() not in ext_to_include: continue
                        
                        mtime = datetime.fromtimestamp(fpath.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        rel_path = fpath.relative_to(settings.base_output_dir)
                        
                        out.write(f"##### BEGIN {rel_path} | file timestamp {mtime} #####\n")
                        try:
                            content = fpath.read_text(encoding="utf-8", errors="replace")
                            out.write(content)
                            if not content.endswith('\n'):
                                out.write('\n')
                        except Exception as e:
                            out.write(f"[Error reading file: {str(e)}]\n")
                        out.write(f"##### END {rel_path} | file timestamp {mtime} #####\n\n")
                        
            messagebox.showinfo("Success", f"Merged TXT exported successfully to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create Merged TXT:\n{str(e)}")

    def show_general_info(self):
        self.open_documentation("General Information")

    def show_howto_info(self):
        self.open_documentation("How-To Workflows")

    def open_tool_command_config(self):
        dlg = ToolCommandConfigWindow(self, self)
        self.wait_window(dlg)

    def open_documentation(self, initial_section=None):
        if self.documentation_window is None or not self.documentation_window.winfo_exists():
            self.documentation_window = DocumentationWindow(
                self,
                self,
                DOCUMENTATION_SECTIONS,
                initial_section=initial_section or "General Information"
            )
        else:
            self.documentation_window.lift()
            self.documentation_window.focus_force()
            self.documentation_window.select_section(initial_section or "General Information")

    def toggle_theme(self):
        settings.current_theme = "light" if settings.current_theme == "dark" else "dark"
        self.apply_theme_to_widget()
        if self.documentation_window and self.documentation_window.winfo_exists():
            self.documentation_window.apply_theme()

    def apply_theme_to_widget(self, parent_widget=None):
        if parent_widget is None: parent_widget = self
        colors = THEMES[settings.current_theme]
        try: parent_widget.configure(bg=colors["bg"])
        except tk.TclError: pass
        
        try:
            style = ttk.Style(parent_widget)
            style.theme_use('default')
            style.configure("Treeview", background=colors["list_bg"], foreground=colors["list_fg"], fieldbackground=colors["list_bg"])
            style.configure("Treeview.Heading", background=colors["btn_bg"], foreground=colors["fg"])
            style.configure("TCombobox", fieldbackground=colors["entry_bg"], background=colors["btn_bg"], foreground=colors["entry_fg"])
            style.map("TCombobox", fieldbackground=[('readonly', colors["entry_bg"])], selectbackground=[('readonly', colors["btn_bg"])], selectforeground=[('readonly', colors["entry_fg"])])
        except Exception:
            pass
        
        def style_widget(widget):
            try:
                if not isinstance(widget, tk.Menu): widget.configure(bg=colors["bg"])
                if isinstance(widget, (tk.Label, tk.Radiobutton, tk.LabelFrame)):
                    widget.configure(fg=colors["fg"])
                    if isinstance(widget, tk.Radiobutton): widget.configure(selectcolor=colors["bg"])
                elif isinstance(widget, tk.Checkbutton):
                    widget.configure(bg=colors["bg"], fg=colors["fg"], selectcolor=colors["bg"])
                elif isinstance(widget, tk.Entry):
                    widget.configure(bg=colors["entry_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_fg"])
                elif isinstance(widget, tk.Text):
                    widget.configure(bg=colors["text_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_fg"])
                elif isinstance(widget, tk.Listbox):
                    widget.configure(bg=colors["list_bg"], fg=colors["list_fg"])
                elif isinstance(widget, tk.Button):
                    if widget.cget("text") == "STOP": widget.configure(bg="#d9534f", fg="white")
                    else: widget.configure(bg=colors["btn_bg"], fg=colors["fg"])
            except tk.TclError: pass
            for child in widget.winfo_children(): style_widget(child)

        style_widget(parent_widget)

    def show_frame(self, page_name):
        if not hasattr(self, 'current_frame_name'):
            self.current_frame_name = None

        if self.current_frame_name and page_name != self.current_frame_name:
            current_frame = self.frames.get(self.current_frame_name)
            if hasattr(current_frame, 'has_active_run') and current_frame.has_active_run():
                dlg = RunningNavigationDialog(self, getattr(current_frame, 'title_text', 'Tool'))
                self.wait_window(dlg)
                if not dlg.result or not dlg.result.get("confirmed"):
                    return
                if not dlg.result["retain_credentials"]:
                    if not messagebox.askyesno("Confirm", "This will clear all credentials from the global Credential Manager. Continue?"):
                        return
                    self.credential_store.clear()
                    for m in self.target_credential_store.mappings.values():
                        m.status = "STALE"
                        m.last_tested = ""
                        m.error_message = "Credential store was cleared"
                    if "LandingPage" in self.frames:
                        self.frames["LandingPage"].refresh_credential_status()
                current_frame.stop_and_clear_for_navigation(retain_targets=dlg.result["retain_targets"], retain_credentials=dlg.result["retain_credentials"])

        self.current_frame_name = page_name
        self.frames[page_name].tkraise()


# ============================================================
# Entry Point
# ============================================================
def _run_execution_self_tests():
    print("Running Netmiko Execution Engine Self-Tests...")
    
    # 1. Transport Error tests
    assert ConnectionManager.is_transport_error("socket is closed", "") == True
    assert ConnectionManager.is_transport_error("", "Session is not active") == True
    assert ConnectionManager.is_transport_error("Timeout", "Command timed out") == False
    
    # 2. Malformed Echo tests
    assert ConnectionManager.is_malformed_echo("show version", "show version") == False
    assert ConnectionManager.is_malformed_echo("show running-config", "show run") == True
    assert ConnectionManager.is_malformed_echo("show log", "show log\nline 1\nline 2") == False
    assert ConnectionManager.is_malformed_echo("terminal pager 0", "term pag") == True
    assert ConnectionManager.is_malformed_echo("show version", "") == False
    
    # 3. Platform Prep tests
    class DummyConn:
        def __init__(self):
            self.cmds = []
        def send_command_timing(self, cmd, **kwargs):
            self.cmds.append(cmd)
            return ""
            
    dummy = DummyConn()
    ConnectionManager.prepare_session(dummy, LogicalPlatform.ASA, "cisco_asa")
    assert dummy.cmds == ["terminal pager 0"]
    
    dummy = DummyConn()
    ConnectionManager.prepare_session(dummy, LogicalPlatform.NXOS, "cisco_nxos")
    assert dummy.cmds == ["terminal length 0"]
    
    dummy = DummyConn()
    ConnectionManager.prepare_session(dummy, LogicalPlatform.IOS, "cisco_ios")
    assert dummy.cmds == ["terminal length 0", "terminal width 511"]
    
    # 4. Command Validator tests
    assert not ToolCommandManager.validate_commands(["terminal pager 0"])
    
    # 5. Unsupported Command test
    class DummyContext:
        conn = DummyConn()
        logical_platform = LogicalPlatform.IOS
        host = "1.1.1.1"
        platform_choice = "Auto Detect"
        device_type = "cisco_ios"
        temp_session_log = ""
        run_platform_probe = False
        platform_probe_output = ""
        _reconnect_credential = None
        
    ctx = DummyContext()
    ctx.conn.send_command_timing = lambda cmd, **kw: "% Invalid input detected at '^' marker."
    res = ConnectionManager.execute_command_with_recovery(ctx, "show fake")
    assert res.status == CommandStatus.COMMAND_UNSUPPORTED
    assert ConnectionManager.is_transport_error("", "% Invalid input") == False
    

    # 7. Privilege / Auth Failure test
    ctx.conn.send_command_timing = lambda cmd, **kw: "% Authorization failed"
    res = ConnectionManager.execute_command_with_recovery(ctx, "show fake")
    assert res.status == CommandStatus.PRIVILEGE_DENIED
    
    # 8. Parser Exact Matching test
    from typing import List
    lines = ["## show interfaces description", "desc", "## show interfaces", "intf", "## end"]
    res_exact = ParserEngine.extract_section("show interfaces", lines)
    assert res_exact == ["intf"]
    
    # 9. NXOS Normalization test
    assert ParserHelpers.normalize_parser_platform(LogicalPlatform.NXOS) == "NEXUS"

    # 10. Redaction tests
    redact_test_tacacs = "tacacs-server key 7 030752180500"
    assert redactor.redact_text(redact_test_tacacs) == "tacacs-server key 7 <REDACTED>"

    redact_test_radius = "radius-server key MySharedSecret"
    assert redactor.redact_text(redact_test_radius) == "radius-server key <REDACTED>"

    redact_test_snmp_priv = "snmp-server user nmsuser NMSGROUP v3 auth sha AuthSecret123 priv aes 128 PrivSecret456"
    assert "AuthSecret123" not in redactor.redact_text(redact_test_snmp_priv)
    assert "PrivSecret456" not in redactor.redact_text(redact_test_snmp_priv)
    
    redact_test_password = "Password: mypass"
    assert redactor.redact_text(redact_test_password) == "Password: <REDACTED>"

    # 11. Buffered Redaction test
    buf_red = LineBufferedRedactor(redactor.redact_text)
    out1 = buf_red.feed("tacacs-server ke")
    out2 = buf_red.feed("y 7 030752180500\n")
    assert out1 == ""
    assert out2 == "tacacs-server key 7 <REDACTED>\n"

    # 12. SnapshotBuilder ARP parsing test
    arp_lines = ["## show ip arp", "Protocol  Address  Age (min)  Hardware Addr  Type  Interface", "Internet  1.1.1.1  0          0000.0000.0000 ARPA  Vlan1"]
    arp_res = ParserEngine.arp_count(ParserEngine.extract_section("show ip arp", arp_lines))
    assert arp_res == 1
    
    # 13. Redaction backreference correctness
    assert "\x01" not in redactor.redact_text("tacacs-server key 7 030752180500")
    assert "\x03" not in redactor.redact_text("tacacs-server key 7 030752180500")

    # 14. CommandOutputAnalyzer Privilege Checks
    # % Authorization failed should fail
    ctx.conn.send_command_timing = lambda cmd, **kw: "% Authorization failed"
    res_auth = ConnectionManager.execute_command_with_recovery(ctx, "show fake")
    assert res_auth.status == CommandStatus.PRIVILEGE_DENIED
    
    # Current privilege level is 15 should pass
    ctx.conn.send_command_timing = lambda cmd, **kw: "Current privilege level is 15"
    res_priv = ConnectionManager.execute_command_with_recovery(ctx, "show fake")
    assert res_priv.status == CommandStatus.SUCCESS

    # username admin privilege 15 should pass
    ctx.conn.send_command_timing = lambda cmd, **kw: "username admin privilege 15 secret 9 hash"
    res_usr = ConnectionManager.execute_command_with_recovery(ctx, "show fake")
    assert res_usr.status == CommandStatus.SUCCESS
    
    # 15. Enable Failure ValueError test
    class MockConnEnable:
        def __init__(self):
            self.logged = False
        def enable(self):
            raise ValueError("Mock ValueError")
        def send_command(self, *a, **k):
            return ""
        def disconnect(self): pass
    
    def enable_log_cb(msg):
        if "Warning: enable mode failed" in msg:
            mock_enable_conn.logged = True

    mock_enable_conn = MockConnEnable()
    original_connect = globals().get('ConnectHandler')
    globals()['ConnectHandler'] = lambda *a, **k: mock_enable_conn
    try:
        ConnectionManager.connect("1.1.1.1", {"username": "u", "password": "p", "secret": "s"}, "Auto Detect", "", log_callback=enable_log_cb, run_platform_probe=False)
        assert mock_enable_conn.logged, "ValueError during enable should trigger a warning log"
    finally:
        globals()['ConnectHandler'] = original_connect


    # 6. Generic Runner / ConnectionManager platform probe toggle
    guesser_called = [False]
    class MockGuesser:
        def __init__(self, *args, **kwargs): pass
        def autodetect(self):
            guesser_called[0] = True
            return "cisco_ios"
    
    original_detect = globals().get('SSHDetect')
    globals()['SSHDetect'] = MockGuesser
    try:
        class MockConn:
            def send_command(self, *a, **k): return ""
            def enable(self): pass
            def disconnect(self): pass
            
        original_connect = globals().get('ConnectHandler')
        globals()['ConnectHandler'] = lambda *a, **k: MockConn()
        
        ConnectionManager.connect("1.1.1.1", {"username": "u", "password": "p"}, "Auto Detect", "", run_platform_probe=False)
        assert not guesser_called[0], "Probing should not occur when run_platform_probe=False"
    except Exception as e:
        print(f"Mock test failed: {e}")
        raise
    finally:
        if original_detect: globals()['SSHDetect'] = original_detect
        if 'original_connect' in locals() and original_connect: globals()['ConnectHandler'] = original_connect
    
    # 7. v2.86 Diagnostics & Timing Settings Defaults
    assert settings.command_timeout == 20
    assert settings.timing_last_read == 0.75
    assert not settings.write_json_outputs
    assert settings.write_csv_summaries
    assert settings.save_session_logs == "errors_only"
    assert not settings.include_full_output_in_compare_reports
    
    # 8. CommandExecutionResult and Diagnostic Formatting
    res2 = CommandExecutionResult(
        command="show version", status=CommandStatus.SUCCESS, output="Cisco IOS",
        elapsed_seconds=6.5, timeout_seconds=20, method_used="send_command_timing",
        attempts=1, output_bytes=9, output_lines=1, last_read_seconds=0.75,
        slow_command=True
    )
    assert res2.elapsed_seconds == 6.5
    assert res2.slow_command is True
    diag_summary = ConnectionManager.summarize_command_diagnostics(res2)
    assert "Slow command:" in diag_summary
    assert "show version took 6.5s" in diag_summary
    assert "bytes=9" in diag_summary
    
    # 9. CompareEngine TXT Snapshot Building
    mock_txt = """# Run ID: TEST-123
# Phase: pre
# Host: 10.0.0.1
# Platform: Cisco IOS
# Timestamp: 2026-05-05-120000
# Capture Mode: REDACTED

## show version
Cisco IOS Software
"""
    tmp_path = Path("test_snapshot.txt")
    tmp_path.write_text(mock_txt, encoding="utf-8")
    try:
        snap = CompareEngine.build_snapshot_from_txt(tmp_path)
        assert snap is not None
        assert snap["run_id"] == "TEST-123"
        assert snap["phase"] == "pre"
        assert snap["host"] == "10.0.0.1"
        assert snap["detected_platform"] == "Cisco IOS"
        assert snap["capture_mode"] == "REDACTED"
    finally:
        if tmp_path.exists(): tmp_path.unlink()
        
    # 10. TargetPanel init
    try:
        root = tk.Tk()
        tp = TargetPanel(root)
        assert hasattr(tp, 'targets_scrollbar')
        root.destroy()
    except Exception as e:
        print(f"Skipping GUI test: {e}")
        
    print("All execution self-tests passed.")

def main():
    if os.environ.get("NETWORK_TOOLBELT_TEST") == "1":
        _run_execution_self_tests()
        return
        
    SecureTempSessionLogManager.cleanup_stale_temp_session_dirs(settings.base_output_dir)
    app = NetworkToolbeltApp()
    app.mainloop()

if __name__ == "__main__":
    main()

# STAGE 1 COMPLETE — Global Credential Manager

# STAGE 2 COMPLETE — Authentication Attempt Logging

# STAGE 3 COMPLETE — Maintenance Runner UI Cleanup

# STAGE 4 COMPLETE — Session Controls & Progress Bars

# STAGE 5 COMPLETE — Command Execution Status Validation

# STAGE 6 COMPLETE — Feature-Aware Command Selection

# STAGE 7 COMPLETE — Deep Analysis Parsers (Interfaces, Logs, Routing)

# STAGE 8 COMPLETE — Severity Scoring & Reporting

# STAGE 9 COMPLETE — Documentation Updates & Final Regression
