"""Global settings, platform maps, command definitions, and filename safety helpers."""

import re
from enum import Enum, auto
from pathlib import Path

APP_VERSION = "3.32"

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

class CommandPolicyMode(Enum):
    SAFE_READ_ONLY = auto()
    EXPANDED_OPERATIONAL = auto()
    UNSAFE_ALLOWED = auto()

class LogicalPlatform(Enum):
    IOS = auto()
    IOS_XE_SWITCH = auto()
    IOS_XE_ROUTER = auto()
    IOS_LEGACY_ROUTER = auto()
    NXOS = auto()
    ASA = auto()
    UNKNOWN_CISCO = auto()

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
        self.concurrency_maintenance = 3
        self.concurrency_scanners = 3
        self.concurrency_command = 3
        self.concurrency_mapper = 3

settings = AppSettings()

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

class FilenameSafety:
    @staticmethod
    def safe_filename(value: str, max_len: int = 100) -> str:
        if not value:
            return "unknown"
        v = value.replace(":", "_")
        v = re.sub(r"[^A-Za-z0-9_\.-]", "_", v)
        v = re.sub(r"_+", "_", v)
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
