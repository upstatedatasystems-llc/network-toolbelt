"""Scanner definitions, scanner engine, and output parsers for Network Toolbelt."""

import csv
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from network_toolbelt.core.maintenance import CompareFinding, ParserHelpers
from network_toolbelt.core.settings import FilenameSafety, settings


@dataclass
class ScannerRunConfig:
    scanner_name: str
    targets: List[str]
    credentials: List[dict]
    platform_choice: str
    options: dict
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
    outputs: Dict[str, str]
    parsed_data: dict
    findings: List[CompareFinding]
    errors: List[str]
    warnings: List[str]


@dataclass
class ScannerDefinition:
    name: str
    internal_key: str
    description: str
    commands_by_command_set: Dict[str, List[str]]
    parser_callback: Callable[[str, Dict[str, str], Dict[str, Any]], Tuple[Dict, List, List]]
    report_callback: Optional[Callable] = None


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
            "\nFiles Generated:",
        ]

        sum_txt = []
        sum_csv = [["Host", "Platform", "Severity", "Finding"]]
        sum_json = {}

        for r in host_results:
            if settings.write_json_outputs:
                idx_txt.append(f"- hosts/{r.safe_host}_report.json")
            idx_txt.append(f"- hosts/{r.safe_host}_report.txt")
            sum_txt.append(f"\n[{r.host}] - {r.connection_status}")
            sum_json[r.host] = {
                "status": r.connection_status,
                "findings": [f.__dict__ for f in r.findings],
                "errors": r.errors,
                "warnings": r.warnings,
            }

            for err in r.errors:
                sum_txt.append(f"  ERROR: {err}")
                sum_csv.append([r.host, r.detected_platform, "ERROR", err])
            for warn in r.warnings:
                sum_txt.append(f"  WARN: {warn}")
                sum_csv.append([r.host, r.detected_platform, "WARN", warn])
            host_severity = "PASS"
            if any(f.status == "FAIL" for f in r.findings) or r.errors:
                host_severity = "FAIL"
            elif any(f.status == "WARN" for f in r.findings) or r.warnings:
                host_severity = "WARN"

            sum_txt[-1] = f"\n[{r.host}] - {r.connection_status} - Severity: {host_severity}"

            for f in r.findings:
                sum_txt.append(f"  {f.status}: [{f.category}] {f.message}")
                sum_csv.append([r.host, r.detected_platform, f.status, f"[{f.category}] {f.message}"])

        (base_dir / "index.txt").write_text("\n".join(idx_txt), encoding="utf-8")
        (base_dir / "scanner_summary.txt").write_text("\n".join(sum_txt), encoding="utf-8")
        if settings.write_json_outputs:
            with open(base_dir / "scanner_summary.json", "w") as f:
                json.dump(sum_json, f, indent=4)
        if settings.write_csv_summaries:
            with open(base_dir / "scanner_summary.csv", "w", newline="") as f:
                csv.writer(f).writerows(sum_csv)


# ================== INTERFACE ERROR SCANNER ==================
def parse_interface_errors(
    platform: str, outputs: Dict[str, str], options: Dict[str, Any]
) -> Tuple[Dict, List, List]:
    findings = []
    warnings = []
    parsed = {"interfaces": {}}

    status_out = outputs.get("show interface status", outputs.get("show interface brief", ""))
    for line in status_out.splitlines():
        if "err-disabled" in line.lower():
            ifc = line.split()[0]
            ParserHelpers.add_finding(findings, "Port State", "FAIL", f"{ifc} is err-disabled")
        elif (
            "down" in line.lower()
            and "admin" not in line.lower()
            and options.get("uplink_sensitive", True)
        ):
            if ParserHelpers.line_contains_any(line, ["trunk", "po", "uplink", "core", "te", "hu"]):
                ifc = line.split()[0]
                ParserHelpers.add_finding(findings, "Port State", "FAIL", f"Likely uplink {ifc} is DOWN")

    err_out = outputs.get(
        "show interfaces counters errors", outputs.get("show interface counters errors", "")
    )
    for line in err_out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and not line.startswith("Port"):
            ifc = parts[0]
            try:
                crc = (
                    ParserHelpers.safe_int(parts[1])
                    if platform == "NEXUS"
                    else ParserHelpers.safe_int(parts[-1] if len(parts) > 5 else parts[3])
                )
                if crc >= options.get("crc_warn", 1):
                    ParserHelpers.add_finding(findings, "CRC", "WARN", f"{ifc} has {crc} CRCs")
            except Exception:
                pass

    return parsed, findings, warnings


INTERFACE_ERROR_DEF = ScannerDefinition(
    name="Interface Error Scanner",
    internal_key="interface_error_scanner",
    description="Captures interface state and error counters to highlight problems like CRCs, input/output errors, and drops.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": [
            "show interface status",
            "show interfaces description",
            "show interfaces counters errors",
            "show logging | include LINK|ERR|CRC",
        ],
        "CATALYST_IOS_XE_SWITCH": [
            "show interface status",
            "show interfaces description",
            "show interfaces counters errors",
            "show logging | include LINK|ERR|CRC",
        ],
        "IOS_XE_ROUTER": [
            "show ip interface brief",
            "show interfaces counters errors",
            "show logging | include LINK|ERR|CRC",
        ],
        "LEGACY_IOS_ROUTER": [
            "show ip interface brief",
            "show interfaces counters errors",
            "show logging | include LINK|ERR|CRC",
        ],
        "NEXUS": [
            "show interface brief",
            "show interface counters errors",
            "show logging last 200",
        ],
        "ASA_FIREWALL": [
            "show interface ip brief",
            "show interface",
            "show logging | include error|fail|down",
        ],
    },
    parser_callback=parse_interface_errors,
)


# ================== PORT CHANNEL SCANNER ==================
def parse_port_channel(
    platform: str, outputs: Dict[str, str], options: Dict[str, Any]
) -> Tuple[Dict, List, List]:
    findings = []
    parsed = {}

    out = outputs.get("show etherchannel summary", outputs.get("show port-channel summary", ""))
    for line in out.splitlines():
        if "(D)" in line or "(S)" in line:
            ParserHelpers.add_finding(
                findings, "Member State", "FAIL", f"Suspended or Down member found: {line.strip()}"
            )
        if "(I)" in line:
            ParserHelpers.add_finding(
                findings, "Member State", "FAIL", f"Individual (not bundled) member found: {line.strip()}"
            )

    return parsed, findings, []


PORT_CHANNEL_DEF = ScannerDefinition(
    name="Port-Channel / LACP Scanner",
    internal_key="port_channel_scanner",
    description="Detects broken LAGs, suspended/individual members, and down port-channels.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": [
            "show etherchannel summary",
            "show lacp neighbor",
            "show interfaces trunk",
        ],
        "CATALYST_IOS_XE_SWITCH": [
            "show etherchannel summary",
            "show lacp neighbor",
            "show interfaces trunk",
        ],
        "IOS_XE_ROUTER": ["show etherchannel summary", "show lacp neighbor"],
        "LEGACY_IOS_ROUTER": ["show etherchannel summary", "show lacp neighbor"],
        "NEXUS": ["show port-channel summary", "show lacp neighbor"],
        "ASA_FIREWALL": ["show interface"],
    },
    parser_callback=parse_port_channel,
)


# ================== ROUTING NEIGHBOR SCANNER ==================
def parse_routing_neighbors(
    platform: str, outputs: Dict[str, str], options: Dict[str, Any]
) -> Tuple[Dict, List, List]:
    findings = []
    warnings = []
    parsed = {}

    bgp_out = outputs.get(
        "show ip bgp summary",
        outputs.get("show bgp summary", outputs.get("show bgp ipv4 unicast summary", "")),
    )
    for line in bgp_out.splitlines():
        if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
            parts = line.split()
            if len(parts) >= 9 and re.match(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", parts[0]):
                nbr = parts[0]
                state = parts[-1]
                if not state.isdigit():
                    ParserHelpers.add_finding(
                        findings, "BGP", "FAIL", f"BGP Peer {nbr} is not Established (State: {state})"
                    )
                elif state == "0" and options.get("bgp_zero_warn", True):
                    ParserHelpers.add_finding(
                        findings, "BGP", "WARN", f"BGP Peer {nbr} is Established but receiving 0 prefixes"
                    )

    ospf_out = outputs.get(
        "show ip ospf neighbor",
        outputs.get("show ospf neighbor", outputs.get("show ip ospf neighbors", "")),
    )
    for line in ospf_out.splitlines():
        if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
            if "FULL" not in line and "2WAY/DROTHER" not in line:
                ParserHelpers.add_finding(
                    findings, "OSPF", "WARN", f"OSPF neighbor state abnormal: {line.strip()}"
                )

    eigrp_out = outputs.get("show ip eigrp neighbors", outputs.get("show eigrp neighbors", ""))
    for line in eigrp_out.splitlines():
        if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line) and "uptime" not in line.lower():
            parsed.setdefault("eigrp", []).append(line.strip())

    if options.get("eigrp", True) and "eigrp" in outputs:
        if not parsed.get("eigrp") and (
            "IP-EIGRP neighbors" in eigrp_out or "EIGRP-IPv4 Neighbors" in eigrp_out
        ):
            ParserHelpers.add_finding(
                findings, "EIGRP", "FAIL", "EIGRP is running but neighbor table is EMPTY"
            )

    return parsed, findings, warnings


ROUTING_NEIGHBOR_DEF = ScannerDefinition(
    name="Routing Neighbor Scanner",
    internal_key="routing_neighbor_scanner",
    description="Check EIGRP, OSPF, BGP, HSRP, and VRRP state across devices.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": [
            "show ip eigrp neighbors",
            "show ip ospf neighbor",
            "show ip bgp summary",
            "show standby brief",
            "show ip route 0.0.0.0",
        ],
        "CATALYST_IOS_XE_SWITCH": [
            "show ip eigrp neighbors",
            "show ip ospf neighbor",
            "show ip bgp summary",
            "show standby brief",
            "show ip route 0.0.0.0",
        ],
        "IOS_XE_ROUTER": [
            "show ip eigrp neighbors",
            "show ip ospf neighbor",
            "show ip bgp summary",
            "show standby brief",
            "show ip route 0.0.0.0",
        ],
        "LEGACY_IOS_ROUTER": [
            "show ip eigrp neighbors",
            "show ip ospf neighbor",
            "show ip bgp summary",
            "show standby brief",
            "show ip route 0.0.0.0",
        ],
        "NEXUS": [
            "show eigrp neighbors",
            "show ip ospf neighbors",
            "show bgp ipv4 unicast summary",
            "show hsrp brief",
            "show ip route 0.0.0.0/0",
        ],
        "ASA_FIREWALL": [
            "show eigrp neighbors",
            "show ospf neighbor",
            "show bgp summary",
            "show route 0.0.0.0",
        ],
    },
    parser_callback=parse_routing_neighbors,
)


# ================== LOG SCANNER ==================
def parse_logs(
    platform: str, outputs: Dict[str, str], options: Dict[str, Any]
) -> Tuple[Dict, List, List]:
    findings = []

    log_out = ""
    for k, v in outputs.items():
        if "logging" in k:
            log_out = v

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
        "CATALYST_IOS_SWITCH": [
            "show logging | include LINK|LINEPROTO|SPANTREE|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP|EC|PAGP|POWER|FAN|TEMP|CPU|MEMORY|CRASH|RELOAD|SYS"
        ],
        "CATALYST_IOS_XE_SWITCH": [
            "show logging | include LINK|LINEPROTO|SPANTREE|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP|EC|PAGP|POWER|FAN|TEMP|CPU|MEMORY|CRASH|RELOAD|SYS"
        ],
        "IOS_XE_ROUTER": [
            "show logging | include LINK|LINEPROTO|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP|POWER|FAN|TEMP|CPU|MEMORY|CRASH|RELOAD|SYS"
        ],
        "LEGACY_IOS_ROUTER": [
            "show logging | include LINK|LINEPROTO|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP|POWER|FAN|TEMP|CPU|MEMORY|CRASH|RELOAD|SYS"
        ],
        "NEXUS": ["show logging last 300"],
        "ASA_FIREWALL": [
            "show logging | include error|fail|down|up|IKE|IPSEC|OSPF|EIGRP|BGP|failover|CRYPTO|teardown|built"
        ],
    },
    parser_callback=parse_logs,
)


# ================== DEVICE INVENTORY SCANNER ==================
def parse_inventory(
    platform: str, outputs: Dict[str, str], options: Dict[str, Any]
) -> Tuple[Dict, List, List]:
    findings = []
    parsed = {"hostname": "Unknown", "model": "Unknown", "serial": "Unknown", "version": "Unknown"}

    ver_out = outputs.get("show version", "")
    for line in ver_out.splitlines():
        if "uptime is" in line.lower():
            parsed["hostname"] = line.split()[0]
        if "processor board id" in line.lower():
            parsed["serial"] = line.split("ID")[-1].strip()
        if "cisco ios software" in line.lower() and "version" in line.lower():
            m = re.search(r"Version (\S+)", line)
            if m:
                parsed["version"] = m.group(1)

    if parsed["serial"] == "Unknown":
        inv_out = outputs.get("show inventory", "")
        for line in inv_out.splitlines():
            if "SN:" in line:
                m = re.search(r"SN:\s*(\S+)", line)
                if m:
                    parsed["serial"] = m.group(1)
                    break

    if parsed["serial"] == "Unknown":
        ParserHelpers.add_finding(findings, "Inventory", "WARN", "Unable to determine serial number")

    ParserHelpers.add_finding(
        findings,
        "Inventory",
        "INFO",
        f"Host: {parsed['hostname']} - Model: {parsed['model']} - SN: {parsed['serial']} - SW: {parsed['version']}",
    )

    return parsed, findings, []


DEVICE_INVENTORY_DEF = ScannerDefinition(
    name="Device Inventory Scanner",
    internal_key="device_inventory_scanner",
    description="Collect hardware/software inventory for documentation and audits.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": ["show version", "show inventory", "show environment all"],
        "CATALYST_IOS_XE_SWITCH": [
            "show version",
            "show inventory",
            "show environment all",
            "show license summary",
        ],
        "IOS_XE_ROUTER": [
            "show version",
            "show inventory",
            "show environment all",
            "show license summary",
        ],
        "LEGACY_IOS_ROUTER": ["show version", "show inventory", "show environment all"],
        "NEXUS": ["show version", "show inventory", "show license usage", "show environment"],
        "ASA_FIREWALL": ["show version", "show inventory", "show activation-key", "show environment"],
    },
    parser_callback=parse_inventory,
)


# ================== OPTICS SCANNER ==================
def parse_optics(
    platform: str, outputs: Dict[str, str], options: Dict[str, Any]
) -> Tuple[Dict, List, List]:
    findings = []

    dom_out = outputs.get(
        "show interfaces transceiver detail", outputs.get("show interface transceiver details", "")
    )
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
        "ASA_FIREWALL": ["show inventory"],
    },
    parser_callback=parse_optics,
)


# ================== BGP ROUTES SCANNER ==================
def parse_bgp_routes(
    platform: str, outputs: Dict[str, str], options: Dict[str, Any]
) -> Tuple[Dict, List, List]:
    findings = []
    warnings = []
    parsed = {}
    return parsed, findings, warnings


BGP_ROUTES_DEF = ScannerDefinition(
    name="BGP/Route Summary Scanner",
    internal_key="routes_advertised_received_scanner",
    description="Collect and report route and BGP summary information.",
    commands_by_command_set={
        "CATALYST_IOS_SWITCH": ["show ip bgp summary"],
        "CATALYST_IOS_XE_SWITCH": ["show ip bgp summary"],
        "IOS_XE_ROUTER": ["show ip bgp summary"],
        "LEGACY_IOS_ROUTER": ["show ip bgp summary"],
        "NEXUS": ["show bgp ipv4 unicast summary"],
        "ASA_FIREWALL": ["show bgp summary"],
    },
    parser_callback=parse_bgp_routes,
)

ALL_SCANNERS = [
    INTERFACE_ERROR_DEF,
    PORT_CHANNEL_DEF,
    ROUTING_NEIGHBOR_DEF,
    LOG_SCANNER_DEF,
    DEVICE_INVENTORY_DEF,
    OPTICS_SCANNER_DEF,
    BGP_ROUTES_DEF,
]
