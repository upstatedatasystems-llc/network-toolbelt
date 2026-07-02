"""Maintenance snapshot collection, output parsers, and snapshot compare engine."""

import csv
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from network_toolbelt.core.settings import FilenameSafety, LogicalPlatform, settings


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


class ParserHelpers:
    @staticmethod
    def normalize_parser_platform(logical_platform) -> str:
        if logical_platform == LogicalPlatform.NXOS:
            return "NEXUS"
        if logical_platform in (LogicalPlatform.IOS_XE_SWITCH, LogicalPlatform.IOS_XE_ROUTER):
            return "IOSXE"
        if logical_platform == LogicalPlatform.ASA:
            return "ASA"
        return "IOS"

    @staticmethod
    def safe_int(value, default=0) -> int:
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def parse_first_int(text: str) -> int:
        m = re.search(r"\d+", text)
        return int(m.group(0)) if m else 0

    @staticmethod
    def normalize_interface_name(name: str) -> str:
        if not name:
            return ""
        name = name.strip()
        name = re.sub(r"^Gi(?:gabitEthernet)?", "Gi", name, flags=re.IGNORECASE)
        name = re.sub(r"^Te(?:nGigabitEthernet)?", "Te", name, flags=re.IGNORECASE)
        name = re.sub(r"^Fa(?:stEthernet)?", "Fa", name, flags=re.IGNORECASE)
        name = re.sub(r"^Po(?:rt-channel)?", "Po", name, flags=re.IGNORECASE)
        return name

    @staticmethod
    def extract_ipv4_addresses(text: str) -> List[str]:
        return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)

    @staticmethod
    def line_contains_any(line: str, keywords: List[str]) -> bool:
        line_lower = line.lower()
        return any(k.lower() in line_lower for k in keywords)

    @staticmethod
    def severity_rank(status: str) -> int:
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
                if "input errors" in line:
                    m = re.search(r"(\d+) input errors, (\d+) CRC", line)
                    if m:
                        current_iface.input_errors = int(m.group(1))
                        current_iface.crc = int(m.group(2))
                elif "output errors" in line:
                    m = re.search(r"(\d+) output errors", line)
                    if m:
                        current_iface.output_errors = int(m.group(1))
                elif "drops" in line.lower() and "input drop" in line.lower():
                    m = re.search(r"(\d+) drops", line.lower())
                    if m:
                        current_iface.drops += int(m.group(1))
            elif " is " in line and " line protocol is " in line:
                m = re.match(r"^(\S+) is (\S+).*line protocol is (\S+)", line)
                if m:
                    if current_iface:
                        interfaces.append(current_iface)
                    current_iface = InterfaceRecord(
                        name=m.group(1), status=m.group(2), protocol=m.group(3)
                    )
            elif "Description:" in line and current_iface:
                current_iface.description = line.split("Description:", 1)[1].strip()

        if current_iface:
            interfaces.append(current_iface)
        return interfaces

    @staticmethod
    def parse_logs(lines: List[str]) -> List[LogEvent]:
        logs = []
        for line in lines:
            m = re.search(r"%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+):\s*(.*)", line)
            if m:
                logs.append(
                    LogEvent(
                        timestamp="",
                        facility=m.group(1),
                        severity=int(m.group(2)),
                        mnemonic=m.group(3),
                        message=m.group(4).strip(),
                    )
                )
        return logs

    @staticmethod
    def parse_routes(
        bgp_lines: List[str], ospf_lines: List[str], eigrp_lines: List[str]
    ) -> List[RoutingNeighbor]:
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
        clean = [
            l
            for l in lines
            if not l.startswith("#")
            and not l.startswith("!")
            and "Current configuration" not in l
            and "Last configuration change" not in l
            and "NVRAM config last updated" not in l
        ]
        if not clean:
            return None
        return hashlib.sha256("\n".join(clean).encode("utf-8")).hexdigest()

    @staticmethod
    def arp_count(lines: List[str]) -> int:
        count = 0
        for line in lines:
            if re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", line):
                count += 1
        return count

    @staticmethod
    def mac_count(lines: List[str]) -> int:
        for line in lines:
            if "Total" in line and re.search(r"\d+", line):
                nums = re.findall(r"\d+", line)
                if nums:
                    return int(nums[-1])
        count = 0
        for line in lines:
            if re.search(r"(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}", line) or re.search(
                r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", line
            ):
                count += 1
        return count

    @staticmethod
    def eigrp_neighbors(lines: List[str]) -> List[str]:
        neighbors = []
        for line in lines:
            if line.strip() and re.search(r"\d+\.\d+\.\d+\.\d+", line):
                parts = line.split()
                if len(parts) > 1 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[1]):
                    neighbors.append(parts[1])
                elif re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    neighbors.append(parts[0])
        return neighbors

    @staticmethod
    def ospf_neighbors(lines: List[str]) -> List[str]:
        neighbors = []
        for line in lines:
            if line.strip() and re.search(r"\d+\.\d+\.\d+\.\d+", line):
                parts = line.split()
                if len(parts) > 0 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    neighbors.append(parts[0])
        return neighbors

    @staticmethod
    def bgp_summary(lines: List[str]) -> Dict[str, str]:
        neighbors = {}
        for line in lines:
            if line.strip() and re.search(r"\d+\.\d+\.\d+\.\d+", line):
                parts = line.split()
                if len(parts) >= 9 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
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
                m = re.search(r"Interface ([^,]+), changed state to (up|down)", log.message)
                if m:
                    iface = m.group(1)
                    flap_counts[iface] = flap_counts.get(iface, 0) + 1
            if log.severity <= 2:
                findings.append(
                    f"FAIL: CRITICAL LOG - {log.facility}-{log.severity}-{log.mnemonic}: {log.message}"
                )
            elif log.severity == 3:
                findings.append(
                    f"WARN: ERROR LOG - {log.facility}-{log.severity}-{log.mnemonic}: {log.message}"
                )

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
    def build(
        run_id: str,
        phase: str,
        host: str,
        platform: str,
        cmd_set: str,
        capture_mode: str,
        output_text: str,
        command_results: List[Dict] = None,
    ) -> dict:
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
            "config": {
                "hash_redacted": ParserEngine.cfg_hash(
                    ParserEngine.extract_section("show running-config", lines)
                )
            },
            "neighbors": {
                "arp_count": ParserEngine.arp_count(
                    ParserEngine.extract_section("show arp", lines)
                    + ParserEngine.extract_section("show ip arp summary", lines)
                    + ParserEngine.extract_section("show ip arp", lines)
                    + ParserEngine.extract_section("show ip arp vrf all", lines)
                ),
                "eigrp": ParserEngine.eigrp_neighbors(
                    ParserEngine.extract_section("show ip eigrp neighbors", lines)
                    + ParserEngine.extract_section("show eigrp neighbors", lines)
                ),
                "ospf": ParserEngine.ospf_neighbors(
                    ParserEngine.extract_section("show ip ospf neighbor", lines)
                    + ParserEngine.extract_section("show ospf neighbor", lines)
                ),
                "bgp": ParserEngine.bgp_summary(
                    ParserEngine.extract_section("show ip bgp summary", lines)
                    + ParserEngine.extract_section("show bgp summary", lines)
                    + ParserEngine.extract_section("show bgp ipv4 unicast summary", lines)
                ),
            },
            "layer2": {
                "mac_count": ParserEngine.mac_count(
                    ParserEngine.extract_section("show mac address-table count", lines)
                )
            },
            "deep_analysis": {
                "interfaces": [
                    vars(i)
                    for i in ParserEngine.parse_interfaces(
                        ParserEngine.extract_section("show interfaces", lines)
                    )
                ],
                "logs": [
                    vars(l)
                    for l in ParserEngine.parse_logs(
                        ParserEngine.extract_section(
                            "show logging | include LINK|LINEPROTO|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP|CRYPTO",
                            lines,
                        )
                        + ParserEngine.extract_section(
                            "show logging | include LINK|LINEPROTO|SPANTREE|ERR|CRC|error|flap|down|up|OSPF|EIGRP|BGP|LACP",
                            lines,
                        )
                    )
                ],
                "routing_neighbors": [
                    vars(r)
                    for r in ParserEngine.parse_routes(
                        ParserEngine.extract_section("show ip bgp summary", lines)
                        + ParserEngine.extract_section("show bgp summary", lines)
                        + ParserEngine.extract_section("show bgp ipv4 unicast summary", lines),
                        ParserEngine.extract_section("show ip ospf neighbor", lines)
                        + ParserEngine.extract_section("show ospf neighbor", lines),
                        ParserEngine.extract_section("show ip eigrp neighbors", lines)
                        + ParserEngine.extract_section("show eigrp neighbors", lines),
                    )
                ],
            },
        }
        return snap


class CompareEngine:
    @staticmethod
    def compare_snapshots(pre_snap: dict, post_snap: dict) -> List[CompareFinding]:
        findings = []

        if not post_snap:
            findings.append(CompareFinding("Reachability", "FAIL", "Missing POST output snapshot."))
            return findings

        cfg_pre = pre_snap.get("config", {}).get("hash_redacted")
        cfg_post = post_snap.get("config", {}).get("hash_redacted")
        if cfg_pre and cfg_post and cfg_pre != cfg_post:
            findings.append(CompareFinding("Config", "FAIL", "running-config changed", cfg_pre, cfg_post))

        arp_pre = pre_snap.get("neighbors", {}).get("arp_count", 0)
        arp_post = post_snap.get("neighbors", {}).get("arp_count", 0)
        if arp_pre > 0:
            diff = (arp_pre - arp_post) / arp_pre
            if diff > 0.50:
                findings.append(CompareFinding("ARP", "FAIL", "ARP drop > 50%", arp_pre, arp_post))
            elif diff > 0.15:
                findings.append(CompareFinding("ARP", "WARN", "ARP drop 15-50%", arp_pre, arp_post))

        mac_pre = pre_snap.get("layer2", {}).get("mac_count", 0) or 0
        mac_post = post_snap.get("layer2", {}).get("mac_count", 0) or 0
        if mac_pre > 0:
            diff = (mac_pre - mac_post) / mac_pre
            if diff > 0.50:
                findings.append(CompareFinding("MAC", "FAIL", "MAC drop > 50%", mac_pre, mac_post))
            elif diff > 0.15:
                findings.append(CompareFinding("MAC", "WARN", "MAC drop 15-50%", mac_pre, mac_post))

        e_pre = set(pre_snap.get("neighbors", {}).get("eigrp", []))
        e_post = set(post_snap.get("neighbors", {}).get("eigrp", []))
        if e_pre != e_post:
            findings.append(CompareFinding("EIGRP", "FAIL", "EIGRP neighbor set changed", len(e_pre), len(e_post)))

        o_pre = set(pre_snap.get("neighbors", {}).get("ospf", []))
        o_post = set(post_snap.get("neighbors", {}).get("ospf", []))
        if o_pre != o_post:
            findings.append(CompareFinding("OSPF", "FAIL", "OSPF neighbor set changed", len(o_pre), len(o_post)))

        b_pre = pre_snap.get("neighbors", {}).get("bgp", {})
        b_post = post_snap.get("neighbors", {}).get("bgp", {})
        if set(b_pre.keys()) != set(b_post.keys()):
            findings.append(CompareFinding("BGP", "FAIL", "BGP neighbor count changed", len(b_pre), len(b_post)))
        else:
            for nbr, state in b_pre.items():
                if state.isdigit() and not b_post.get(nbr, "").isdigit():
                    findings.append(CompareFinding("BGP", "FAIL", f"BGP peer {nbr} lost Established state", state, b_post.get(nbr)))

        if post_snap and "deep_analysis" in post_snap and "interfaces" in post_snap["deep_analysis"]:
            for iface in post_snap["deep_analysis"]["interfaces"]:
                if iface["input_errors"] > 0 or iface["output_errors"] > 0 or iface["crc"] > 0 or iface["drops"] > 0:
                    findings.append(CompareFinding("Interface", "WARN", f"{iface['name']} has errors/drops (In:{iface['input_errors']}, Out:{iface['output_errors']}, CRC:{iface['crc']}, Drops:{iface['drops']})"))

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
            if line.startswith("# Run ID:"):
                run_id = line.split(":", 1)[1].strip()
            elif line.startswith("# Phase:"):
                phase = line.split(":", 1)[1].strip()
            elif line.startswith("# Host:"):
                host = line.split(":", 1)[1].strip()
            elif line.startswith("# Platform:"):
                platform = line.split(":", 1)[1].strip()
            elif line.startswith("# Capture Mode:"):
                mode = line.split(":", 1)[1].strip()
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
            if pre_file.suffix == ".txt" and pre_file.with_suffix(".json").exists():
                continue

            ip = (
                pre_file.name.replace("-pre_RAW.json", "")
                .replace("-pre.json", "")
                .replace("-pre_RAW.txt", "")
                .replace("-pre.txt", "")
            )

            post_file_redacted_json = post_dir / f"{ip}-post.json"
            post_file_raw_json = post_dir / f"{ip}-post_RAW.json"
            post_file_redacted_txt = post_dir / f"{ip}-post.txt"
            post_file_raw_txt = post_dir / f"{ip}-post_RAW.txt"

            pre_snap = None
            if pre_file.suffix == ".json":
                with open(pre_file, "r") as f:
                    pre_snap = json.load(f)
            else:
                pre_snap = CompareEngine.build_snapshot_from_txt(pre_file)

            post_snap = None
            if post_file_raw_json.exists():
                with open(post_file_raw_json, "r") as f:
                    post_snap = json.load(f)
            elif post_file_redacted_json.exists():
                with open(post_file_redacted_json, "r") as f:
                    post_snap = json.load(f)
            elif post_file_raw_txt.exists():
                post_snap = CompareEngine.build_snapshot_from_txt(post_file_raw_txt)
            elif post_file_redacted_txt.exists():
                post_snap = CompareEngine.build_snapshot_from_txt(post_file_redacted_txt)

            findings = CompareEngine.compare_snapshots(pre_snap, post_snap)

            summary_json[ip] = [f.__dict__ for f in findings]
            host_status = (
                "FAIL"
                if any(f.status == "FAIL" for f in findings)
                else ("WARN" if any(f.status == "WARN" for f in findings) else "PASS")
            )

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
            with open(out_dir / "summary.json", "w") as f:
                json.dump(summary_json, f, indent=4)
        with open(out_dir / "summary.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(summary_csv)

        return sum_txt_data
