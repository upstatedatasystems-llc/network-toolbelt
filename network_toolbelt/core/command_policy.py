"""Command policy enforcement and command overrides manager."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List

from network_toolbelt.core.settings import CommandPolicyMode, settings


@dataclass
class CommandDecision:
    allowed: bool
    reason: str
    severity: str


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

    def _backup_bad_file(self, reason: str):
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
            "tools": self.overrides,
        }
        try:
            with open(self.override_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception:
            pass

    def get_effective_commands(
        self, tool_key: str, group_key: str, default_cmds: list
    ) -> list:
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
        allowed_prefixes = (
            "show ",
            "terminal length",
            "terminal width",
            "terminal pager",
            "dir",
            "pwd",
        )
        dangerous_prefixes = (
            "configure",
            "conf",
            "reload",
            "write",
            "copy",
            "delete",
            "erase",
            "clear",
            "debug",
            "undebug",
            "request",
            "install",
            "test",
            "ping",
            "traceroute",
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
    SAFE_PREFIXES = (
        "show ",
        "terminal length ",
        "terminal width ",
        "terminal pager ",
        "dir ",
        "pwd ",
    )
    EXPANDED_PREFIXES = ("ping ", "traceroute ")
    DANGEROUS_PREFIXES = (
        "configure",
        "conf",
        "reload",
        "write",
        "copy",
        "delete",
        "erase",
        "format",
        "clear",
        "debug",
        "undebug",
        "no debug",
        "archive",
        "request",
        "install",
        "license",
        "crypto key",
        "test",
        "hw-module",
        "mkdir",
        "rmdir",
        "squeeze",
        "more system:running-config",
        "send",
        "clock set",
        "terminal monitor",
        "terminal no monitor",
        "monitor capture",
        "packet-tracer",
        "capture",
        "failover active",
        "failover reload-standby",
        "redundancy force-switchover",
        "issu",
        "guestshell",
        "app-hosting",
        "virtual-service",
        "service internal",
    )

    @classmethod
    def evaluate(cls, command: str, mode: CommandPolicyMode) -> CommandDecision:
        cmd_lower = command.strip().lower()
        if mode == CommandPolicyMode.UNSAFE_ALLOWED:
            return CommandDecision(True, "Unsafe mode allows all commands.", "unsafe")
        for dp in cls.DANGEROUS_PREFIXES:
            if cmd_lower.startswith(dp):
                return CommandDecision(
                    False, f"Command matches dangerous prefix '{dp}'.", "blocked"
                )
        for ep in cls.EXPANDED_PREFIXES:
            if cmd_lower.startswith(ep):
                if mode == CommandPolicyMode.EXPANDED_OPERATIONAL:
                    return CommandDecision(
                        True, "Matched expanded operational allowlist.", "expanded"
                    )
                return CommandDecision(
                    False, "Command requires Expanded Operational mode.", "blocked"
                )
        for sp in cls.SAFE_PREFIXES:
            if cmd_lower.startswith(sp):
                return CommandDecision(True, "Matched safe read-only allowlist.", "safe")
        return CommandDecision(
            False, "Command is not in the allowlist. Default deny.", "blocked"
        )

    @classmethod
    def evaluate_many(
        cls, commands: List[str], mode: CommandPolicyMode
    ) -> List[CommandDecision]:
        return [cls.evaluate(cmd, mode) for cmd in commands]

    @classmethod
    def validate_scanner_commands(cls, commands: List[str]) -> List[str]:
        unsafe = []
        for cmd in commands:
            c = cmd.strip().lower()
            if any(c.startswith(dp) for dp in cls.DANGEROUS_PREFIXES) or any(
                c.startswith(ep) for ep in cls.EXPANDED_PREFIXES
            ):
                unsafe.append(cmd)
        return unsafe
