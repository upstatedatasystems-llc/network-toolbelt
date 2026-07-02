"""Text scrubbing, secret redaction, and temp session log management."""

import re
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


class LineBufferedRedactor:
    def __init__(self, redact_fn: Callable[[str], str]):
        self.redact_fn = redact_fn
        self.pending = ""

    def feed(self, text: str) -> str:
        if not text:
            return ""
        combined = self.pending + text
        lines = combined.splitlines(True)
        if not lines:
            return ""
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
    def ensure_secure_temp_session_dir(base_output_dir: Path, run_id: str) -> Path:
        temp_dir = base_output_dir / ".temp_sessions" / run_id
        temp_dir.mkdir(parents=True, exist_ok=True)
        try:
            temp_dir.chmod(0o700)
        except Exception:
            pass
        return temp_dir

    @staticmethod
    def create_secure_session_log_path(temp_dir: Path, safe_host: str) -> Path:
        p = temp_dir / f"{safe_host}_{uuid.uuid4().hex[:8]}.log"
        p.touch()
        try:
            p.chmod(0o600)
        except Exception:
            pass
        return p

    @staticmethod
    def cleanup_secure_session_log(path: Path):
        try:
            if path and path.exists():
                path.unlink(missing_ok=True)
        except Exception:
            pass

    @staticmethod
    def cleanup_stale_temp_session_dirs(base_output_dir: Path):
        temp_base = base_output_dir / ".temp_sessions"
        if not temp_base.exists():
            return
        for d in temp_base.iterdir():
            if d.is_dir():
                try:
                    shutil.rmtree(d)
                except Exception:
                    pass


@dataclass
class RedactionRule:
    name: str
    pattern: re.Pattern
    replacement: Any


class Redactor:
    def __init__(self):
        self.rules = [
            RedactionRule(
                "username_secret",
                re.compile(
                    r"(?im)^(\s*username\s+\S+(?:\s+privilege\s+\d+)?\s+(?:secret|password)\s+(?:\d\s+)?)(.*)$"
                ),
                r"\1<REDACTED>",
            ),
            RedactionRule(
                "enable_secret",
                re.compile(
                    r"(?im)^(\s*enable\s+(?:secret|password)\s+(?:\d\s+)?)(.*)$"
                ),
                r"\1<REDACTED>",
            ),
            RedactionRule(
                "line_password",
                re.compile(r"(?im)^(\s*password\s+(?:\d\s+)?)(.*)$"),
                r"\1<REDACTED>",
            ),
            RedactionRule(
                "snmp_community",
                re.compile(
                    r"(?im)^(\s*snmp-server\s+community\s+)(\S+)(.*)$"
                ),
                r"\1<REDACTED>\3",
            ),
            RedactionRule(
                "snmp_host",
                re.compile(
                    r"(?im)^(\s*snmp-server\s+host\s+\S+(?:\s+vrf\s+\S+)?\s+(?:version\s+\S+\s+)?)(?!version)(\S+)(.*)$"
                ),
                r"\1<REDACTED>\3",
            ),
            RedactionRule(
                "snmp_user",
                re.compile(
                    r"(?im)^(\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\s+auth\s+\S+\s+)(\S+)(.*)$"
                ),
                r"\1<REDACTED>\3",
            ),
            RedactionRule(
                "aaa_server_key",
                re.compile(
                    r"(?im)^(\s*(?:tacacs|radius)-server\s+(?:host\s+\S+\s+)?key\s+(?:\d\s+)?)(.*)$"
                ),
                r"\1<REDACTED>",
            ),
            RedactionRule(
                "crypto_isakmp_key",
                re.compile(
                    r"(?im)^(\s*crypto\s+isakmp\s+key\s+(?:\d\s+)?)(?!address)(\S+)(.*)$"
                ),
                r"\1<REDACTED>\3",
            ),
            RedactionRule(
                "crypto_ikev2_key",
                re.compile(
                    r"(?im)^(\s*(?:local|remote)-authentication\s+pre-shared-key\s+(?:\d\s+)?)(.*)$"
                ),
                r"\1<REDACTED>",
            ),
            RedactionRule(
                "tunnel_group_ike",
                re.compile(
                    r"(?im)^(\s*ikev[12]\s+(?:remote-authentication\s+)?pre-shared-key\s+(?:\d\s+)?)(.*)$"
                ),
                r"\1<REDACTED>",
            ),
            RedactionRule(
                "ospf_auth",
                re.compile(
                    r"(?im)^(\s*ip\s+ospf\s+(?:message-digest-key\s+\d+\s+md5|authentication-key)\s+(?:\d\s+)?)(.*)$"
                ),
                r"\1<REDACTED>",
            ),
            RedactionRule(
                "key_string",
                re.compile(r"(?im)^(\s*key-string\s+(?:\d\s+)?)(.*)$"),
                r"\1<REDACTED>",
            ),
            RedactionRule(
                "ntp_auth",
                re.compile(
                    r"(?im)^(\s*ntp\s+authentication-key\s+\d+\s+md5\s+)(.*)$"
                ),
                r"\1<REDACTED>",
            ),
            RedactionRule(
                "certificate_block",
                re.compile(
                    r"(?s)(\s*certificate\s+self-signed\s*\n\s*[0-9A-Fa-f\s]+\n\s*quit)"
                ),
                r"\n  certificate self-signed\n    <REDACTED>\n  quit",
            ),
            RedactionRule(
                "pem_private_key",
                re.compile(
                    r"(?s)-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----"
                ),
                r"-----BEGIN PRIVATE KEY-----\n<REDACTED>\n-----END PRIVATE KEY-----",
            ),
            RedactionRule(
                "pem_certificate",
                re.compile(
                    r"(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
                ),
                r"-----BEGIN CERTIFICATE-----\n<REDACTED>\n-----END CERTIFICATE-----",
            ),
            RedactionRule(
                "wireless_psk",
                re.compile(r"(?im)^(\s*wpa-psk\s+(?:ascii\s+)?(?:\d\s+)?)(.*)$"),
                r"\1<REDACTED>",
            ),
            RedactionRule(
                "generic_catchall",
                re.compile(
                    r"(?im)^.*(?:password|secret|community|key-string|pre-shared-key|server-key).*$"
                ),
                lambda m: re.sub(
                    r"(\s+(?:password|secret|community|key-string|pre-shared-key|server-key|key)\s+(?:\d\s+)?)(?![\s\n])(\S+)",
                    r"\1<REDACTED>",
                    m.group(0),
                ),
            ),
            RedactionRule(
                "tacacs_radius_nested",
                re.compile(
                    r"(?im)^(\s*(?:key(?:word)?)\s+(?:\d\s+)?)(?![\s\n])(\S+)(.*)$"
                ),
                r"\1<REDACTED>\3",
            ),
            RedactionRule(
                "snmpv3_auth_priv",
                re.compile(
                    r"(?im)^(\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\s+auth\s+(?:md5|sha|sha-224|sha-256|sha-384|sha-512)\s+)(\S+)(\s+priv\s+(?:aes\s+\d+|des|3des|aes)\s+)(\S+)(.*)$"
                ),
                r"\1<REDACTED>\3<REDACTED>\5",
            ),
            RedactionRule(
                "snmpv3_auth_only",
                re.compile(
                    r"(?im)^(\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\s+auth\s+(?:md5|sha|sha-224|sha-256|sha-384|sha-512)\s+)(\S+)(.*)$"
                ),
                r"\1<REDACTED>\3",
            ),
            RedactionRule(
                "password_colon",
                re.compile(
                    r"(?im)^((?:.*[pP]assword|.*[pP]asscode)\s*:\s*)(.*)$"
                ),
                lambda m: m.group(1) + "<REDACTED>"
                if m.group(2).strip()
                else m.group(0),
            ),
        ]

    def redact_text(self, text: str) -> str:
        if not text:
            return ""
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
