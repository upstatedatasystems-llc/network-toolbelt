"""In-memory credential models and target mapping stores."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


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

    def add(self, label: str, username: str, password: str, secret: str = ""):
        rid = str(uuid.uuid4())
        self.records.append(
            CredentialRecord(
                rid,
                label,
                username,
                password,
                secret,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        )

    def update(
        self, record_id: str, label: str, username: str, password: str, secret: str
    ):
        for r in self.records:
            if r.id == record_id:
                r.label = label
                r.username = username
                if password:
                    r.password = password
                if secret:
                    r.secret = secret
                break

    def delete(self, record_id: str):
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

    def list_safe(self) -> List[str]:
        safe_list = []
        for i, r in enumerate(self.records, 1):
            en_status = "yes" if r.secret else "no"
            safe_list.append(
                f"Credential Set {i} — label: {r.label} — user: {r.username} — enable: {en_status}"
            )
        return safe_list

    def as_netmiko_dicts(self) -> List[Dict[str, str]]:
        return [
            {"username": r.username, "password": r.password, "secret": r.secret}
            for r in self.records
        ]


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
