"""PySide6 custom status panels and control groupboxes."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class CredentialStatusPanel(QGroupBox):
    def __init__(self, parent=None, controller=None):
        super().__init__("Credentials (Temp)", parent)
        self.controller = controller

        layout = QVBoxLayout(self)
        self.status_lbl = QLabel("Credentials loaded: 0")
        layout.addWidget(self.status_lbl)

        btn = QPushButton("Manage Credentials && Library")
        btn.clicked.connect(self.open_manager)
        layout.addWidget(btn)

    def open_manager(self):
        if self.controller:
            self.controller.show_frame("CredentialManagerLibraryPage")

    def refresh(self):
        if self.controller and hasattr(self.controller, "credential_store"):
            count = len(self.controller.credential_store.records)
            self.status_lbl.setText(f"Credentials loaded: {count}")


class SnmpCredentialStatusPanel(QGroupBox):
    def __init__(self, parent=None, controller=None):
        super().__init__("SNMP Credentials (Volatile)", parent)
        self.controller = controller

        layout = QVBoxLayout(self)
        self.status_lbl = QLabel("SNMP Credentials: 0 configured, 0 enabled")
        layout.addWidget(self.status_lbl)

        btn = QPushButton("Manage SNMP Credentials")
        btn.clicked.connect(self.open_manager)
        layout.addWidget(btn)
        self.refresh()

    def open_manager(self):
        if self.controller:
            self.controller.show_frame("SnmpCredentialManagerPage")

    def refresh(self):
        if self.controller and hasattr(self.controller, "snmp_credential_store"):
            store = self.controller.snmp_credential_store
            if store:
                configured = (
                    store.count() if hasattr(store, "count") else len(store.records)
                )
                enabled = (
                    store.enabled_count()
                    if hasattr(store, "enabled_count")
                    else len(store.records)
                )
                self.status_lbl.setText(
                    f"SNMP Credentials: {configured} configured, {enabled} enabled"
                )
                return
        self.status_lbl.setText("SNMP Credentials: Store unavailable")


class TargetPanel(QGroupBox):
    def __init__(self, parent=None, controller=None):
        super().__init__("Target IPs", parent)
        self.controller = controller

        layout = QVBoxLayout(self)

        self.platform_cb = QComboBox()
        self.platform_cb.addItems(
            [
                "Auto Detect Platform",
                "Cisco IOS / IOS-XE",
                "Cisco NX-OS",
                "Cisco ASA",
            ]
        )
        layout.addWidget(self.platform_cb)

        self.targets_text = QTextEdit()
        self.targets_text.setPlaceholderText("Enter Target IPs or Hostnames (one per line)")
        layout.addWidget(self.targets_text)

        self.stats_lbl = QLabel("Session targets: 0, Mapped: 0")
        layout.addWidget(self.stats_lbl)

        btn_layout = QHBoxLayout()
        load_btn = QPushButton("Load Session Targets")
        load_btn.clicked.connect(self.load_session_targets)
        save_btn = QPushButton("Save Targets to Session")
        save_btn.clicked.connect(self.save_targets_to_session)

        btn_layout.addWidget(load_btn)
        btn_layout.addWidget(save_btn)
        layout.addLayout(btn_layout)

    def refresh_session_counts(self):
        if self.controller and hasattr(self.controller, "target_credential_store"):
            t_count = len(self.controller.target_credential_store.targets)
            m_count = (
                self.controller.target_credential_store.mapped_count_for_current_targets()
            )
            self.stats_lbl.setText(
                f"Session targets: {t_count}, Mapped: {m_count}/{t_count}"
            )

    def load_session_targets(self):
        if not self.controller or not hasattr(
            self.controller, "target_credential_store"
        ):
            return
        targets = self.controller.target_credential_store.targets
        if not targets:
            QMessageBox.information(
                self, "Info", "No targets in session mapping store."
            )
            return

        current = self.targets_text.toPlainText().strip()
        if current:
            reply = QMessageBox.question(
                self,
                "Overwrite",
                "Target box is not empty. Overwrite with session targets?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return

        self.targets_text.setPlainText("\n".join(targets))
        self.refresh_session_counts()

    def save_targets_to_session(self):
        if not self.controller or not hasattr(
            self.controller, "target_credential_store"
        ):
            return
        targets = self.get_targets()

        seen = set()
        cleaned = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                cleaned.append(t)

        self.controller.target_credential_store.set_targets(cleaned)
        self.refresh_session_counts()

        if hasattr(self.controller, "frames") and "LandingPage" in self.controller.frames:
            self.controller.frames["LandingPage"].refresh_credential_status()

        QMessageBox.information(
            self, "Saved", "Targets saved to session mapping store."
        )

    def get_targets(self) -> list:
        raw = self.targets_text.toPlainText()
        return [t.strip() for t in raw.splitlines() if t.strip()]

    def get_platform(self) -> str:
        return self.platform_cb.currentText()


class ConcurrentHostsControl(QGroupBox):
    DEFAULT_CONCURRENCY = 3
    MAX_CONCURRENCY = 20

    def __init__(self, parent=None, default=None):
        super().__init__("Concurrent Hosts", parent)
        if default is None:
            default = self.DEFAULT_CONCURRENCY

        layout = QVBoxLayout(self)
        row = QHBoxLayout()

        lbl = QLabel("Max parallel hosts:")
        self.spinbox = QSpinBox()
        self.spinbox.setRange(1, self.MAX_CONCURRENCY)
        self.spinbox.setValue(default)

        row.addWidget(lbl)
        row.addWidget(self.spinbox)
        layout.addLayout(row)

        sub = QLabel("Set to 1 for sequential execution.")
        sub.setStyleSheet("font-style: italic; font-size: 8pt;")
        layout.addWidget(sub)

    def get_value(self) -> int:
        return self.spinbox.value()
