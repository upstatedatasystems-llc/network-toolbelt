"""PySide6 Landing Page (Dashboard)."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGroupBox, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget


class LandingPage(QWidget):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent)
        self.controller = controller

        layout = QVBoxLayout(self)

        title = QLabel("Network Toolbelt Dashboard")
        title.setStyleSheet("font-size: 22px; font-weight: bold; margin-top: 15px; margin-bottom: 20px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        cards_layout = QHBoxLayout()

        # Tools Column
        tools_box = QGroupBox("Tools")
        tools_layout = QVBoxLayout(tools_box)

        cmd_btn = QPushButton("Generic Command Runner")
        cmd_btn.setMinimumHeight(50)
        cmd_btn.setStyleSheet("font-size: 14px; font-weight: bold;")
        cmd_btn.clicked.connect(lambda: self.controller.show_frame("CommandRunnerPage"))
        tools_layout.addWidget(cmd_btn)

        maint_btn = QPushButton("Maintenance Pre/Post Runner")
        maint_btn.setMinimumHeight(50)
        maint_btn.setStyleSheet("font-size: 14px; font-weight: bold;")
        maint_btn.clicked.connect(lambda: self.controller.show_frame("MaintenanceRunnerPage"))
        tools_layout.addWidget(maint_btn)

        scan_btn = QPushButton("Network Scanners")
        scan_btn.setMinimumHeight(50)
        scan_btn.setStyleSheet("font-size: 14px; font-weight: bold;")
        scan_btn.clicked.connect(lambda: self.controller.show_frame("ScannerLandingPage"))
        tools_layout.addWidget(scan_btn)

        tools_layout.addStretch()
        cards_layout.addWidget(tools_box)

        # Session && Help Column
        session_box = QGroupBox("Session && Help")
        session_layout = QVBoxLayout(session_box)

        self.cred_status_lbl = QLabel("Credentials loaded: 0")
        self.cred_status_lbl.setAlignment(Qt.AlignCenter)
        self.cred_status_lbl.setStyleSheet("font-size: 13px; margin-top: 10px; margin-bottom: 10px;")
        session_layout.addWidget(self.cred_status_lbl)

        cred_btn = QPushButton("Credential Manager && Library")
        cred_btn.setMinimumHeight(45)
        cred_btn.setStyleSheet("font-size: 14px; font-weight: bold;")
        cred_btn.clicked.connect(lambda: self.controller.show_frame("CredentialManagerLibraryPage"))
        session_layout.addWidget(cred_btn)

        help_btn = QPushButton("Help && Documentation")
        help_btn.setMinimumHeight(45)
        help_btn.setStyleSheet("font-size: 14px; font-weight: bold;")
        help_btn.clicked.connect(lambda: self.controller.open_documentation())
        session_layout.addWidget(help_btn)

        session_layout.addStretch()
        cards_layout.addWidget(session_box)

        layout.addLayout(cards_layout)
        layout.addStretch()

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_credential_status()

    def refresh_credential_status(self):
        if not self.controller:
            return
        count = len(self.controller.credential_store.records)
        if hasattr(self.controller, "target_credential_store"):
            t_count = len(self.controller.target_credential_store.targets)
            m_count = self.controller.target_credential_store.mapped_count_for_current_targets()
            self.cred_status_lbl.setText(
                f"Credentials loaded: {count}   Session targets: {t_count}   Mapped targets: {m_count}/{t_count}"
            )
        else:
            self.cred_status_lbl.setText(f"Credentials loaded: {count}")
