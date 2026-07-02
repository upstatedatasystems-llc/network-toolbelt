"""PySide6 stub pages for deferred tools."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget


class StubPage(QWidget):
    def __init__(self, parent=None, controller=None, tool_name: str = "Tool"):
        super().__init__(parent)
        self.controller = controller
        self.tool_name = tool_name

        layout = QVBoxLayout(self)

        nav_layout = QHBoxLayout()
        back_btn = QPushButton("← Back to Dashboard")
        back_btn.clicked.connect(self.go_back)
        nav_layout.addWidget(back_btn)
        nav_layout.addStretch()
        layout.addLayout(nav_layout)

        title = QLabel(f"Tool: {self.tool_name}")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin-top: 20px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        info_card = QLabel(
            f"ℹ The '{self.tool_name}' component is deferred to a subsequent migration pass.\n\n"
            "Milestone 1 focuses on launching the PySide6 framework, SSH Credential Library, "
            "Target Mapping, and Generic Command Runner.\n\n"
            "You can switch back to the working Tkinter app (python network-toolbelt.pyw) "
            "if you need to run this specific tool right away!"
        )
        info_card.setStyleSheet(
            "background-color: #3c3f41; padding: 20px; border-radius: 6px; font-size: 13px;"
        )
        info_card.setWordWrap(True)
        info_card.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_card)

        layout.addStretch()

    def go_back(self):
        if self.controller:
            self.controller.show_frame("LandingPage")


class MaintenanceRunnerStubPage(StubPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, "Maintenance Pre/Post Runner")


class ScannerLandingStubPage(StubPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, "Network Scanners Suite")


class SnmpCredentialManagerStubPage(StubPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, "SNMP Credential Manager")


class SnmpOidScannerStubPage(StubPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, "SNMP OID Scanner")


class DocumentationStubPage(StubPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, "Documentation Browser")
