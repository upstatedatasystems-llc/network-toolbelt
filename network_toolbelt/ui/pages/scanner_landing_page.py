"""PySide6 Scanner Landing Page dashboard for Network Scanners Suite."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QGroupBox, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget


class ScannerLandingPage(QWidget):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent)
        self.controller = controller
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Nav Header
        nav_layout = QHBoxLayout()
        back_btn = QPushButton("← Back to Dashboard")
        back_btn.clicked.connect(lambda: self.controller.show_frame("LandingPage"))
        nav_layout.addWidget(back_btn)

        title = QLabel("Network Scanner Suite")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        nav_layout.addWidget(title)
        nav_layout.addStretch()

        layout.addLayout(nav_layout)

        # Main Grid Box
        grid_box = QGroupBox("Select a Network Scanner")
        grid_layout = QGridLayout(grid_box)

        scanners = [
            ("Interface Error Scanner", "InterfaceErrorScannerPage", "Checks interface states, CRCs, errors, and drops."),
            ("Port-Channel / LACP Scanner", "PortChannelScannerPage", "Detects broken LAGs and suspended/individual members."),
            ("Optics Scanner", "OpticsScannerPage", "Finds low RX power, high TX power, and DOM alarms."),
            ("Routing Neighbor Scanner", "RoutingNeighborScannerPage", "Checks EIGRP, OSPF, BGP, HSRP, and VRRP neighbor states."),
            ("Log Scanner", "LogScannerPage", "Classifies critical log events, link flaps, and error events."),
            ("Device Inventory Scanner", "DeviceInventoryScannerPage", "Audits hardware, software, serials, and models."),
            ("BGP/Route Summary Scanner", "BgpRoutesScannerPage", "Collects BGP route information and summary outputs."),
        ]

        row, col = 0, 0
        for name, page_key, desc in scanners:
            btn = QPushButton(name)
            btn.setMinimumHeight(60)
            btn.setStyleSheet("font-size: 13px; font-weight: bold; text-align: left; padding: 10px;")
            btn.clicked.connect(lambda checked=False, k=page_key: self.controller.show_frame(k))

            grid_layout.addWidget(btn, row, col)
            col += 1
            if col > 1:
                col = 0
                row += 1

        layout.addWidget(grid_box)
        layout.addStretch()
