"""Concrete PySide6 Scanner pages."""

from PySide6.QtWidgets import QCheckBox, QLabel, QTextEdit, QVBoxLayout
from network_toolbelt.core.scanners import (
    BGP_ROUTES_DEF,
    DEVICE_INVENTORY_DEF,
    INTERFACE_ERROR_DEF,
    LOG_SCANNER_DEF,
    OPTICS_SCANNER_DEF,
    PORT_CHANNEL_DEF,
    ROUTING_NEIGHBOR_DEF,
)
from network_toolbelt.ui.pages.base_scanner_page import BaseScannerPage


class InterfaceErrorScannerPage(BaseScannerPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, INTERFACE_ERROR_DEF)

    def build_options(self):
        self.uplink_cb = QCheckBox("Uplink-Sensitive Mode")
        self.uplink_cb.setChecked(True)
        self.options_layout.addWidget(self.uplink_cb)

    def get_options(self) -> dict:
        return {"uplink_sensitive": self.uplink_cb.isChecked(), "crc_warn": 1}


class PortChannelScannerPage(BaseScannerPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, PORT_CHANNEL_DEF)


class RoutingNeighborScannerPage(BaseScannerPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, ROUTING_NEIGHBOR_DEF)

    def build_options(self):
        self.eigrp_cb = QCheckBox("Check EIGRP")
        self.eigrp_cb.setChecked(True)
        self.ospf_cb = QCheckBox("Check OSPF")
        self.ospf_cb.setChecked(True)
        self.bgp_cb = QCheckBox("Check BGP")
        self.bgp_cb.setChecked(True)
        self.bgp_zero_cb = QCheckBox("Treat BGP 0 prefixes as WARN")
        self.bgp_zero_cb.setChecked(True)

        self.options_layout.addWidget(self.eigrp_cb)
        self.options_layout.addWidget(self.ospf_cb)
        self.options_layout.addWidget(self.bgp_cb)
        self.options_layout.addWidget(self.bgp_zero_cb)

    def get_options(self) -> dict:
        return {
            "eigrp": self.eigrp_cb.isChecked(),
            "ospf": self.ospf_cb.isChecked(),
            "bgp": self.bgp_cb.isChecked(),
            "bgp_zero_warn": self.bgp_zero_cb.isChecked(),
        }


class LogScannerPage(BaseScannerPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, LOG_SCANNER_DEF)


class DeviceInventoryScannerPage(BaseScannerPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, DEVICE_INVENTORY_DEF)


class OpticsScannerPage(BaseScannerPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, OPTICS_SCANNER_DEF)


class BgpRoutesScannerPage(BaseScannerPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, BGP_ROUTES_DEF)

    def build_options(self):
        self.options_layout.addWidget(QLabel("Target Neighbors (one per line):"))
        self.nbr_edit = QTextEdit()
        self.nbr_edit.setMaximumHeight(80)
        self.options_layout.addWidget(self.nbr_edit)

    def get_options(self) -> dict:
        nbrs = [n.strip() for n in self.nbr_edit.toPlainText().splitlines() if n.strip()]
        return {"neighbors": nbrs, "adv": True, "rec": True}
