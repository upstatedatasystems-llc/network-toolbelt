"""PySide6 target mapping table widget."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget


class TargetMappingTable(QTableWidget):
    HEADERS = [
        "Host / IP",
        "Status",
        "Credential Label",
        "Username",
        "Detected Platform",
        "Last Tested",
        "Error Message",
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(len(self.HEADERS))
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)

    def update_mapping(
        self,
        host: str,
        status: str,
        cred_label: str,
        username: str,
        platform: str,
        last_tested: str,
        error_msg: str,
    ):
        # Find row or insert
        target_row = -1
        for row in range(self.rowCount()):
            item = self.item(row, 0)
            if item and item.text().lower() == host.lower():
                target_row = row
                break

        if target_row == -1:
            target_row = self.rowCount()
            self.insertRow(target_row)

        values = [
            host,
            status,
            cred_label,
            username,
            platform,
            last_tested,
            error_msg,
        ]
        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val or ""))
            if col == 1:
                # Colorize status
                if status == "MAPPED":
                    item.setForeground(Qt.green)
                elif status in ("FAILED", "STOPPED"):
                    item.setForeground(Qt.red)
                elif status == "STALE":
                    item.setForeground(Qt.yellow)
            self.setItem(target_row, col, item)
