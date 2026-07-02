"""PySide6 dialog implementations for Network Toolbelt."""

import os
import queue
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from network_toolbelt.core.device_runner import CredentialMappingRunner
from network_toolbelt.core.settings import settings


class ParallelSessionsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Parallel Sessions Configuration")
        self.setFixedSize(380, 280)

        layout = QVBoxLayout(self)
        title = QLabel("Configure Parallel Session Limits")
        title.setStyleSheet("font-size: 14px; font-weight: bold;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        form_layout = QFormLayout()

        self.maint_spin = QSpinBox()
        self.maint_spin.setRange(1, 20)
        self.maint_spin.setValue(settings.concurrency_maintenance)
        form_layout.addRow("Maintenance Pre/Post Runner:", self.maint_spin)

        self.scan_spin = QSpinBox()
        self.scan_spin.setRange(1, 20)
        self.scan_spin.setValue(settings.concurrency_scanners)
        form_layout.addRow("Network Scanners:", self.scan_spin)

        self.cmd_spin = QSpinBox()
        self.cmd_spin.setRange(1, 20)
        self.cmd_spin.setValue(settings.concurrency_command)
        form_layout.addRow("Generic Command Runner:", self.cmd_spin)

        self.map_spin = QSpinBox()
        self.map_spin.setRange(1, 20)
        self.map_spin.setValue(settings.concurrency_mapper)
        form_layout.addRow("Credential Mapper:", self.map_spin)

        layout.addLayout(form_layout)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save_settings)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def save_settings(self):
        settings.concurrency_maintenance = self.maint_spin.value()
        settings.concurrency_scanners = self.scan_spin.value()
        settings.concurrency_command = self.cmd_spin.value()
        settings.concurrency_mapper = self.map_spin.value()
        QMessageBox.information(
            self, "Success", "Parallel sessions settings updated successfully."
        )
        self.accept()


class RunningNavigationDialog(QDialog):
    def __init__(self, parent=None, tool_name: str = "Tool"):
        super().__init__(parent)
        self.setWindowTitle("Stop Running Tool?")
        self.setFixedSize(380, 220)
        self.result_data = None

        layout = QVBoxLayout(self)
        title = QLabel(f"{tool_name} is still running.")
        title.setStyleSheet("font-size: 13px; font-weight: bold;")
        layout.addWidget(title)

        subtitle = QLabel(
            "Leaving this page will stop the tool\nand clear the session. Are you sure?"
        )
        layout.addWidget(subtitle)

        self.retain_creds = QCheckBox("Retain global credentials")
        self.retain_creds.setChecked(True)
        layout.addWidget(self.retain_creds)

        self.retain_targets = QCheckBox("Retain target IPs")
        self.retain_targets.setChecked(True)
        layout.addWidget(self.retain_targets)

        btn_layout = QHBoxLayout()
        leave_btn = QPushButton("Leave Page")
        leave_btn.clicked.connect(self.do_leave)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(leave_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def do_leave(self):
        self.result_data = {
            "confirmed": True,
            "retain_credentials": self.retain_creds.isChecked(),
            "retain_targets": self.retain_targets.isChecked(),
        }
        self.accept()


class ClearSessionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Clear Session")
        self.setFixedSize(320, 180)
        self.result_data = None

        layout = QVBoxLayout(self)
        title = QLabel("Clear the current session?")
        title.setStyleSheet("font-size: 13px; font-weight: bold;")
        layout.addWidget(title)

        self.retain_creds = QCheckBox("Retain global credentials")
        self.retain_creds.setChecked(True)
        layout.addWidget(self.retain_creds)

        self.retain_targets = QCheckBox("Retain target IPs")
        self.retain_targets.setChecked(True)
        layout.addWidget(self.retain_targets)

        btn_layout = QHBoxLayout()
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.do_clear)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(clear_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def do_clear(self):
        self.result_data = {
            "retain_credentials": self.retain_creds.isChecked(),
            "retain_targets": self.retain_targets.isChecked(),
        }
        self.accept()


class MappingPromptDialog(QDialog):
    def __init__(self, parent=None, controller=None, targets: list = None):
        super().__init__(parent)
        self.setWindowTitle("Pre-Run Mapping Required?")
        self.setFixedSize(450, 260)
        self.result_choice = "CANCEL"
        self.fallback = False

        layout = QVBoxLayout(self)
        msg = (
            "Map IPs to loaded credentials before running this tool?\n\n"
            "This will attempt SSH authentication to each target using the loaded credentials "
            "and remember which credential works for each IP. This reduces repeated failed auth attempts."
        )
        lbl = QLabel(msg)
        lbl.setWordWrap(True)
        layout.addWidget(lbl)

        self.fallback_cb = QCheckBox(
            "Fallback to all credentials if mapped credential fails during tool run"
        )
        layout.addWidget(self.fallback_cb)

        btn_layout = QHBoxLayout()
        map_btn = QPushButton("Map Now")
        map_btn.clicked.connect(self.do_map)
        cont_btn = QPushButton("Continue Without Mapping")
        cont_btn.clicked.connect(self.do_continue)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(map_btn)
        btn_layout.addWidget(cont_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def do_map(self):
        self.result_choice = "MAP_NOW"
        self.fallback = self.fallback_cb.isChecked()
        self.accept()

    def do_continue(self):
        self.result_choice = "CONTINUE"
        self.fallback = self.fallback_cb.isChecked()
        self.accept()


class SmallMappingProgressDialog(QDialog):
    def __init__(self, parent=None, controller=None, targets: list = None):
        super().__init__(parent)
        self.controller = controller
        self.targets = targets or []
        self.setWindowTitle("Mapping Progress")
        self.setFixedSize(520, 360)

        self.ui_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.is_running = True

        layout = QVBoxLayout(self)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, len(self.targets) or 1)
        layout.addWidget(self.progress_bar)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)

        self.stop_btn = QPushButton("STOP")
        self.stop_btn.setStyleSheet("color: red; font-weight: bold;")
        self.stop_btn.clicked.connect(self.stop_mapping)
        layout.addWidget(self.stop_btn)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.process_queue)
        self.timer.start(100)

        self.start_thread()

    def start_thread(self):
        def _log(msg):
            self.ui_queue.put(("LOG", msg))

        def _stat(h, s, c, u, p, l, e):
            pass

        def _prog(i, t, h=None):
            self.ui_queue.put(("PROGRESS", (i, t, h)))

        cb = {"log_cb": _log, "status_cb": _stat, "progress_cb": _prog}

        def run():
            if self.controller:
                CredentialMappingRunner.map_targets(
                    self.targets,
                    self.controller.credential_store,
                    self.controller.target_credential_store,
                    "Auto Detect Platform",
                    cb,
                    self.stop_event,
                    False,
                    True,
                    "redacted",
                )
            self.ui_queue.put(("DONE", None))

        threading.Thread(target=run, daemon=True).start()

    def stop_mapping(self):
        self.stop_event.set()
        self.stop_btn.setEnabled(False)

    def process_queue(self):
        try:
            while True:
                msg_type, data = self.ui_queue.get_nowait()
                if msg_type == "LOG":
                    self.log_text.append(data)
                elif msg_type == "PROGRESS":
                    if len(data) == 3:
                        idx, total, _ = data
                    else:
                        idx, total = data
                    self.progress_bar.setMaximum(total)
                    self.progress_bar.setValue(idx)
                elif msg_type == "DONE":
                    self.is_running = False
                    self.timer.stop()
                    self.stop_btn.setText("Close")
                    self.stop_btn.setEnabled(True)
                    self.stop_btn.setStyleSheet("")
                    self.stop_btn.clicked.disconnect()
                    self.stop_btn.clicked.connect(self.accept)
        except queue.Empty:
            pass


class ToolCommandConfigDialog(QDialog):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent)
        self.setWindowTitle("Tool Command Configuration")
        self.setFixedSize(700, 500)
        layout = QVBoxLayout(self)
        lbl = QLabel(
            "Tool Command Configuration is available under Settings.\n\n"
            "Default command bundles are active for all tools."
        )
        lbl.setWordWrap(True)
        layout.addWidget(lbl)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)


class RunSessionSelectionDialog(QDialog):
    def __init__(self, parent=None, sessions: list = None):
        super().__init__(parent)
        self.setWindowTitle("Select Run Session")
        self.setFixedSize(650, 400)
        self.sessions = sessions or []
        self.selected_session = None

        layout = QVBoxLayout(self)
        lbl = QLabel("Select a Run Session for Export:")
        lbl.setStyleSheet("font-weight: bold; font-size: 13px;")
        layout.addWidget(lbl)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Tool / Scanner", "Run ID", "Last Modified"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.itemDoubleClicked.connect(self.do_select)

        for idx, (tool, run_id, path) in enumerate(self.sessions):
            self.table.insertRow(idx)
            self.table.setItem(idx, 0, QTableWidgetItem(str(tool)))
            self.table.setItem(idx, 1, QTableWidgetItem(str(run_id)))
            try:
                mtime_str = datetime.fromtimestamp(path.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                mtime_str = "Unknown"
            self.table.setItem(idx, 2, QTableWidgetItem(mtime_str))

        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        sel_btn = QPushButton("Select")
        sel_btn.clicked.connect(self.do_select)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(sel_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def do_select(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            self.selected_session = self.sessions[row]
            self.accept()
        else:
            QMessageBox.warning(self, "Selection Required", "Please select a run session from the list.")
