"""PySide6 Credential Manager & Library Page."""

import threading
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from network_toolbelt.core.device_runner import CredentialMappingRunner
from network_toolbelt.core.settings import settings
from network_toolbelt.ui.signal_bridge import UIEventBridge
from network_toolbelt.ui.widgets.dialogs import ClearSessionDialog
from network_toolbelt.ui.widgets.target_mapper import TargetMappingTable


class CredentialManagerLibraryPage(QWidget):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent)
        self.controller = controller
        self.bridge = UIEventBridge()
        self.bridge.event_signal.connect(self.handle_ui_event)

        self.stop_event = threading.Event()
        self.is_running = False
        self.current_edit_id = None

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # 1. Nav Frame
        nav_layout = QHBoxLayout()
        back_btn = QPushButton("← Back to Dashboard")
        back_btn.clicked.connect(lambda: self.controller.show_frame("LandingPage"))
        nav_layout.addWidget(back_btn)

        self.status_lbl = QLabel("Idle")
        self.status_lbl.setStyleSheet("font-weight: bold; font-size: 13px;")
        nav_layout.addWidget(QLabel("Status:"))
        nav_layout.addWidget(self.status_lbl)

        nav_layout.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(300)
        nav_layout.addWidget(self.progress_bar)

        layout.addLayout(nav_layout)

        # 2. Main Splitter (Upper: Controls/Tables, Lower: Logs)
        main_splitter = QSplitter(Qt.Vertical)

        upper_widget = QWidget()
        upper_layout = QHBoxLayout(upper_widget)

        # Left Column: Add/Edit Credential & Mapping Controls
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_widget.setMaximumWidth(400)

        # Form Group
        form_box = QGroupBox("Add / Edit Credential")
        form_layout = QFormLayout(form_box)

        self.lbl_edit = QLineEdit()
        form_layout.addRow("Label:", self.lbl_edit)

        self.user_edit = QLineEdit()
        form_layout.addRow("Username:", self.user_edit)

        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Password:", self.pass_edit)

        self.sec_edit = QLineEdit()
        self.sec_edit.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Enable Secret:", self.sec_edit)

        btn_row = QHBoxLayout()
        save_cred_btn = QPushButton("Save Credential")
        save_cred_btn.clicked.connect(self.save_cred)
        clear_form_btn = QPushButton("New / Clear")
        clear_form_btn.clicked.connect(self.clear_form)
        btn_row.addWidget(save_cred_btn)
        btn_row.addWidget(clear_form_btn)
        form_layout.addRow(btn_row)

        left_layout.addWidget(form_box)

        # Mapping Group
        mapping_box = QGroupBox("Target IP && Platform Mapping")
        mapping_layout = QVBoxLayout(mapping_box)

        mapping_layout.addWidget(QLabel("Targets (IP/Hostname):"))
        self.targets_edit = QTextEdit()
        self.targets_edit.setPlaceholderText("Enter targets (one per line)")
        self.targets_edit.setMaximumHeight(120)
        mapping_layout.addWidget(self.targets_edit)

        mapping_layout.addWidget(QLabel("Platform for Fast Mapping:"))
        self.fast_platform_cb = QComboBox()
        self.fast_platform_cb.addItems(
            ["Cisco IOS/IOS-XE", "Cisco NX-OS", "Cisco ASA", "Auto Detect"]
        )
        mapping_layout.addWidget(self.fast_platform_cb)

        self.probe_cb = QCheckBox("Run platform detection")
        mapping_layout.addWidget(self.probe_cb)

        self.retest_cb = QCheckBox("Re-test already mapped")
        mapping_layout.addWidget(self.retest_cb)

        map_btn_row = QHBoxLayout()
        self.start_btn = QPushButton("Start Mapping")
        self.start_btn.clicked.connect(self.start_mapping)
        self.stop_btn = QPushButton("STOP")
        self.stop_btn.setStyleSheet("color: red; font-weight: bold;")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_mapping)
        clear_sess_btn = QPushButton("Clear Session")
        clear_sess_btn.clicked.connect(self.clear_session)

        map_btn_row.addWidget(self.start_btn)
        map_btn_row.addWidget(self.stop_btn)
        map_btn_row.addWidget(clear_sess_btn)
        mapping_layout.addLayout(map_btn_row)

        self.stats_lbl = QLabel("")
        mapping_layout.addWidget(self.stats_lbl)

        left_layout.addWidget(mapping_box)
        upper_layout.addWidget(left_widget)

        # Right Column: Credentials Library & Mapped Target Table
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        lib_box = QGroupBox("Credentials Library")
        lib_layout = QHBoxLayout(lib_box)

        self.cred_list = QListWidget()
        self.cred_list.itemClicked.connect(self.on_select_cred)
        lib_layout.addWidget(self.cred_list)

        lib_btn_col = QVBoxLayout()
        del_cred_btn = QPushButton("Delete")
        del_cred_btn.clicked.connect(self.delete_cred)
        clear_all_cred_btn = QPushButton("Clear All")
        clear_all_cred_btn.clicked.connect(self.clear_all_creds)
        lib_btn_col.addWidget(del_cred_btn)
        lib_btn_col.addWidget(clear_all_cred_btn)
        lib_btn_col.addStretch()
        lib_layout.addLayout(lib_btn_col)

        right_layout.addWidget(lib_box)

        # Mapped Targets Table
        map_table_box = QGroupBox("Mapped Host List")
        map_table_layout = QVBoxLayout(map_table_box)
        self.mapping_table = TargetMappingTable()
        map_table_layout.addWidget(self.mapping_table)
        right_layout.addWidget(map_table_box)

        upper_layout.addWidget(right_widget)
        main_splitter.addWidget(upper_widget)

        # Lower Log Frame
        log_box = QGroupBox("Mapping Logs")
        log_layout = QVBoxLayout(log_box)
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        log_layout.addWidget(self.log_edit)
        main_splitter.addWidget(log_box)

        main_splitter.setSizes([500, 200])
        layout.addWidget(main_splitter)

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_cred_list()
        self.refresh_mapped_table()

    def save_cred(self):
        lbl = self.lbl_edit.text().strip()
        user = self.user_edit.text().strip()
        password = self.pass_edit.text().strip()
        secret = self.sec_edit.text().strip()

        if not lbl or not user:
            QMessageBox.warning(self, "Error", "Label and Username are required.")
            return

        store = self.controller.credential_store
        if self.current_edit_id:
            store.update(self.current_edit_id, lbl, user, password, secret)
        else:
            if not password:
                QMessageBox.warning(self, "Error", "Password is required for new credentials.")
                return
            store.add(lbl, user, password, secret)

        self.clear_form()
        self.refresh_cred_list()

    def clear_form(self):
        self.current_edit_id = None
        self.lbl_edit.clear()
        self.user_edit.clear()
        self.pass_edit.clear()
        self.sec_edit.clear()
        self.cred_list.clearSelection()

    def refresh_cred_list(self):
        self.cred_list.clear()
        if not self.controller:
            return
        store = self.controller.credential_store
        for i, r in enumerate(store.records, 1):
            sec_tag = " [enable secret]" if r.secret else ""
            item = QListWidgetItem(f"{i}. {r.label} ({r.username}){sec_tag}")
            item.setData(Qt.UserRole, r.id)
            self.cred_list.addItem(item)

    def on_select_cred(self, item):
        rid = item.data(Qt.UserRole)
        record = self.controller.credential_store.get_by_id(rid)
        if record:
            self.current_edit_id = record.id
            self.lbl_edit.setText(record.label)
            self.user_edit.setText(record.username)
            self.pass_edit.clear()
            self.sec_edit.clear()

    def delete_cred(self):
        selected = self.cred_list.currentItem()
        if not selected:
            return
        rid = selected.data(Qt.UserRole)
        self.controller.credential_store.delete(rid)
        self.clear_form()
        self.refresh_cred_list()

    def clear_all_creds(self):
        reply = QMessageBox.question(
            self,
            "Clear All",
            "Clear all loaded credentials?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.controller.credential_store.clear()
            self.clear_form()
            self.refresh_cred_list()

    def refresh_mapped_table(self):
        if not self.controller or not hasattr(self.controller, "target_credential_store"):
            return
        map_store = self.controller.target_credential_store
        targets = map_store.get_targets()
        if targets and not self.targets_edit.toPlainText().strip():
            self.targets_edit.setPlainText("\n".join(targets))

        for host in targets:
            m = map_store.get_mapping(host)
            if m:
                self.mapping_table.update_mapping(
                    m.host,
                    m.status,
                    m.credential_label,
                    m.username,
                    m.detected_platform,
                    m.last_tested,
                    m.error_message,
                )

        t_count = len(targets)
        m_count = map_store.mapped_count_for_current_targets()
        self.stats_lbl.setText(f"Session targets: {t_count} | Mapped: {m_count}/{t_count}")

    def start_mapping(self):
        raw_targets = self.targets_edit.toPlainText()
        targets = [t.strip() for t in raw_targets.splitlines() if t.strip()]

        if not targets:
            QMessageBox.warning(self, "No Targets", "Please enter at least one target IP or hostname.")
            return

        if not self.controller.credential_store.records:
            QMessageBox.warning(self, "No Credentials", "Please add at least one credential first.")
            return

        self.controller.target_credential_store.set_targets(targets)
        self.stop_event.clear()
        self.is_running = True

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_lbl.setText("Mapping...")

        platform_choice = self.fast_platform_cb.currentText()
        run_probe = self.probe_cb.isChecked()
        retest = self.retest_cb.isChecked()

        def log_cb(msg):
            self.bridge.dispatch("LOG", msg)

        def status_cb(host, status, m_cred, user, plat, last, err):
            self.bridge.dispatch("STATUS", (host, status, m_cred, user, plat, last, err))

        def progress_cb(idx, total, host=None):
            self.bridge.dispatch("PROGRESS", (idx, total, host))

        cb = {"log_cb": log_cb, "status_cb": status_cb, "progress_cb": progress_cb}

        def run():
            CredentialMappingRunner.map_targets(
                targets,
                self.controller.credential_store,
                self.controller.target_credential_store,
                platform_choice,
                cb,
                self.stop_event,
                retest_mapped=retest,
                run_platform_probe=run_probe,
            )
            self.bridge.dispatch("DONE", None)

        threading.Thread(target=run, daemon=True).start()

    def stop_mapping(self):
        self.stop_event.set()
        self.stop_btn.setEnabled(False)
        self.status_lbl.setText("Stopping...")

    def clear_session(self):
        dlg = ClearSessionDialog(self)
        if dlg.exec() == ClearSessionDialog.Accepted and dlg.result_data:
            res = dlg.result_data
            if not res.get("retain_credentials"):
                self.controller.credential_store.clear()
                self.refresh_cred_list()

            if not res.get("retain_targets"):
                self.controller.target_credential_store.clear_all()
                self.targets_edit.clear()

            self.mapping_table.setRowCount(0)
            self.log_edit.clear()
            self.refresh_mapped_table()

    def handle_ui_event(self, event_type: str, args: tuple):
        if event_type == "LOG":
            self.log_edit.append(str(args[0]))
        elif event_type == "STATUS":
            host, status, m_cred, user, plat, last, err = args[0]
            self.mapping_table.update_mapping(host, status, m_cred, user, plat, last, err)
        elif event_type == "PROGRESS":
            idx, total = args[0][0], args[0][1]
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(idx)
        elif event_type == "DONE":
            self.is_running = False
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_lbl.setText("Complete")
            self.refresh_mapped_table()
