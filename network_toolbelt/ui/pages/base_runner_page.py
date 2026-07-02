"""PySide6 BaseRunnerPage reusable base class for runner/scanner pages."""

import threading
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from network_toolbelt.core.settings import settings
from network_toolbelt.ui.signal_bridge import UIEventBridge
from network_toolbelt.ui.widgets.dialogs import MappingPromptDialog, SmallMappingProgressDialog


class BaseRunnerPage(QWidget):
    def __init__(self, parent=None, controller=None, title_text="Runner"):
        super().__init__(parent)
        self.controller = controller
        self.title_text = title_text

        self.bridge = UIEventBridge()
        self.bridge.event_signal.connect(self.process_ui_event)

        self.stop_event = threading.Event()
        self.is_running = False
        self.active_conn = None
        self.active_conns = getattr(controller, "active_conns", None)
        self.fallback_to_all_credentials_for_run = False

        self._setup_base_ui()

    def enqueue(self, event_type: str, *args):
        """Bridge thread events into Qt main thread queue."""
        self.bridge.dispatch(event_type, *args)

    def set_status(self, text: str):
        self.enqueue("STATUS_UPDATE", text)

    def set_progress(self, value: float):
        self.enqueue("PROGRESS_UPDATE", value)

    def has_active_run(self) -> bool:
        return self.is_running or (hasattr(self, "run_btn") and not self.run_btn.isEnabled())

    def stop_and_clear_for_navigation(self, retain_targets: bool, retain_credentials: bool):
        self.stop_event.set()
        if self.active_conn:
            try:
                self.active_conn.disconnect()
            except Exception:
                pass
            self.active_conn = None
        if self.active_conns:
            self.active_conns.disconnect_all()
        self.enqueue("CLEAR_LOGS")
        self.set_status("Idle")
        self.set_progress(0)
        self.enqueue("WARNING_BANNER", "")
        self.enqueue("SET_BUTTONS", True, False)
        self.update_session_log_label()
        self.clear_page_fields(retain_targets=retain_targets, retain_credentials=retain_credentials)
        self.is_running = False
        self.fallback_to_all_credentials_for_run = False

    def clear_page_fields(self, retain_targets: bool = True, retain_credentials: bool = True):
        pass

    def sync_targets_to_session(self, targets: list):
        store = getattr(self.controller, "target_credential_store", None)
        if store is not None:
            seen = set()
            cleaned = []
            for t in targets:
                if t not in seen:
                    seen.add(t)
                    cleaned.append(t)
            store.set_targets(cleaned)

    def prompt_for_mapping_if_needed(self, targets: list, on_continue):
        if not targets:
            QMessageBox.critical(self, "Error", "No targets specified.")
            return

        cred_store = self.controller.credential_store
        if not cred_store.records:
            QMessageBox.critical(self, "Error", "No credentials loaded.")
            return

        map_store = getattr(self.controller, "target_credential_store", None)
        if not map_store or len(cred_store.records) <= 1:
            self.fallback_to_all_credentials_for_run = False
            on_continue()
            return

        needs_mapping = False
        for t in targets:
            m = map_store.get_mapping(t)
            if not m or m.status in ("UNMAPPED", "STALE", "FAILED", "STOPPED"):
                needs_mapping = True
                break

        if not needs_mapping:
            self.fallback_to_all_credentials_for_run = False
            on_continue()
            return

        dlg = MappingPromptDialog(self, self.controller, targets)
        if dlg.exec() == MappingPromptDialog.Accepted:
            if dlg.result_choice == "CANCEL":
                return
            elif dlg.result_choice == "CONTINUE":
                self.fallback_to_all_credentials_for_run = dlg.fallback
                on_continue()
            elif dlg.result_choice == "MAP_NOW":
                self.fallback_to_all_credentials_for_run = dlg.fallback
                prog_dlg = SmallMappingProgressDialog(self, self.controller, targets)
                prog_dlg.exec()

                failed = False
                for t in targets:
                    m = map_store.get_mapping(t)
                    if not m or m.status != "MAPPED":
                        failed = True
                        break

                if failed:
                    reply = QMessageBox.question(
                        self,
                        "Continue?",
                        "Mapping completed with failures or was stopped. Continue running the tool anyway?",
                        QMessageBox.Yes | QMessageBox.No,
                    )
                    if reply != QMessageBox.Yes:
                        return

                on_continue()

    def _setup_base_ui(self):
        layout = QVBoxLayout(self)

        # Nav Header
        nav_layout = QHBoxLayout()
        back_btn = QPushButton("← Back to Dashboard")
        back_btn.clicked.connect(lambda: self.controller.show_frame("LandingPage"))
        nav_layout.addWidget(back_btn)

        title = QLabel(self.title_text)
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        nav_layout.addWidget(title)
        nav_layout.addStretch()
        layout.addLayout(nav_layout)

        # Status & Progress Row
        status_row = QHBoxLayout()
        status_row.addWidget(QLabel("Status:"))
        self.status_lbl = QLabel("Idle")
        self.status_lbl.setStyleSheet("font-weight: bold;")
        status_row.addWidget(self.status_lbl)
        status_row.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(300)
        status_row.addWidget(self.progress_bar)
        layout.addLayout(status_row)

        # Warning Banner (Hidden by default)
        self.warning_banner = QLabel("")
        self.warning_banner.setStyleSheet("background-color: red; color: white; font-weight: bold; padding: 5px;")
        self.warning_banner.hide()
        layout.addWidget(self.warning_banner)

        # Main Paned Splitter (Left: Controls, Right: Logs)
        self.main_pane = QSplitter(Qt.Horizontal)

        self.left_panel = QWidget()
        self.left_layout = QVBoxLayout(self.left_panel)
        self.left_panel.setMaximumWidth(380)

        # Right Log Splitter (Execution Log & Session Log)
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        self.log_splitter = QSplitter(Qt.Vertical)

        # Execution Log Box
        exec_box = QWidget()
        exec_layout = QVBoxLayout(exec_box)
        exec_layout.setContentsMargins(0, 0, 0, 0)
        exec_title = QLabel("Execution Log")
        exec_title.setStyleSheet("font-weight: bold;")
        exec_layout.addWidget(exec_title)

        self.exec_text = QTextEdit()
        self.exec_text.setReadOnly(True)
        exec_layout.addWidget(self.exec_text)
        self.log_splitter.addWidget(exec_box)

        # Session Log Box
        session_box = QWidget()
        session_layout = QVBoxLayout(session_box)
        session_layout.setContentsMargins(0, 0, 0, 0)
        self.session_title = QLabel("Session Log")
        self.session_title.setStyleSheet("font-weight: bold;")
        session_layout.addWidget(self.session_title)

        self.session_text = QTextEdit()
        self.session_text.setReadOnly(True)
        session_layout.addWidget(self.session_text)
        self.log_splitter.addWidget(session_box)

        self.log_splitter.setSizes([300, 300])
        right_layout.addWidget(self.log_splitter)

        self.main_pane.addWidget(self.left_panel)
        self.main_pane.addWidget(right_panel)
        self.main_pane.setSizes([380, 800])

        layout.addWidget(self.main_pane)

    def showEvent(self, event):
        super().showEvent(event)
        self.update_session_log_label()
        if hasattr(self, "cred_panel") and hasattr(self.cred_panel, "refresh"):
            self.cred_panel.refresh()

    def update_session_log_label(self):
        if settings.capture_mode == "raw":
            self.session_title.setText("Session Log (RAW - sensitive)")
            self.session_title.setStyleSheet("font-weight: bold; color: red;")
        else:
            self.session_title.setText("Session Log")
            self.session_title.setStyleSheet("font-weight: bold;")

    def process_ui_event(self, event_type: str, args: tuple):
        if event_type == "LOG_EXEC":
            self.exec_text.append(args[0])
        elif event_type == "LOG_SESSION":
            self.session_text.insertPlainText(args[0])
            self.session_text.verticalScrollBar().setValue(
                self.session_text.verticalScrollBar().maximum()
            )
        elif event_type == "SET_BUTTONS":
            run_state, stop_state = args[0], args[1]
            if hasattr(self, "run_btn"):
                self.run_btn.setEnabled(run_state)
            if hasattr(self, "stop_btn"):
                self.stop_btn.setEnabled(stop_state)
        elif event_type == "CLEAR_LOGS":
            self.exec_text.clear()
            self.session_text.clear()
        elif event_type == "STATUS_UPDATE":
            self.status_lbl.setText(str(args[0]))
        elif event_type == "PROGRESS_UPDATE":
            val = int(args[0]) if isinstance(args[0], (int, float)) else 0
            self.progress_bar.setValue(val)
        elif event_type == "WARNING_BANNER":
            msg = args[0]
            if msg:
                self.warning_banner.setText(msg)
                self.warning_banner.show()
            else:
                self.warning_banner.hide()
