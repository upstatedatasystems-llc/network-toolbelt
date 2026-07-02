"""PySide6 Generic Command Runner Page."""

import os
import threading
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from network_toolbelt.core.command_policy import CommandPolicy, CommandPolicyMode
from network_toolbelt.core.device_runner import (
    ActiveConnectionRegistry,
    ConnectionManager,
    ConnectionStatus,
    DeviceSessionContext,
    FilenameSafety,
    format_concurrent_status,
)
from network_toolbelt.core.redaction import (
    LineBufferedRedactor,
    SecureTempSessionLogManager,
    redactor,
)
from network_toolbelt.core.settings import settings
from network_toolbelt.ui.pages.base_runner_page import BaseRunnerPage
from network_toolbelt.ui.widgets.dialogs import ClearSessionDialog
from network_toolbelt.ui.widgets.status_widgets import (
    CredentialStatusPanel,
    TargetPanel,
)


class CommandRunnerPage(BaseRunnerPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent, controller, title_text="Generic Command Runner")
        self.setup_ui()

    def setup_ui(self):
        self.cred_panel = CredentialStatusPanel(self.left_panel, self.controller)
        self.left_layout.addWidget(self.cred_panel)

        self.target_panel = TargetPanel(self.left_panel, self.controller)
        self.left_layout.addWidget(self.target_panel)

        run_id_box = QGroupBox("Run ID (optional)")
        run_id_layout = QHBoxLayout(run_id_box)
        self.run_id_entry = QLineEdit()
        self.run_id_entry.setPlaceholderText("Auto-generated if left blank")
        run_id_layout.addWidget(self.run_id_entry)
        self.left_layout.addWidget(run_id_box)

        cmd_box = QGroupBox("3. Commands to Run")
        cmd_layout = QVBoxLayout(cmd_box)
        self.cmd_text = QTextEdit()
        self.cmd_text.setPlaceholderText("Enter commands (one per line)")
        self.cmd_text.setMaximumHeight(120)
        cmd_layout.addWidget(self.cmd_text)
        self.left_layout.addWidget(cmd_box)

        self.run_btn = QPushButton("RUN COMMANDS")
        self.run_btn.setStyleSheet("font-size: 14px; font-weight: bold; background-color: #1e88e5; padding: 10px;")
        self.run_btn.clicked.connect(self.start_execution)
        self.left_layout.addWidget(self.run_btn)

        self.stop_btn = QPushButton("STOP")
        self.stop_btn.setStyleSheet("font-size: 14px; font-weight: bold; color: red;")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_execution)
        self.left_layout.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("Clear Current Session")
        self.clear_btn.clicked.connect(self.clear_current_session)
        self.left_layout.addWidget(self.clear_btn)

        self.left_layout.addStretch()

    def get_run_ts(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def start_execution(self):
        targets = self.target_panel.get_targets()
        self.sync_targets_to_session(targets)
        platform_choice = self.target_panel.get_platform()
        commands = [c.strip() for c in self.cmd_text.toPlainText().splitlines() if c.strip()]
        cred_sets = self.controller.credential_store.as_netmiko_dicts()
        run_id = self.run_id_entry.text().strip()
        if not run_id:
            run_id = f"CommandRunner-{self.get_run_ts()}"
        run_id = FilenameSafety.safe_run_id(run_id)

        if not cred_sets:
            QMessageBox.critical(self, "Error", "Please add at least one Credential Set")
            return
        if not targets:
            QMessageBox.critical(self, "Error", "Please provide at least one Target IP")
            return
        if not commands:
            QMessageBox.critical(self, "Error", "Please provide at least one Command")
            return

        decisions = CommandPolicy.evaluate_many(commands, settings.command_policy_mode)
        blocked = [d for d in zip(commands, decisions) if not d[1].allowed]
        if blocked:
            msg = "The following commands are blocked by the current Command Policy:\n\n"
            for cmd, dec in blocked:
                msg += f"- '{cmd}': {dec.reason}\n"
            QMessageBox.critical(self, "Policy Restriction", msg)
            return

        if settings.command_policy_mode == CommandPolicyMode.UNSAFE_ALLOWED:
            reply = QMessageBox.question(
                self,
                "Unsafe Policy Warning",
                "You are running in UNSAFE mode. Are you sure you want to execute these commands?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return

        def begin_run():
            self.stop_event.clear()
            self.enqueue("SET_BUTTONS", False, True)
            self.enqueue("CLEAR_LOGS")

            if settings.capture_mode == "raw":
                self.enqueue("WARNING_BANNER", "RAW CAPTURE ENABLED - DANGER")
            elif settings.command_policy_mode == CommandPolicyMode.UNSAFE_ALLOWED:
                self.enqueue("WARNING_BANNER", "UNSAFE COMMAND POLICY ACTIVE")
            else:
                self.enqueue("WARNING_BANNER", "")

            self.is_running = True
            threading.Thread(
                target=self.execution_thread,
                args=(cred_sets, targets, commands, platform_choice, run_id),
                daemon=True,
            ).start()

        self.prompt_for_mapping_if_needed(targets, begin_run)

    def stop_execution(self):
        self.stop_event.set()
        if self.active_conn:
            try:
                self.active_conn.disconnect()
            except Exception:
                pass
        if self.active_conns:
            self.active_conns.disconnect_all()
        self.enqueue("LOG_EXEC", "\n[Stop Requested by User]")

    def clear_current_session(self):
        dlg = ClearSessionDialog(self)
        if dlg.exec() == ClearSessionDialog.Accepted and dlg.result_data:
            res = dlg.result_data
            self.clear_page_fields(
                retain_targets=res.get("retain_targets"),
                retain_credentials=res.get("retain_credentials"),
            )
            if not res.get("retain_credentials"):
                self.controller.credential_store.clear()
                self.cred_panel.refresh()

    def clear_page_fields(self, retain_targets: bool = True, retain_credentials: bool = True):
        self.cmd_text.clear()
        self.run_id_entry.clear()
        if not retain_targets:
            self.target_panel.targets_text.clear()

    def execution_thread(self, cred_sets, targets, commands, platform_choice, run_id):
        try:
            self.enqueue("LOG_EXEC", "=== COMMAND RUNNER ===")
            log_dir = settings.base_output_dir / "Command_Runner" / run_id
            log_dir.mkdir(parents=True, exist_ok=True)
            self.enqueue("LOG_EXEC", f"Logs will be saved to: {log_dir}")

            concurrency = settings.concurrency_command

            def process_single_host(host, host_idx):
                if self.stop_event.is_set():
                    return

                safe_h = FilenameSafety.safe_host_label(host)
                prefix = f"[{host}] " if concurrency > 1 else ""
                self.enqueue("LOG_EXEC", f"\n{prefix}Connecting to {host}...")

                creds = None
                map_store = getattr(self.controller, "target_credential_store", None)
                if map_store and not self.fallback_to_all_credentials_for_run:
                    mapping = map_store.get_mapping(host)
                    if mapping and mapping.status == "MAPPED" and mapping.credential_id:
                        found = self.controller.credential_store.get_by_id(mapping.credential_id)
                        if found:
                            creds = {
                                "username": found.username,
                                "password": found.password,
                                "secret": found.secret,
                            }

                creds_to_try = [creds] if creds else cred_sets

                temp_dir = SecureTempSessionLogManager.ensure_secure_temp_session_dir(
                    settings.base_output_dir, run_id
                )
                temp_session_log_path = (
                    SecureTempSessionLogManager.create_secure_session_log_path(
                        temp_dir, safe_h
                    )
                )
                temp_session_log = str(temp_session_log_path)

                tail_stop_event = threading.Event()

                def tail_file(filepath, stop_evt):
                    try:
                        buf_redactor = LineBufferedRedactor(redactor.redact_text)
                        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                            while not stop_evt.is_set():
                                chunk = f.read(1024)
                                if chunk:
                                    out = (
                                        buf_redactor.feed(chunk)
                                        if settings.capture_mode == "redacted"
                                        else chunk
                                    )
                                    if out:
                                        self.enqueue("LOG_SESSION", out)
                                else:
                                    time.sleep(0.1)
                            chunk = f.read()
                            if chunk:
                                out = (
                                    buf_redactor.feed(chunk) + buf_redactor.flush()
                                    if settings.capture_mode == "redacted"
                                    else chunk
                                )
                                if out:
                                    self.enqueue("LOG_SESSION", out)
                    except Exception:
                        pass

                tail_t = threading.Thread(
                    target=tail_file,
                    args=(temp_session_log, tail_stop_event),
                    daemon=True,
                )
                tail_t.start()

                conn_result = None
                for c in creds_to_try:
                    if self.stop_event.is_set():
                        break
                    conn_result = ConnectionManager.connect(
                        host, c, platform_choice, temp_session_log
                    )
                    if conn_result.status == ConnectionStatus.SUCCESS:
                        break

                if not conn_result or conn_result.status != ConnectionStatus.SUCCESS:
                    err_msg = conn_result.error_message if conn_result else "Connection failed"
                    self.enqueue("LOG_EXEC", f"{prefix}✗ Connection failed: {err_msg}")
                    tail_stop_event.set()
                    tail_t.join(1.0)
                    SecureTempSessionLogManager.cleanup_secure_session_log(
                        Path(temp_session_log)
                    )
                    return

                conn = conn_result.connection
                if self.active_conns:
                    self.active_conns.register(host, conn)

                ctx = DeviceSessionContext(
                    host=host,
                    platform_choice=platform_choice,
                    logical_platform=conn_result.logical_platform,
                    device_type=conn_result.netmiko_device_type,
                    temp_session_log=temp_session_log,
                    conn=conn,
                    run_platform_probe=True,
                    _reconnect_credential=conn_result._reconnect_credential,
                )

                host_log = ""
                for cmd in commands:
                    if self.stop_event.is_set():
                        break
                    self.enqueue("LOG_EXEC", f"{prefix}Executing: {cmd}")
                    res = ConnectionManager.execute_command_with_recovery(
                        ctx, cmd, log_callback=lambda m: self.enqueue("LOG_EXEC", f"{prefix}{m}")
                    )

                    out = res.output
                    if settings.capture_mode == "redacted":
                        out = redactor.redact_text(out)

                    host_log += f"=== Command: {cmd} ===\n{out}\n\n"

                try:
                    conn.disconnect()
                except Exception:
                    pass
                if self.active_conns:
                    self.active_conns.unregister(host)

                tail_stop_event.set()
                tail_t.join(1.0)

                suffix = "_REDACTED" if settings.capture_mode == "redacted" else "_RAW"
                outfile = log_dir / f"{safe_h}{suffix}.txt"
                outfile.write_text(host_log, encoding="utf-8")
                self.enqueue("LOG_EXEC", f"{prefix}✓ Output saved to {outfile.name}")
                SecureTempSessionLogManager.cleanup_secure_session_log(
                    Path(temp_session_log)
                )

            total = len(targets)
            if concurrency == 1:
                for idx, h in enumerate(targets):
                    if self.stop_event.is_set():
                        break
                    self.set_status(f"Running — host {idx+1}/{total}: {h}")
                    self.set_progress((idx / total) * 100)
                    process_single_host(h, idx + 1)
            else:
                completed_count = 0
                active_count = 0
                targets_to_submit = list(enumerate(targets, 1))
                active_futures = set()

                with ThreadPoolExecutor(max_workers=concurrency) as executor:
                    while len(active_futures) < concurrency and targets_to_submit:
                        idx, host = targets_to_submit.pop(0)
                        active_count += 1
                        self.set_status(
                            format_concurrent_status(
                                completed_count, total, active_count, self.stop_event.is_set()
                            )
                        )
                        self.set_progress((completed_count / total) * 100)
                        f = executor.submit(process_single_host, host, idx)
                        active_futures.add(f)

                    while active_futures:
                        done, not_done = wait(active_futures, return_when=FIRST_COMPLETED)
                        for f in done:
                            active_futures.remove(f)
                            active_count -= 1
                            completed_count += 1

                            try:
                                f.result()
                            except Exception as fut_err:
                                self.enqueue("LOG_EXEC", f"Task error: {fut_err}")

                            self.set_status(
                                format_concurrent_status(
                                    completed_count, total, active_count, self.stop_event.is_set()
                                )
                            )
                            self.set_progress((completed_count / total) * 100)

                        if not self.stop_event.is_set():
                            while len(active_futures) < concurrency and targets_to_submit:
                                idx, host = targets_to_submit.pop(0)
                                active_count += 1
                                self.set_status(
                                    format_concurrent_status(
                                        completed_count, total, active_count, self.stop_event.is_set()
                                    )
                                )
                                f = executor.submit(process_single_host, host, idx)
                                active_futures.add(f)

            if self.stop_event.is_set():
                self.set_status("Stopped")
                self.enqueue("LOG_EXEC", "\n=== Execution Stopped ===")
            else:
                self.set_status("Complete")
                self.set_progress(100)
                self.enqueue("LOG_EXEC", "\n=== All Hosts Completed ===")

        except Exception as e:
            self.enqueue("LOG_EXEC", f"\nError: {str(e)}")
            self.set_status("Error")
        finally:
            self.is_running = False
            self.enqueue("SET_BUTTONS", True, False)
