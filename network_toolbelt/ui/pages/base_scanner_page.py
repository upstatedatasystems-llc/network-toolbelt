"""PySide6 BaseScannerPage base class for all scanner pages."""

import json
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from network_toolbelt.core.device_runner import (
    ConnectionManager,
    ConnectionStatus,
    DeviceSessionContext,
    FilenameSafety,
    format_concurrent_status,
)
from network_toolbelt.core.maintenance import ParserHelpers
from network_toolbelt.core.redaction import LineBufferedRedactor, SecureTempSessionLogManager, redactor
from network_toolbelt.core.scanners import ScannerDefinition, ScannerEngine, ScannerHostResult, ScannerRunConfig
from network_toolbelt.core.settings import PLATFORM_COMMAND_SET_MAP, CommandStatus, settings
from network_toolbelt.ui.pages.base_runner_page import BaseRunnerPage
from network_toolbelt.ui.widgets.dialogs import ClearSessionDialog
from network_toolbelt.ui.widgets.status_widgets import CredentialStatusPanel, TargetPanel


class BaseScannerPage(BaseRunnerPage):
    def __init__(self, parent=None, controller=None, scanner_def: ScannerDefinition = None):
        title = scanner_def.name if scanner_def else "Scanner"
        super().__init__(parent=parent, controller=controller, title_text=title)
        self.scanner_def = scanner_def
        self._setup_scanner_base_ui()

    def _setup_scanner_base_ui(self):
        # 1. Back to Scanners Landing button
        back_scanners_btn = QPushButton("← Back to Scanners")
        back_scanners_btn.clicked.connect(lambda: self.controller.show_frame("ScannerLandingPage"))
        self.left_layout.insertWidget(0, back_scanners_btn)

        if self.scanner_def and self.scanner_def.description:
            desc_lbl = QLabel(self.scanner_def.description)
            desc_lbl.setWordWrap(True)
            desc_lbl.setStyleSheet("color: #aaa; font-style: italic; margin-bottom: 5px;")
            self.left_layout.insertWidget(1, desc_lbl)

        # 2. Run ID Box
        run_id_box = QGroupBox("Run ID")
        run_id_layout = QVBoxLayout(run_id_box)
        self.run_id_entry = QLineEdit()
        self.generate_run_id()
        run_id_layout.addWidget(self.run_id_entry)
        self.left_layout.addWidget(run_id_box)

        # 3. Credential & Target Panels
        self.cred_panel = CredentialStatusPanel(self.left_panel, self.controller)
        self.left_layout.addWidget(self.cred_panel)

        self.target_panel = TargetPanel(self.left_panel, self.controller)
        self.left_layout.addWidget(self.target_panel)

        # 4. Options Frame
        self.options_box = QGroupBox("Scanner Options")
        self.options_layout = QVBoxLayout(self.options_box)
        self.build_options()
        self.left_layout.addWidget(self.options_box)

        # 5. Buttons
        self.run_btn = QPushButton("RUN SCANNER")
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

    def generate_run_id(self):
        self.run_id_entry.setText(f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    def build_options(self):
        pass  # Override in subclasses

    def get_options(self) -> dict:
        return {}  # Override in subclasses

    def start_execution(self):
        run_id_raw = self.run_id_entry.text().strip()
        run_id = FilenameSafety.safe_run_id(run_id_raw)
        if not run_id or run_id == "unknown":
            QMessageBox.warning(self, "Error", "Valid Run ID is required")
            return

        targets = self.target_panel.get_targets()
        self.sync_targets_to_session(targets)
        platform_choice = self.target_panel.get_platform()
        cred_sets = self.controller.credential_store.as_netmiko_dicts()
        options = self.get_options()

        if not cred_sets:
            QMessageBox.critical(self, "Error", "Please add at least one Credential Set")
            return
        if not targets:
            QMessageBox.critical(self, "Error", "Please provide at least one Target IP")
            return

        concurrency = settings.concurrency_scanners

        internal_key = self.scanner_def.internal_key
        all_cmds = []
        for grp in self.scanner_def.commands_by_command_set.keys():
            all_cmds.extend(
                self.controller.tool_command_manager.get_effective_commands(
                    internal_key, grp, self.scanner_def.commands_by_command_set[grp]
                )
            )

        unsafe = self.controller.tool_command_manager.validate_commands(all_cmds)
        if unsafe:
            QMessageBox.critical(self, "Internal Error", f"Scanner bundle contains unsafe commands: {unsafe}")
            return

        config = ScannerRunConfig(
            scanner_name=self.scanner_def.name,
            targets=targets,
            credentials=cred_sets,
            platform_choice=platform_choice,
            options=options,
            run_id=run_id,
            output_dir=settings.base_output_dir / "Scanners" / FilenameSafety.safe_filename(self.scanner_def.name) / run_id,
            timestamp=datetime.now().strftime("%Y%m%d-%H%M%S"),
        )

        def begin_run():
            self.stop_event.clear()
            self.enqueue("SET_BUTTONS", False, True)
            self.enqueue("CLEAR_LOGS")

            if settings.capture_mode == "raw":
                self.enqueue("WARNING_BANNER", "RAW CAPTURE ENABLED - DANGER")
            else:
                self.enqueue("WARNING_BANNER", "")
                self.update_session_log_label()

            self.is_running = True
            threading.Thread(target=self.execution_thread, args=(config, concurrency), daemon=True).start()

        self.prompt_for_mapping_if_needed(targets, begin_run)

    def stop_execution(self):
        self.stop_event.set()
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
        self.generate_run_id()
        if not retain_targets:
            self.target_panel.targets_text.clear()

    def execution_thread(self, config: ScannerRunConfig, concurrency: int):
        try:
            self.enqueue("LOG_EXEC", f"=== STARTING {config.scanner_name.upper()} ===")
            config.output_dir.mkdir(parents=True, exist_ok=True)
            self.enqueue("LOG_EXEC", f"Output directory: {config.output_dir}")
            self.enqueue("LOG_EXEC", f"Concurrency: {concurrency}")

            host_results = []
            total_hosts = len(config.targets)

            def worker_task(host, idx, task_key):
                safe_host = FilenameSafety.safe_host_label(host)
                host_had_diagnostics = False
                outputs = {}
                errors = []
                last_exec_res = None
                logical_plat = None
                conn_result = None

                host_out_dir = config.output_dir / "hosts"
                host_out_dir.mkdir(exist_ok=True)
                temp_dir = SecureTempSessionLogManager.ensure_secure_temp_session_dir(settings.base_output_dir, "generic")
                temp_session_log_path = SecureTempSessionLogManager.create_secure_session_log_path(
                    temp_dir, f"{safe_host}_{idx}"
                )
                temp_session_log = str(temp_session_log_path)

                tail_stop_event = threading.Event()

                def sync_tail():
                    try:
                        buf_redactor = LineBufferedRedactor(redactor)
                        with open(temp_session_log, "r", encoding="utf-8", errors="replace") as f:
                            while not tail_stop_event.is_set() and not self.stop_event.is_set():
                                chunk = f.read(1024)
                                if chunk:
                                    out = buf_redactor.feed(chunk) if settings.capture_mode == "redacted" else chunk
                                    if out:
                                        self.enqueue("LOG_SESSION", out)
                                else:
                                    time.sleep(0.1)
                            chunk = f.read()
                            if chunk:
                                out = buf_redactor.feed(chunk) if settings.capture_mode == "redacted" else chunk
                                if out:
                                    self.enqueue("LOG_SESSION", out)
                            out = buf_redactor.flush() if settings.capture_mode == "redacted" else ""
                            if out:
                                self.enqueue("LOG_SESSION", out)
                    except Exception:
                        pass

                tail_t = threading.Thread(target=sync_tail, daemon=True)
                tail_t.start()

                def log_cb(msg):
                    self.enqueue("LOG_EXEC", f"[{host}] {msg}")

                try:
                    self.enqueue("LOG_EXEC", f"\n▶ Starting host [{idx}/{len(config.targets)}] {host}")

                    conn_result = ConnectionManager.connect_with_mapped_or_global_credentials(
                        host,
                        config.platform_choice,
                        temp_session_log,
                        self.controller.credential_store,
                        getattr(self.controller, "target_credential_store", None),
                        log_cb,
                        self.stop_event,
                        getattr(self, "fallback_to_all_credentials_for_run", False),
                        run_platform_probe=True,
                    )

                    if conn_result.status == ConnectionStatus.SUCCESS:
                        self.active_conns.register(task_key, conn_result.connection)

                        if not conn_result.session_prepped:
                            ConnectionManager.prepare_session(
                                conn_result.connection,
                                conn_result.logical_platform,
                                conn_result.netmiko_device_type,
                                log_cb,
                            )

                        logical_plat = conn_result.logical_platform
                        cmd_set_key = PLATFORM_COMMAND_SET_MAP.get(logical_plat)

                        cmd_bundle = self.scanner_def.commands_by_command_set.get(cmd_set_key, [])
                        internal_key = self.scanner_def.internal_key
                        cmd_bundle = self.controller.tool_command_manager.get_effective_commands(
                            internal_key, cmd_set_key, cmd_bundle
                        )

                        unsafe_s = self.controller.tool_command_manager.validate_commands(cmd_bundle)
                        if unsafe_s:
                            self.enqueue("LOG_EXEC", f"[{host}] ! Unsafe commands found in override, skipping: {unsafe_s}")
                            cmd_bundle = [c for c in cmd_bundle if c not in unsafe_s]

                        if not cmd_bundle:
                            self.enqueue("LOG_EXEC", f"[{host}] ✗ No commands for platform {logical_plat.name}")
                            errors.append(f"No commands for {logical_plat.name}")
                        else:
                            for cmd_idx, cmd in enumerate(cmd_bundle, 1):
                                if self.stop_event.is_set():
                                    break
                                self.enqueue("LOG_EXEC", f"[{host}] -> {cmd}")

                                context = DeviceSessionContext(
                                    host=host,
                                    platform_choice=config.platform_choice,
                                    logical_platform=conn_result.logical_platform,
                                    device_type=conn_result.netmiko_device_type,
                                    temp_session_log=temp_session_log,
                                    conn=conn_result.connection,
                                    run_platform_probe=True,
                                    platform_probe_output=conn_result.platform_probe_output,
                                    _reconnect_credential=conn_result._reconnect_credential,
                                )
                                exec_res = ConnectionManager.execute_command_with_recovery(context, cmd, log_callback=log_cb)
                                self.active_conns.register(task_key, context.conn)
                                cmd_out = exec_res.output
                                status = exec_res.status
                                err_msg = exec_res.error_message

                                last_exec_res = exec_res
                                diag_hdr = ConnectionManager.format_diagnostic_header(exec_res)

                                if status == CommandStatus.COMMAND_UNSUPPORTED:
                                    self.enqueue("LOG_EXEC", f"[{host}] ! Command unsupported: {cmd}")
                                elif status == CommandStatus.PRIVILEGE_DENIED:
                                    self.enqueue("LOG_EXEC", f"[{host}] ! Privilege denied: {cmd}")
                                elif status == CommandStatus.COMMAND_TIMEOUT:
                                    self.enqueue("LOG_EXEC", f"[{host}] ✗ Timeout: {cmd}")
                                    outputs[cmd] = f"{diag_hdr}\nCOMMAND TIMEOUT"
                                    errors.append(f"Timeout on {cmd}")
                                    continue
                                elif status != CommandStatus.SUCCESS:
                                    self.enqueue("LOG_EXEC", f"[{host}] ✗ Error: {cmd} - {err_msg}")
                                    outputs[cmd] = f"{diag_hdr}\nERROR: {err_msg}"
                                    errors.append(f"Error on {cmd}: {err_msg}")
                                    continue

                                if settings.capture_mode == "redacted":
                                    cmd_out = redactor.redact_text(cmd_out)
                                outputs[cmd] = f"{diag_hdr}\n{cmd_out}"
                    else:
                        host_had_diagnostics = True
                        errors.append(conn_result.error_message if conn_result else "Connection Failed")
                except Exception as ex:
                    host_had_diagnostics = True
                    errors.append(f"Worker crash: {ex}")
                finally:
                    self.active_conns.unregister(task_key)
                    if conn_result and conn_result.status == ConnectionStatus.SUCCESS:
                        try:
                            conn_result.connection.disconnect()
                        except Exception:
                            pass

                    tail_stop_event.set()
                    tail_t.join(1.0)

                    has_errors = bool(errors) or (last_exec_res.abort_host if last_exec_res else False)

                    if conn_result and conn_result.status == ConnectionStatus.SUCCESS:
                        if settings.save_session_logs == "never" or (
                            settings.save_session_logs == "errors_only" and not (has_errors or host_had_diagnostics)
                        ):
                            SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
                        else:
                            if settings.capture_mode == "redacted":
                                redactor.redact_file(
                                    Path(temp_session_log),
                                    host_out_dir / f"{safe_host}_{config.timestamp}_session_REDACTED.log",
                                )
                                SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))
                            else:
                                Path(temp_session_log).rename(
                                    host_out_dir / f"{safe_host}_{config.timestamp}_session_RAW.log"
                                )
                    else:
                        if settings.save_session_logs != "never":
                            if settings.capture_mode == "redacted":
                                redactor.redact_file(
                                    Path(temp_session_log),
                                    host_out_dir / f"{safe_host}_{config.timestamp}_session_REDACTED.log",
                                )
                            else:
                                Path(temp_session_log).rename(
                                    host_out_dir / f"{safe_host}_{config.timestamp}_session_RAW.log"
                                )
                        SecureTempSessionLogManager.cleanup_secure_session_log(Path(temp_session_log))

                parsed_data = {}
                findings = []
                warnings = []
                try:
                    if (
                        outputs
                        and conn_result
                        and conn_result.status == ConnectionStatus.SUCCESS
                        and not self.stop_event.is_set()
                    ):
                        parsed_data, findings, warnings = self.scanner_def.parser_callback(
                            ParserHelpers.normalize_parser_platform(logical_plat), outputs, config.options
                        )
                except Exception as e:
                    errors.append(f"Parser crash: {str(e)}")

                status_res = conn_result.status.name if conn_result else "FAIL"
                res = ScannerHostResult(
                    host,
                    safe_host,
                    status_res,
                    logical_plat.name if logical_plat else "",
                    conn_result.netmiko_device_type if conn_result else "",
                    outputs,
                    parsed_data,
                    findings,
                    errors,
                    warnings,
                )

                if not self.stop_event.is_set() and conn_result and conn_result.status == ConnectionStatus.SUCCESS:
                    if settings.write_json_outputs:
                        out_json = {
                            "host": host,
                            "status": res.connection_status,
                            "parsed": parsed_data,
                            "findings": [f.__dict__ for f in findings],
                            "errors": errors,
                            "warnings": warnings,
                        }
                        if settings.write_full_output_json:
                            out_json["outputs"] = outputs
                        with open(host_out_dir / f"{safe_host}_report.json", "w") as f:
                            json.dump(out_json, f, indent=4)

                    host_severity = "PASS"
                    if any(f.status == "FAIL" for f in findings) or errors:
                        host_severity = "FAIL"
                    elif any(f.status == "WARN" for f in findings) or warnings:
                        host_severity = "WARN"

                    out_txt = [f"HOST: {host}", f"STATUS: {host_severity}", "\nTop Findings:"]
                    for err in errors:
                        out_txt.append(f"[FAIL] ERROR: {err}")
                    for warn in warnings:
                        out_txt.append(f"[WARN] WARNING: {warn}")
                    for f_obj in findings:
                        out_txt.append(f"[{f_obj.status}] {f_obj.category}: {f_obj.message}")
                    if not findings and not errors and not warnings:
                        out_txt.append("[PASS] No issues found.")

                    out_txt.append("\n--- Raw/Redacted Output ---")
                    for cmd, out in outputs.items():
                        out_txt.append(f"\n## {cmd}\n{out}")
                    (host_out_dir / f"{safe_host}_report.txt").write_text("\n".join(out_txt), encoding="utf-8")
                    self.enqueue("LOG_EXEC", f"[{host}] ✓ completed")
                else:
                    out_txt = [f"HOST: {host}", "STATUS: FAIL", "\nTop Findings:"]
                    for err in errors:
                        out_txt.append(f"[FAIL] ERROR: {err}")
                    (host_out_dir / f"{safe_host}_report.txt").write_text("\n".join(out_txt), encoding="utf-8")

                return res

            completed_count = 0
            active_count = 0
            futures = {}
            targets_to_submit = list(enumerate(config.targets, 1))
            active_futures = set()

            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                while len(active_futures) < concurrency and targets_to_submit:
                    idx, host = targets_to_submit.pop(0)
                    task_key = f"{host.lower()}::{config.run_id}::{idx}"
                    active_count += 1
                    self.enqueue("STATUS_UPDATE", format_concurrent_status(completed_count, total_hosts, active_count, self.stop_event.is_set()))

                    f = executor.submit(worker_task, host, idx, task_key)
                    active_futures.add(f)
                    futures[f] = (host, idx)

                while active_futures:
                    done, not_done = wait(active_futures, return_when=FIRST_COMPLETED)
                    for f in done:
                        active_futures.remove(f)
                        active_count -= 1
                        host, idx = futures.pop(f)

                        try:
                            res = f.result()
                        except Exception as e:
                            res = ScannerHostResult(
                                host=host,
                                safe_host=FilenameSafety.safe_host_label(host),
                                connection_status="FAIL",
                                detected_platform="",
                                netmiko_device_type="",
                                outputs={},
                                parsed_data={},
                                findings=[],
                                errors=[f"Internal thread crash: {e}"],
                                warnings=[],
                            )

                        host_results.append(res)
                        completed_count += 1
                        self.enqueue("PROGRESS_UPDATE", (completed_count / total_hosts) * 100)
                        self.enqueue("STATUS_UPDATE", format_concurrent_status(completed_count, total_hosts, active_count, self.stop_event.is_set()))

                        if not self.stop_event.is_set() and targets_to_submit:
                            n_idx, next_host = targets_to_submit.pop(0)
                            next_key = f"{next_host.lower()}::{config.run_id}::{n_idx}"
                            active_count += 1
                            self.enqueue("STATUS_UPDATE", format_concurrent_status(completed_count, total_hosts, active_count, self.stop_event.is_set()))

                            next_f = executor.submit(worker_task, next_host, n_idx, next_key)
                            active_futures.add(next_f)
                            futures[next_f] = (next_host, n_idx)

            if self.stop_event.is_set():
                self.enqueue("STATUS_UPDATE", "Stopped by user")
            else:
                ScannerEngine.write_scanner_summary(config, host_results)
                self.enqueue("PROGRESS_UPDATE", 100)
                self.enqueue("STATUS_UPDATE", "Complete")
                self.enqueue("LOG_EXEC", "\n=== ALL DONE ===")

        except Exception as e:
            self.enqueue("STATUS_UPDATE", "Error")
            self.enqueue("LOG_EXEC", f"\nFATAL ERROR: {str(e)}")
        finally:
            self.enqueue("SET_BUTTONS", True, False)
            self.is_running = False
            self.fallback_to_all_credentials_for_run = False
