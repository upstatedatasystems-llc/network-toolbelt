"""PySide6 Maintenance Pre/Post Runner Page."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
)

from network_toolbelt.core.command_policy import CommandPolicy
from network_toolbelt.core.device_runner import ConnectionManager, ConnectionStatus
from network_toolbelt.core.maintenance import CompareEngine, SnapshotBuilder
from network_toolbelt.core.redaction import LineBufferedRedactor, SecureTempSessionLogManager, redactor
from network_toolbelt.core.settings import (
    FEATURE_COMMANDS,
    MAINTENANCE_BASELINE_COMMANDS,
    PLATFORM_COMMAND_SET_MAP,
    FilenameSafety,
    settings,
)
from network_toolbelt.ui.pages.base_runner_page import BaseRunnerPage
from network_toolbelt.ui.widgets.dialogs import ClearSessionDialog
from network_toolbelt.ui.widgets.status_widgets import CredentialStatusPanel, TargetPanel


class MaintenanceRunnerPage(BaseRunnerPage):
    def __init__(self, parent=None, controller=None):
        super().__init__(parent=parent, controller=controller, title_text="Maintenance Pre/Post Runner")
        self._build_custom_controls()

    def _build_custom_controls(self):
        # 1. Credential & Target Panels
        self.cred_panel = CredentialStatusPanel(self.left_panel, self.controller)
        self.left_layout.addWidget(self.cred_panel)

        self.target_panel = TargetPanel(self.left_panel, self.controller)
        self.left_layout.addWidget(self.target_panel)

        # 2. Action Mode Group Box
        mode_box = QGroupBox("Action Mode")
        mode_layout = QVBoxLayout(mode_box)

        self.btn_group = QButtonGroup(self)
        self.radio_pre = QRadioButton("Pre-Check Capture")
        self.radio_post = QRadioButton("Post-Check Capture")
        self.radio_compare = QRadioButton("Compare Snapshots")

        self.radio_pre.setChecked(True)
        self.btn_group.addButton(self.radio_pre)
        self.btn_group.addButton(self.radio_post)
        self.btn_group.addButton(self.radio_compare)

        mode_layout.addWidget(self.radio_pre)
        mode_layout.addWidget(self.radio_post)
        mode_layout.addWidget(self.radio_compare)

        self.left_layout.addWidget(mode_box)

        # 3. Run ID Group Box
        run_box = QGroupBox("Maintenance Run ID")
        run_layout = QFormLayout(run_box)

        self.run_id_edit = QLineEdit()
        self.generate_run_id()
        gen_btn = QPushButton("Generate New")
        gen_btn.clicked.connect(self.generate_run_id)

        run_layout.addRow("Run ID:", self.run_id_edit)
        run_layout.addRow("", gen_btn)

        self.left_layout.addWidget(run_box)

        # 4. Optional Features Group Box
        feat_box = QGroupBox("Optional Feature Bundles")
        feat_layout = QVBoxLayout(feat_box)

        self.feat_checkboxes = {}
        for feat, name in [
            ("bgp", "BGP Summary && Neighbors"),
            ("ospf", "OSPF Neighbors"),
            ("eigrp", "EIGRP Neighbors"),
            ("hsrp", "HSRP Summary"),
            ("vrrp", "VRRP Summary"),
            ("portchannel", "Port-Channel / LACP"),
            ("crypto_vpn", "Crypto / VPN Sessions"),
            ("asa_failover", "ASA Failover Status"),
        ]:
            cb = QCheckBox(name)
            self.feat_checkboxes[feat] = cb
            feat_layout.addWidget(cb)

        self.left_layout.addWidget(feat_box)

        # 5. Buttons
        self.run_btn = QPushButton("RUN MAINTENANCE CHECK")
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
        self.run_id_edit.setText(f"Run_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    def get_selected_phase(self) -> str:
        if self.radio_pre.isChecked():
            return "pre"
        if self.radio_post.isChecked():
            return "post"
        return "compare"

    def start_execution(self):
        phase = self.get_selected_phase()
        targets = self.target_panel.get_targets()
        self.sync_targets_to_session(targets)

        raw_run_id = self.run_id_edit.text().strip()
        run_id = FilenameSafety.safe_run_id(raw_run_id)

        if phase != "compare" and not targets:
            QMessageBox.warning(self, "No Targets", "Please enter at least one target IP or hostname.")
            return

        if not run_id:
            QMessageBox.warning(self, "No Run ID", "Please enter a valid Run ID.")
            return

        selected_features = [f for f, cb in self.feat_checkboxes.items() if cb.isChecked()]

        def begin_run():
            self.stop_event.clear()
            self.enqueue("SET_BUTTONS", False, True)
            self.enqueue("CLEAR_LOGS")
            self.enqueue("STATUS_UPDATE", "Starting...")
            self.enqueue("PROGRESS_UPDATE", 0)
            self.is_running = True

            threading.Thread(
                target=self.execution_thread,
                args=(targets, phase, run_id, selected_features),
                daemon=True,
            ).start()

        if phase == "compare":
            begin_run()
        else:
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

    def execution_thread(self, targets, phase, run_id, selected_features):
        try:
            concurrency = settings.concurrency_maintenance
            base_maint_dir = settings.base_output_dir / "maintenance" / run_id
            base_maint_dir.mkdir(parents=True, exist_ok=True)

            if phase == "compare":
                self.enqueue("LOG_EXEC", f"▶ Running snapshot comparison for Run ID: {run_id}...")
                self.enqueue("STATUS_UPDATE", "Comparing...")
                result_txt = CompareEngine.run_comparison(run_id, base_maint_dir)
                self.enqueue("LOG_EXEC", result_txt)
                self.enqueue("STATUS_UPDATE", "Comparison Complete")
                self.enqueue("PROGRESS_UPDATE", 100)
                return

            phase_dir = base_maint_dir / phase
            phase_dir.mkdir(parents=True, exist_ok=True)

            self.enqueue(
                "LOG_EXEC",
                f"▶ Starting Maintenance {phase.upper()} Capture (Run ID: {run_id}, Concurrency: {concurrency})...",
            )

            completed = 0
            total = len(targets)

            def process_host(target):
                if self.stop_event.is_set():
                    return target, "SKIPPED", "Stop requested"

                self.enqueue("LOG_EXEC", f"▶ Host [{target}]: Initializing connection...")

                cred = self.controller.target_credential_store.get_mapping(target)
                auth_creds = []
                if cred and cred.status == "MAPPED" and not self.fallback_to_all_credentials_for_run:
                    rec = self.controller.credential_store.get_by_id(cred.credential_id)
                    if rec:
                        auth_creds.append(rec)
                if not auth_creds:
                    auth_creds = self.controller.credential_store.records

                if not auth_creds:
                    self.enqueue("LOG_EXEC", f"❌ Host [{target}]: No credentials available.")
                    return target, "FAIL", "No credentials"

                conn_res = None
                used_cred = None
                for c in auth_creds:
                    if self.stop_event.is_set():
                        break
                    conn_res = ConnectionManager.connect(target, c, self.active_conns, run_platform_probe=True)
                    if conn_res.status == ConnectionStatus.SUCCESS:
                        used_cred = c
                        break

                if not conn_res or conn_res.status != ConnectionStatus.SUCCESS or not conn_res.netmiko_conn:
                    msg = conn_res.error_message if conn_res else "Auth failed"
                    self.enqueue("LOG_EXEC", f"❌ Host [{target}]: Connection failed - {msg}")
                    return target, "FAIL", msg

                net_conn = conn_res.netmiko_conn
                platform = conn_res.detected_platform
                cmd_set_key = PLATFORM_COMMAND_SET_MAP.get(platform, "CATALYST_IOS_SWITCH")
                cmd_list = list(MAINTENANCE_BASELINE_COMMANDS.get(cmd_set_key, []))

                for feat in selected_features:
                    cmd_list.extend(FEATURE_COMMANDS.get(feat, []))

                seen = set()
                dedup_cmds = []
                for c in cmd_list:
                    if c not in seen:
                        seen.add(c)
                        dedup_cmds.append(c)

                host_output = []
                cmd_results = []
                safe_host = FilenameSafety.safe_host_label(target)

                temp_mgr = SecureTempSessionLogManager(redactor)
                temp_path = temp_mgr.create_temp_log(run_id, phase, safe_host)

                with open(temp_path, "a", encoding="utf-8") as temp_file:
                    stream_redactor = LineBufferedRedactor(redactor, temp_file)

                    for cmd in dedup_cmds:
                        if self.stop_event.is_set():
                            break

                        decision = CommandPolicy.evaluate(cmd, settings.command_policy_mode)
                        if not decision.allowed:
                            self.enqueue("LOG_EXEC", f"⚠️ [{target}] Blocked by policy: {cmd}")
                            continue

                        self.enqueue("LOG_EXEC", f"[{target}] Executing: {cmd}")

                        c_res = ConnectionManager.safe_send_command(net_conn, cmd)
                        cmd_results.append(
                            {
                                "command": cmd,
                                "status": c_res.status.name,
                                "elapsed": c_res.elapsed_seconds,
                            }
                        )

                        hdr = f"## {cmd}\n"
                        host_output.append(hdr)
                        host_output.append(c_res.output)
                        host_output.append("\n")

                        stream_redactor.write(hdr + c_res.output + "\n")

                net_conn.disconnect()

                full_output_text = "".join(host_output)

                txt_file = phase_dir / f"{safe_host}-{phase}.txt"
                txt_file.write_text(full_output_text, encoding="utf-8")

                snap = SnapshotBuilder.build(
                    run_id, phase, target, platform.name, cmd_set_key, settings.capture_mode, full_output_text, cmd_results
                )

                if settings.write_json_outputs:
                    json_file = phase_dir / f"{safe_host}-{phase}.json"
                    json_file.write_text(json.dumps(snap, indent=4), encoding="utf-8")

                temp_mgr.cleanup_all()

                self.enqueue("LOG_EXEC", f"✅ Host [{target}]: Capture complete.")
                return target, "SUCCESS", "Complete"

            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = {executor.submit(process_host, t): t for t in targets}
                for f in as_completed(futures):
                    t = futures[f]
                    try:
                        _, st, msg = f.result()
                    except Exception as e:
                        self.enqueue("LOG_EXEC", f"❌ Host [{t}]: Exception - {str(e)}")
                    completed += 1
                    self.enqueue("PROGRESS_UPDATE", (completed / total) * 100)
                    self.enqueue("STATUS_UPDATE", f"Running ({completed}/{total})")

            if self.stop_event.is_set():
                self.enqueue("STATUS_UPDATE", "Stopped")
                self.enqueue("LOG_EXEC", "\n=== Execution Stopped ===")
            else:
                self.enqueue("STATUS_UPDATE", "Complete")
                self.enqueue("PROGRESS_UPDATE", 100)
                self.enqueue("LOG_EXEC", f"\n▶ Maintenance {phase.upper()} Capture complete!")

        except Exception as e:
            self.enqueue("LOG_EXEC", f"\nError: {str(e)}")
            self.enqueue("STATUS_UPDATE", "Error")
        finally:
            self.is_running = False
            self.enqueue("SET_BUTTONS", True, False)
