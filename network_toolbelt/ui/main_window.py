"""PySide6 MainWindow shell for Network Toolbelt."""

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QMainWindow,
    QMenu,
    QMenuBar,
    QMessageBox,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from network_toolbelt.core.credentials import CredentialStore, TargetCredentialMapStore
from network_toolbelt.core.device_runner import ActiveConnectionRegistry
from network_toolbelt.core.settings import APP_VERSION, CommandPolicyMode, settings
from network_toolbelt.ui.pages.base_runner_page import BaseRunnerPage
from network_toolbelt.ui.pages.command_runner_page import CommandRunnerPage
from network_toolbelt.ui.pages.credential_manager_page import CredentialManagerLibraryPage
from network_toolbelt.ui.pages.landing_page import LandingPage
from network_toolbelt.ui.pages.stub_page import (
    DocumentationStubPage,
    MaintenanceRunnerStubPage,
    ScannerLandingStubPage,
    SnmpCredentialManagerStubPage,
    SnmpOidScannerStubPage,
)
from network_toolbelt.ui.widgets.dialogs import ParallelSessionsDialog, RunningNavigationDialog


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.credential_store = CredentialStore()
        self.target_credential_store = TargetCredentialMapStore()
        self.snmp_credential_store = None
        self.active_conns = ActiveConnectionRegistry()

        self.setWindowTitle(f"Network Toolbelt v{APP_VERSION} (PySide6)")
        self.resize(1350, 850)
        self.setMinimumSize(1100, 750)

        self.container = QStackedWidget()
        self.setCentralWidget(self.container)

        self.frames = {}
        self._init_pages()
        self._setup_menu()

        self.statusBar().showMessage(f"Network Toolbelt v{APP_VERSION} Ready")
        self.show_frame("LandingPage")

    def _init_pages(self):
        page_classes = [
            ("LandingPage", LandingPage),
            ("CredentialManagerLibraryPage", CredentialManagerLibraryPage),
            ("CommandRunnerPage", CommandRunnerPage),
            ("MaintenanceRunnerPage", MaintenanceRunnerStubPage),
            ("ScannerLandingPage", ScannerLandingStubPage),
            ("SnmpCredentialManagerPage", SnmpCredentialManagerStubPage),
            ("SnmpOidScannerPage", SnmpOidScannerStubPage),
            ("DocumentationPage", DocumentationStubPage),
        ]

        for name, cls in page_classes:
            page = cls(parent=self.container, controller=self)
            self.frames[name] = page
            self.container.addWidget(page)

    def show_frame(self, page_name: str):
        current_widget = self.container.currentWidget()
        if (
            isinstance(current_widget, BaseRunnerPage)
            and current_widget.has_active_run()
        ):
            dlg = RunningNavigationDialog(self, current_widget.title_text)
            if dlg.exec() == RunningNavigationDialog.Accepted and dlg.result_data:
                res = dlg.result_data
                current_widget.stop_and_clear_for_navigation(
                    retain_targets=res.get("retain_targets"),
                    retain_credentials=res.get("retain_credentials"),
                )
            else:
                return

        if page_name in self.frames:
            target_widget = self.frames[page_name]
            self.container.setCurrentWidget(target_widget)

    def open_documentation(self, section: str = None):
        self.show_frame("DocumentationPage")

    def _setup_menu(self):
        menubar = self.menuBar()

        # File Menu
        file_menu = menubar.addMenu("File")

        home_action = file_menu.addAction("Home (Dashboard)")
        home_action.triggered.connect(lambda: self.show_frame("LandingPage"))

        file_menu.addSeparator()

        export_menu = file_menu.addMenu("Export Operations")

        zip_action = export_menu.addAction("Bulk Export: Output Directory (ZIP)")
        zip_action.triggered.connect(self.export_zip)

        txt_action = export_menu.addAction("Bulk Export: Output Directory (Unified TXT)")
        txt_action.triggered.connect(self.export_merged_txt)

        file_menu.addSeparator()

        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)

        # Tools Menu
        tools_menu = menubar.addMenu("Tools")

        cmd_action = tools_menu.addAction("Generic Command Runner")
        cmd_action.triggered.connect(lambda: self.show_frame("CommandRunnerPage"))

        maint_action = tools_menu.addAction("Maintenance Pre/Post Runner")
        maint_action.triggered.connect(lambda: self.show_frame("MaintenanceRunnerPage"))

        scan_action = tools_menu.addAction("Network Scanners")
        scan_action.triggered.connect(lambda: self.show_frame("ScannerLandingPage"))

        snmp_scan_action = tools_menu.addAction("SNMP OID Scanner")
        snmp_scan_action.triggered.connect(lambda: self.show_frame("SnmpOidScannerPage"))

        cred_action = tools_menu.addAction("SSH Credential Manager")
        cred_action.triggered.connect(lambda: self.show_frame("CredentialManagerLibraryPage"))

        snmp_cred_action = tools_menu.addAction("SNMP Credential Manager")
        snmp_cred_action.triggered.connect(lambda: self.show_frame("SnmpCredentialManagerPage"))

        # Settings Menu
        settings_menu = menubar.addMenu("Settings")

        out_dir_action = settings_menu.addAction("Choose Base Output Directory...")
        out_dir_action.triggered.connect(self.choose_output_dir)

        parallel_action = settings_menu.addAction("Parallel sessions...")
        parallel_action.triggered.connect(self.open_parallel_sessions_config)

        settings_menu.addSeparator()

        # Help Menu
        help_menu = menubar.addMenu("Help")
        doc_action = help_menu.addAction("Documentation")
        doc_action.triggered.connect(lambda: self.open_documentation())

    def choose_output_dir(self):
        selected = QFileDialog.getExistingDirectory(
            self, "Select Base Output Directory", str(settings.base_output_dir)
        )
        if selected:
            settings.base_output_dir = Path(selected)
            settings.base_output_dir.mkdir(exist_ok=True)
            QMessageBox.information(
                self, "Directory Updated", f"Output directory set to:\n{settings.base_output_dir}"
            )

    def open_parallel_sessions_config(self):
        dlg = ParallelSessionsDialog(self)
        dlg.exec()

    def export_zip(self):
        if not settings.base_output_dir.exists() or not any(settings.base_output_dir.iterdir()):
            QMessageBox.information(self, "Export ZIP", "Output directory is empty or missing.")
            return

        reply = QMessageBox.question(
            self,
            "Export Warning",
            "Security Warning: The output folder may contain sensitive data.\n\nExport folder to ZIP?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Output as ZIP",
            str(settings.base_output_dir / f"NetworkToolbelt_Export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"),
            "ZIP files (*.zip)",
        )

        if not save_path:
            return

        import zipfile
        try:
            with zipfile.ZipFile(save_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(settings.base_output_dir):
                    for f in files:
                        fpath = Path(root) / f
                        arcname = fpath.relative_to(settings.base_output_dir)
                        zf.write(fpath, arcname)
            QMessageBox.information(self, "Success", f"Output exported successfully to:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create ZIP:\n{str(e)}")

    def export_merged_txt(self):
        if not settings.base_output_dir.exists() or not any(settings.base_output_dir.iterdir()):
            QMessageBox.information(self, "Export Merged TXT", "Output directory is empty or missing.")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Merged TXT",
            str(settings.base_output_dir / f"NetworkToolbelt_Merged_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"),
            "Text files (*.txt)",
        )

        if not save_path:
            return

        try:
            with open(save_path, "w", encoding="utf-8") as out:
                out.write("===== NETWORK TOOLBELT MERGED OUTPUT =====\n\n")
                for root, dirs, files in os.walk(settings.base_output_dir):
                    for f in files:
                        if f.endswith((".txt", ".csv", ".log")):
                            fpath = Path(root) / f
                            rel_path = fpath.relative_to(settings.base_output_dir)
                            out.write(f"##### BEGIN {rel_path} #####\n")
                            out.write(fpath.read_text(encoding="utf-8", errors="replace"))
                            out.write(f"\n##### END {rel_path} #####\n\n")
            QMessageBox.information(self, "Success", f"Merged TXT exported successfully to:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create Merged TXT:\n{str(e)}")
