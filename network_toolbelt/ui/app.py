"""PySide6 Application Bootstrap for Network Toolbelt."""

import sys
from pathlib import Path
from PySide6.QtWidgets import QApplication
from network_toolbelt.ui.main_window import MainWindow


def run_app():
    app = QApplication(sys.argv)
    app.setApplicationName("Network Toolbelt")

    # Load QSS stylesheet
    style_path = Path(__file__).parent / "styles" / "app.qss"
    if style_path.exists():
        qss = style_path.read_text(encoding="utf-8")
        app.setStyleSheet(qss)

    window = MainWindow()
    window.show()

    return app.exec()
