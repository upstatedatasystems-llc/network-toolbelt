"""Qt Signal Bridge to connect background thread events to PySide6 UI thread."""

from PySide6.QtCore import QObject, Signal


class UIEventBridge(QObject):
    # Generic event signal matching legacy queue event vocabulary (event_type, args)
    event_signal = Signal(str, object)

    # Specific convenience signals
    log_exec_signal = Signal(str)
    log_session_signal = Signal(str)
    set_buttons_signal = Signal(bool, bool)
    clear_logs_signal = Signal()
    status_update_signal = Signal(str)
    progress_update_signal = Signal(float)
    warning_banner_signal = Signal(str)
    mode_label_signal = Signal(str, str)

    def dispatch(self, event_type: str, *args):
        """Emit generic event signal for main thread handling."""
        self.event_signal.emit(event_type, args)
