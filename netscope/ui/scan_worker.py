"""Run scans off the GUI thread.

A WiFi scan can take a couple of seconds (netsh shells out), and blocking the
Qt event loop would freeze the window. So every scan runs in a QThread worker
that emits either a result list or a friendly error string. The window just
listens to signals — it never touches the scanner directly.
"""
from __future__ import annotations

from PySide6.QtCore import QObject, QThread, Signal, Slot

from ..scanners import ScannerError, get_scanner


class ScanWorker(QObject):
    """Lives on a background QThread; performs one scan per `run()` call."""

    finished = Signal(list)   # list[AccessPoint]
    failed = Signal(str)      # human-readable error message

    def __init__(self, force_mock: bool = False) -> None:
        super().__init__()
        self._scanner = get_scanner(force_mock=force_mock)

    @property
    def scanner_name(self) -> str:
        return self._scanner.name

    @property
    def is_real(self) -> bool:
        return self._scanner.is_real

    @Slot()
    def run(self) -> None:
        try:
            aps = self._scanner.scan()
        except ScannerError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:  # never let a worker crash take down the app
            self.failed.emit(f"Unexpected error: {exc}")
        else:
            self.finished.emit(aps)


class ScanController(QObject):
    """Owns the worker + its thread and serializes scan requests.

    `request_scan()` is safe to call from the UI thread at any time; if a scan
    is already running the call is ignored (no overlapping netsh processes).
    """

    results = Signal(list)
    error = Signal(str)
    busy_changed = Signal(bool)

    def __init__(self, force_mock: bool = False, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread = QThread()
        self._worker = ScanWorker(force_mock=force_mock)
        self._worker.moveToThread(self._thread)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._busy = False
        self._thread.start()

    @property
    def scanner_name(self) -> str:
        return self._worker.scanner_name

    @property
    def is_real(self) -> bool:
        return self._worker.is_real

    @property
    def busy(self) -> bool:
        return self._busy

    def request_scan(self) -> None:
        if self._busy:
            return
        self._busy = True
        self.busy_changed.emit(True)
        # Queued invocation hops onto the worker thread.
        from PySide6.QtCore import QMetaObject, Qt
        QMetaObject.invokeMethod(self._worker, "run", Qt.QueuedConnection)

    def _on_finished(self, aps) -> None:
        self._busy = False
        self.busy_changed.emit(False)
        self.results.emit(aps)

    def _on_failed(self, msg: str) -> None:
        self._busy = False
        self.busy_changed.emit(False)
        self.error.emit(msg)

    def shutdown(self) -> None:
        self._thread.quit()
        self._thread.wait(2000)
