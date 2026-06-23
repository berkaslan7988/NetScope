"""Run LAN discovery + port scans off the GUI thread.

A /24 ping sweep takes seconds, so it must never touch the Qt event loop.
Requests are delivered to the worker via cross-thread signals (Qt queues them
onto the worker thread automatically), and results come back the same way.
"""
from __future__ import annotations

from PySide6.QtCore import QObject, QThread, Signal, Slot

from ..lan import LanScannerError, get_lan_scanner


class _LanWorker(QObject):
    progress = Signal(int, int)
    discovered = Signal(list)        # list[Device]
    ports_done = Signal(str, list)   # ip, list[PortResult]
    failed = Signal(str)

    def __init__(self, force_mock: bool = False) -> None:
        super().__init__()
        self._scanner = get_lan_scanner(force_mock=force_mock)

    @property
    def scanner_name(self) -> str:
        return self._scanner.name

    @property
    def is_real(self) -> bool:
        return self._scanner.is_real

    def subnet(self) -> str:
        try:
            return self._scanner.subnet()
        except Exception:
            return "—"

    @Slot()
    def do_discover(self) -> None:
        try:
            devices = self._scanner.discover(
                progress=lambda d, t: self.progress.emit(d, t)
            )
        except LanScannerError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:  # never let the worker crash the app
            self.failed.emit(f"Discovery failed: {exc}")
        else:
            self.discovered.emit(devices)

    @Slot(str)
    def do_ports(self, ip: str) -> None:
        try:
            results = self._scanner.scan_ports(ip)
        except Exception as exc:
            self.failed.emit(f"Port scan failed: {exc}")
        else:
            self.ports_done.emit(ip, results)


class LanController(QObject):
    progress = Signal(int, int)
    results = Signal(list)
    ports = Signal(str, list)
    error = Signal(str)
    busy_changed = Signal(bool)
    ports_busy_changed = Signal(bool)

    _req_discover = Signal()
    _req_ports = Signal(str)

    def __init__(self, force_mock: bool = False, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread = QThread()
        self._worker = _LanWorker(force_mock=force_mock)
        self._worker.moveToThread(self._thread)
        # cross-thread request signals -> worker slots (auto-queued)
        self._req_discover.connect(self._worker.do_discover)
        self._req_ports.connect(self._worker.do_ports)
        self._worker.progress.connect(self.progress)
        self._worker.discovered.connect(self._on_discovered)
        self._worker.ports_done.connect(self._on_ports)
        self._worker.failed.connect(self._on_failed)
        self._busy = False
        self._ports_busy = False
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

    def subnet(self) -> str:
        return self._worker.subnet()

    def discover(self) -> None:
        if self._busy:
            return
        self._busy = True
        self.busy_changed.emit(True)
        self._req_discover.emit()

    def scan_ports(self, ip: str) -> None:
        if self._ports_busy:
            return
        self._ports_busy = True
        self.ports_busy_changed.emit(True)
        self._req_ports.emit(ip)

    def _on_discovered(self, devices) -> None:
        self._busy = False
        self.busy_changed.emit(False)
        self.results.emit(devices)

    def _on_ports(self, ip, results) -> None:
        self._ports_busy = False
        self.ports_busy_changed.emit(False)
        self.ports.emit(ip, results)

    def _on_failed(self, msg: str) -> None:
        self._busy = False
        self._ports_busy = False
        self.busy_changed.emit(False)
        self.ports_busy_changed.emit(False)
        self.error.emit(msg)

    def shutdown(self) -> None:
        self._thread.quit()
        self._thread.wait(3000)
