"""The NetScope main window — the 'perfect UI' Phase 1 target.

Layout
------
┌───────────────────────────── toolbar ─────────────────────────────┐
│ NetScope   [search]  [band ▾]  [⚠ weak only]  [▶ auto]  [↻ scan]   │
├───────────────┬───────────────────────────────────────────────────┤
│  KPI cards    │                                                    │
│  channel graph│   network table          │     detail panel        │
│               │                          │                         │
├───────────────┴───────────────────────────────────────────────────┤
│ status: scanner · N networks · last scan · busy spinner            │
└────────────────────────────────────────────────────────────────────┘
"""
from __future__ import annotations

import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QFileDialog,
    QSplitter,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ..models import Band
from . import analysis
from .analytics import AnalyticsView
from .history import SignalHistory
from .lan_view import LanView
from .lan_worker import LanController
from .security_view import SecurityView
from .alerts import SecurityMonitor
from .history_view import HistoryView
from . import threats
from ..store import Store
from ..config import Config
from .. import report
from .detail import DetailPanel
from .graph import ChannelGraph
from .scan_worker import ScanController
from .table import (
    ApRole,
    COL_BSSID,
    COL_CHANNEL,
    COL_SECURITY,
    COL_SIGNAL,
    NetworkFilterProxy,
    NetworkTableModel,
    SecurityDelegate,
    SignalDelegate,
)
from .theme import DARK, LIGHT, stylesheet

DEFAULT_INTERVAL_S = 4


def _as_band(data) -> "Band | None":
    """Coerce a combo box's currentData() back to a Band.

    Band is a str-Enum, so Qt stores it in a QVariant as a plain str and hands
    it back as a plain str (losing the enum type). We rebuild the enum from its
    value string; ``None`` (the "All bands" item) passes through unchanged.
    """
    if data is None or isinstance(data, Band):
        return data
    try:
        return Band(data)
    except ValueError:
        return None


def _kpi_card(pal) -> tuple[QFrame, QLabel]:
    card = QFrame()
    card.setObjectName("card")
    lay = QVBoxLayout(card)
    lay.setContentsMargins(14, 12, 14, 12)
    lay.setSpacing(2)
    value = QLabel("—")
    value.setObjectName("kpiValue")
    lay.addWidget(value)
    return card, value


class MainWindow(QMainWindow):
    def __init__(self, force_mock: bool = False) -> None:
        super().__init__()
        self.config = Config()
        self._dark = self.config.get("theme") == "dark"
        self.pal = DARK if self._dark else LIGHT
        self.setWindowTitle("NetScope — Wi-Fi Monitor")
        self.resize(1240, 760)

        self._empty_streak = 0
        self._last_nonempty = 0
        self._current_aps = []
        self.history = SignalHistory()
        self.lan = LanController(force_mock=force_mock)
        from ..lan.traffic import TrafficMonitor
        self._traffic = TrafficMonitor()
        self.security_monitor = SecurityMonitor(
            lost_after=float(self.config.get("lost_after")),
            warn_weak=bool(self.config.get("warn_weak")))
        self.store = Store(self.config.get("db_path"))
        self._apply_retention()
        self.controller = ScanController(force_mock=force_mock)
        self.controller.results.connect(self._on_results)
        self.controller.error.connect(self._on_error)
        self.controller.busy_changed.connect(self._on_busy)

        self._build_toolbar()
        self._build_body()
        self._build_statusbar()
        self.apply_theme()

        # auto-refresh timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.controller.request_scan)

        # apply saved preferences
        self._apply_interval(int(self.config.get("scan_interval")))
        self._show_view(self.config.get("start_view"))
        auto = bool(self.config.get("auto_start"))
        self.auto_btn.setChecked(auto)
        self._set_auto(auto)
        if auto:
            QTimer.singleShot(150, self.controller.request_scan)

    # ------------------------------------------------------------------ UI
    def _build_toolbar(self) -> None:
        tb = self.addToolBar("main")
        tb.setMovable(False)

        brand = QLabel("  NetScope")
        brand.setObjectName("brand")
        tb.addWidget(brand)
        spacer = QLabel("   ")
        tb.addWidget(spacer)

        self.nav_networks = QPushButton("Networks")
        self.nav_networks.setCheckable(True)
        self.nav_networks.setChecked(True)
        self.nav_networks.clicked.connect(lambda: self._show_view("networks"))
        tb.addWidget(self.nav_networks)
        self.nav_analytics = QPushButton("Analytics")
        self.nav_analytics.setCheckable(True)
        self.nav_analytics.clicked.connect(lambda: self._show_view("analytics"))
        tb.addWidget(self.nav_analytics)
        self.nav_lan = QPushButton("LAN")
        self.nav_lan.setCheckable(True)
        self.nav_lan.clicked.connect(lambda: self._show_view("lan"))
        tb.addWidget(self.nav_lan)
        self.nav_security = QPushButton("Security")
        self.nav_security.setCheckable(True)
        self.nav_security.clicked.connect(lambda: self._show_view("security"))
        tb.addWidget(self.nav_security)
        self.nav_history = QPushButton("History")
        self.nav_history.setCheckable(True)
        self.nav_history.clicked.connect(lambda: self._show_view("history"))
        tb.addWidget(self.nav_history)
        tb.addWidget(QLabel("   "))

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search SSID, BSSID or vendor…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(240)
        self.search.textChanged.connect(self._on_search)
        self._act_search = tb.addWidget(self.search)

        self.band_filter = QComboBox()
        self.band_filter.addItem("All bands", None)
        self.band_filter.addItem("2.4 GHz", Band.BAND_2_4)
        self.band_filter.addItem("5 GHz", Band.BAND_5)
        self.band_filter.addItem("6 GHz", Band.BAND_6)
        self.band_filter.currentIndexChanged.connect(self._on_band_filter)
        self._act_band = tb.addWidget(self.band_filter)

        self.weak_btn = QPushButton("⚠ Weak only")
        self.weak_btn.setCheckable(True)
        self.weak_btn.toggled.connect(self._on_weak_toggle)
        self._act_weak = tb.addWidget(self.weak_btn)

        # right-aligned controls
        right = QWidget()
        rlay = QHBoxLayout(right)
        rlay.setContentsMargins(0, 0, 0, 0)
        rlay.addStretch(1)
        tb.addWidget(right)

        self.interval = QComboBox()
        for s in (2, 3, 4, 6, 10):
            self.interval.addItem(f"every {s}s", s)
        self.interval.setCurrentIndex(2)  # 4s
        self.interval.currentIndexChanged.connect(self._on_interval)
        tb.addWidget(self.interval)

        self.auto_btn = QPushButton("⏸ Pause")
        self.auto_btn.setCheckable(True)
        self.auto_btn.setChecked(True)
        self.auto_btn.toggled.connect(self._set_auto)
        tb.addWidget(self.auto_btn)

        self.scan_btn = QPushButton("↻ Scan now")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self.controller.request_scan)
        tb.addWidget(self.scan_btn)

        self.theme_btn = QPushButton("◐ Theme")
        self.theme_btn.clicked.connect(self._toggle_theme)
        tb.addWidget(self.theme_btn)

        self.settings_btn = QPushButton("⚙")
        self.settings_btn.setToolTip("Settings")
        self.settings_btn.clicked.connect(self._open_settings)
        tb.addWidget(self.settings_btn)

    def _build_body(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        outer = QHBoxLayout(root)
        outer.setContentsMargins(14, 14, 14, 10)
        outer.setSpacing(12)

        # --- left column: KPIs + channel graph ---
        left = QWidget()
        left.setMaximumWidth(310)
        left.setMinimumWidth(270)
        lcol = QVBoxLayout(left)
        lcol.setContentsMargins(0, 0, 0, 0)
        lcol.setSpacing(12)

        kpi_row1 = QHBoxLayout()
        kpi_row2 = QHBoxLayout()
        self.kpi_total_card, self.kpi_total = _kpi_card(self.pal)
        self.kpi_weak_card, self.kpi_weak = _kpi_card(self.pal)
        self.kpi_chan_card, self.kpi_chan = _kpi_card(self.pal)
        self.kpi_band_card, self.kpi_band = _kpi_card(self.pal)
        for card, title in (
            (self.kpi_total_card, "Networks"),
            (self.kpi_weak_card, "Weak / open"),
            (self.kpi_chan_card, "Best 2.4 ch"),
            (self.kpi_band_card, "Bands"),
        ):
            lbl = QLabel(title)
            lbl.setObjectName("kpiLabel")
            card.layout().addWidget(lbl)
        kpi_row1.addWidget(self.kpi_total_card)
        kpi_row1.addWidget(self.kpi_weak_card)
        kpi_row2.addWidget(self.kpi_chan_card)
        kpi_row2.addWidget(self.kpi_band_card)
        lcol.addLayout(kpi_row1)
        lcol.addLayout(kpi_row2)

        graph_card = QFrame()
        graph_card.setObjectName("card")
        glay = QVBoxLayout(graph_card)
        glay.setContentsMargins(14, 12, 14, 12)
        ghead = QHBoxLayout()
        gtitle = QLabel("Channels")
        gtitle.setObjectName("h2")
        ghead.addWidget(gtitle)
        ghead.addStretch(1)
        self.graph_band = QComboBox()
        self.graph_band.addItem("2.4 GHz", Band.BAND_2_4)
        self.graph_band.addItem("5 GHz", Band.BAND_5)
        self.graph_band.currentIndexChanged.connect(self._on_graph_band)
        ghead.addWidget(self.graph_band)
        glay.addLayout(ghead)
        self.graph = ChannelGraph(self.pal)
        glay.addWidget(self.graph)
        lcol.addWidget(graph_card, 1)

        # --- center: table ---
        self.model = NetworkTableModel(self)
        self.proxy = NetworkFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(COL_SIGNAL, Qt.DescendingOrder)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(38)
        self.table.setEditTriggers(QTableView.NoEditTriggers)

        self.sig_delegate = SignalDelegate(self.pal, self.table)
        self.sec_delegate = SecurityDelegate(self.pal, self.table)
        self.table.setItemDelegateForColumn(COL_SIGNAL, self.sig_delegate)
        self.table.setItemDelegateForColumn(COL_SECURITY, self.sec_delegate)

        hh = self.table.horizontalHeader()
        hh.setMinimumSectionSize(46)
        hh.setSectionResizeMode(QHeaderView.Interactive)
        # SSID stretches to fill leftover space but the BSSID column can be the
        # one that yields, so the network name never collapses to nothing.
        hh.setStretchLastSection(True)
        from .table import COL_SSID, COL_VENDOR, COL_BAND
        self.table.setColumnWidth(COL_SSID, 168)
        self.table.setColumnWidth(COL_VENDOR, 96)
        self.table.setColumnWidth(COL_BAND, 70)
        self.table.setColumnWidth(COL_CHANNEL, 48)
        self.table.setColumnWidth(COL_SECURITY, 116)
        self.table.setColumnWidth(COL_SIGNAL, 188)
        self.table.setColumnWidth(COL_BSSID, 150)
        self.table.selectionModel().selectionChanged.connect(self._on_select)

        # --- right: detail panel ---
        self.detail = DetailPanel(self.pal)
        self.detail.setMinimumWidth(270)
        self.detail.setMaximumWidth(330)

        split = QSplitter(Qt.Horizontal)
        split.addWidget(left)
        split.addWidget(self.table)
        split.addWidget(self.detail)
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setStretchFactor(2, 0)
        split.setChildrenCollapsible(False)
        outer.addWidget(split)

        self.networks_page = root
        self.analytics = AnalyticsView(self.pal)
        self.lan_view = LanView(self.pal)
        self.security_view = SecurityView(self.pal)
        self.history_view = HistoryView(self.pal)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.networks_page)
        self.stack.addWidget(self.analytics)
        self.stack.addWidget(self.lan_view)
        self.stack.addWidget(self.security_view)
        self.stack.addWidget(self.history_view)
        self.setCentralWidget(self.stack)

        self.history_view.refreshRequested.connect(self._refresh_history)
        self.history_view.exportCsvRequested.connect(self._export_csv)
        self.history_view.exportPdfRequested.connect(self._export_pdf)
        self.lan.results.connect(lambda devs: self.store.record_devices(devs))

        # LAN wiring
        self.lan_view.set_subnet(self.lan.subnet())
        self.lan_view.discoverRequested.connect(self.lan.discover)
        self.lan_view.portsRequested.connect(self.lan.scan_ports)
        self.lan.results.connect(self.lan_view.set_devices)
        self.lan.ports.connect(self.lan_view.set_ports)
        self.lan.progress.connect(self.lan_view.set_progress)
        self.lan.busy_changed.connect(self.lan_view.set_busy)
        self.lan.error.connect(lambda m: self.lan_view.progress.setText(f"⚠ {m}"))
        self._lan_discovered_once = False
        # throughput timer (only runs while the LAN view is visible)
        self._bw_timer = QTimer(self)
        self._bw_timer.timeout.connect(self._poll_traffic)

    def _build_statusbar(self) -> None:
        sb = self.statusBar()
        self.status_scanner = QLabel("")
        self.status_count = QLabel("")
        self.status_scan = QLabel("")
        self.status_busy = QLabel("")
        sb.addWidget(self.status_scanner)
        sb.addPermanentWidget(self.status_busy)
        sb.addPermanentWidget(self.status_count)
        sb.addPermanentWidget(self.status_scan)
        tag = "" if self.controller.is_real else "  ·  mock data"
        self.status_scanner.setText(f"  Scanner: {self.controller.scanner_name}{tag}")

    # -------------------------------------------------------------- theming
    def apply_theme(self) -> None:
        self.setStyleSheet(stylesheet(self.pal))
        self.graph.set_palette(self.pal)
        self.detail.set_palette(self.pal)
        if hasattr(self, 'analytics'):
            self.analytics.set_palette(self.pal)
        if hasattr(self, 'lan_view'):
            self.lan_view.set_palette(self.pal)
        if hasattr(self, 'security_view'):
            self.security_view.set_palette(self.pal)
        if hasattr(self, 'history_view'):
            self.history_view.set_palette(self.pal)
        self.sig_delegate.pal = self.pal
        self.sec_delegate.pal = self.pal
        self.table.viewport().update()

    def _toggle_theme(self) -> None:
        self._dark = not self._dark
        self.pal = DARK if self._dark else LIGHT
        self.apply_theme()

    def _show_view(self, view: str) -> None:
        """Switch between the Networks, Analytics and LAN views."""
        pages = {"networks": self.networks_page, "analytics": self.analytics,
                 "lan": self.lan_view, "security": self.security_view,
                 "history": self.history_view}
        self.stack.setCurrentWidget(pages.get(view, self.networks_page))
        self.nav_networks.setChecked(view == "networks")
        self.nav_analytics.setChecked(view == "analytics")
        self.nav_lan.setChecked(view == "lan")
        self.nav_security.setChecked(view == "security")
        self.nav_history.setChecked(view == "history")
        # the Wi-Fi table filters only make sense on the Networks view
        for act in (self._act_search, self._act_band, self._act_weak):
            act.setVisible(view == "networks")
        if view == "analytics":
            self.analytics.update_view(self._current_aps, self.history)
        if view == "lan":
            self._poll_traffic()
            self._bw_timer.start(2000)
            if not self._lan_discovered_once:
                self._lan_discovered_once = True
                self.lan.discover()
        else:
            self._bw_timer.stop()
        if view == "history":
            self._refresh_history()

    def _poll_traffic(self) -> None:
        down, up = self._traffic.poll()
        self.lan_view.set_throughput(down, up, self._traffic.down, self._traffic.up)

    # ------------------------------------------------------------- settings
    def _apply_retention(self) -> None:
        days = int(self.config.get("retention_days"))
        if days > 0:
            self.store.prune(time.time() - days * 86400)

    def _apply_interval(self, seconds: int) -> None:
        idx = self.interval.findData(seconds)
        if idx < 0:
            self.interval.addItem(f"every {seconds}s", seconds)
            idx = self.interval.findData(seconds)
        self.interval.setCurrentIndex(idx)
        if getattr(self, "_timer", None) and self._timer.isActive():
            self._timer.start(self._interval_ms())

    def _open_settings(self) -> None:
        from pathlib import Path
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        from .settings_dialog import SettingsDialog

        def clear_history() -> None:
            self.store.clear_history()
            self._refresh_history()

        def open_folder() -> None:
            folder = str(Path(self.config.get("db_path")).parent)
            QDesktopServices.openUrl(QUrl.fromLocalFile(folder))

        dlg = SettingsDialog(self.config, self,
                             on_clear_history=clear_history, on_open_folder=open_folder)
        if dlg.exec():
            self._apply_config(dlg.values())

    def _apply_config(self, values: dict) -> None:
        old_db = self.config.get("db_path")
        self.config.update(values)
        self.config.save()
        want_dark = self.config.get("theme") == "dark"
        if want_dark != self._dark:
            self._dark = want_dark
            self.pal = DARK if want_dark else LIGHT
            self.apply_theme()
        self._apply_interval(int(self.config.get("scan_interval")))
        self.security_monitor._lost_after = float(self.config.get("lost_after"))
        self.security_monitor.warn_weak = bool(self.config.get("warn_weak"))
        self._apply_retention()
        if self.config.get("db_path") != old_db:
            self.status_scanner.setText(
                "  Settings saved — restart to use the new database location.")

    def _refresh_history(self) -> None:
        self.history_view.set_summary(self.store.summary())
        self.history_view.set_networks(self.store.networks())

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export networks as CSV", "netscope-networks.csv", "CSV files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(report.build_csv(self.store.networks()))
            self.history_view.flash(f"Saved CSV → {path}")
        except OSError as exc:
            self.history_view.flash(f"⚠ Could not save: {exc}")

    def _export_pdf(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export report as PDF", "netscope-report.pdf", "PDF files (*.pdf)")
        if not path:
            return
        findings = threats.analyze(self._current_aps)
        html = report.build_html_report(
            summary=self.store.summary(),
            posture=threats.posture(findings),
            findings=findings,
            networks=self.store.networks(),
            alerts=self.store.recent_alerts(),
        )
        try:
            report.write_pdf(html, path)
            self.history_view.flash(f"Saved PDF → {path}")
        except Exception as exc:
            self.history_view.flash(f"⚠ Could not export PDF: {exc}")

    # --------------------------------------------------------------- events
    def _set_auto(self, on: bool) -> None:
        self.auto_btn.setText("⏸ Pause" if on else "▶ Resume")
        if on:
            self._timer.start(self._interval_ms())
            self.controller.request_scan()
        else:
            self._timer.stop()

    def _interval_ms(self) -> int:
        return int(self.interval.currentData()) * 1000

    def _on_interval(self) -> None:
        if self._timer.isActive():
            self._timer.start(self._interval_ms())

    def _on_search(self, text: str) -> None:
        self.proxy.set_text(text)

    def _on_band_filter(self) -> None:
        self.proxy.set_band(_as_band(self.band_filter.currentData()))

    def _on_weak_toggle(self, on: bool) -> None:
        self.proxy.set_weak_only(on)

    def _on_graph_band(self) -> None:
        self.graph.set_band(_as_band(self.graph_band.currentData()) or Band.BAND_2_4)

    def _on_busy(self, busy: bool) -> None:
        self.status_busy.setText("scanning…" if busy else "")
        self.scan_btn.setEnabled(not busy)

    def _on_error(self, msg: str) -> None:
        self.status_scanner.setText(f"  ⚠ {msg}")

    def _on_results(self, aps) -> None:
        # A real scan can momentarily return nothing while the adapter refreshes
        # its cache. Ignore a few such blips so the list doesn't flash empty;
        # only commit an empty result once it persists (e.g. Wi-Fi turned off).
        if not aps and getattr(self, "_last_nonempty", 0) and self._empty_streak < 3:
            self._empty_streak += 1
            return
        self._empty_streak = 0 if aps else self._empty_streak + 1
        if aps:
            self._last_nonempty = 1

        keep = self._selected_bssid()
        self._current_aps = aps
        self.history.record(aps)
        self.model.update(aps)
        self.detail.record(aps)
        self.graph.set_data(aps)
        self.analytics.update_view(aps, self.history)
        if self.config.get("alerts_enabled"):
            produced = self.security_monitor.feed(aps)
            self.store.record_alerts(produced)
        self.security_view.update_view(aps, self.security_monitor)
        self.store.record_scan(aps)

        self.kpi_total.setText(str(len(aps)))
        self.kpi_weak.setText(str(analysis.weak_count(aps)))
        best = analysis.best_24_channel(aps)
        self.kpi_chan.setText(str(best) if best else "—")
        self.kpi_band.setText(str(len({a.band for a in aps})))

        self.status_count.setText(f"{len(aps)} networks  ")
        self.status_scan.setText(time.strftime("last scan %H:%M:%S  "))
        tag = "" if self.controller.is_real else "  ·  mock data"
        self.status_scanner.setText(f"  Scanner: {self.controller.scanner_name}{tag}")

        # Pin the detail panel to the same network across refreshes: re-select
        # by BSSID rather than row index, so sort/insert/remove can't move it.
        if keep and self._select_bssid(keep):
            pass
        elif not self.table.selectionModel().hasSelection() and self.proxy.rowCount():
            self.table.selectRow(0)
        self._refresh_detail()

    def _on_select(self, *_args) -> None:
        self._refresh_detail()

    def _selected_bssid(self) -> "str | None":
        idxs = self.table.selectionModel().selectedRows()
        if idxs:
            ap = idxs[0].data(ApRole)
            return ap.bssid if ap else None
        return None

    def _select_bssid(self, bssid: str) -> bool:
        """Select the row for a BSSID if it is currently visible. Returns hit."""
        for r in range(self.proxy.rowCount()):
            ap = self.proxy.index(r, 0).data(ApRole)
            if ap is not None and ap.bssid == bssid:
                if self.table.selectionModel().selectedRows()[:1] != [self.proxy.index(r, 0)]:
                    self.table.selectRow(r)
                return True
        return False

    def _refresh_detail(self) -> None:
        idxs = self.table.selectionModel().selectedRows()
        if not idxs:
            self.detail.show_ap(None)
            return
        ap = idxs[0].data(ApRole)
        self.detail.show_ap(ap)

    def closeEvent(self, event) -> None:
        self._timer.stop()
        self._bw_timer.stop()
        self.controller.shutdown()
        self.lan.shutdown()
        self.store.close()
        super().closeEvent(event)
