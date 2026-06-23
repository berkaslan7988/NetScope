"""The History view (Phase 5).

Surfaces the persistent SQLite store: lifetime stats, every network ever seen
(with first/last seen and how often), and one-click CSV / PDF export. The view
is presentation-only — it shows data handed to it and emits export/refresh
signals that MainWindow services (it owns the store + live findings).
"""
from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ..report import fmt_ts
from .theme import Palette

_HEADERS = ["SSID", "BSSID", "Security", "Band", "Ch", "Vendor", "First seen", "Last seen", "Seen"]


class HistoryModel(QAbstractTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[dict] = []

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(_HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return _HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        n = self._rows[index.row()]
        col = index.column()
        if role == Qt.DisplayRole:
            return [
                n.get("ssid") or "‹hidden›", n.get("bssid"), n.get("security"),
                n.get("band"), str(n.get("channel") or "—"), n.get("vendor") or "—",
                fmt_ts(n.get("first_seen")), fmt_ts(n.get("last_seen")),
                str(n.get("times_seen") or 0),
            ][col]
        if role == Qt.TextAlignmentRole and col in (4, 8):
            return int(Qt.AlignCenter)
        return None

    def set_rows(self, rows: list[dict]) -> None:
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()


def _kpi(title: str) -> tuple[QFrame, QLabel]:
    card = QFrame(); card.setObjectName("card")
    lay = QVBoxLayout(card); lay.setContentsMargins(14, 10, 14, 10); lay.setSpacing(2)
    val = QLabel("—"); val.setObjectName("kpiValue"); lay.addWidget(val)
    lbl = QLabel(title); lbl.setObjectName("kpiLabel"); lay.addWidget(lbl)
    return card, val


class HistoryView(QWidget):
    refreshRequested = Signal()
    exportCsvRequested = Signal()
    exportPdfRequested = Signal()

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("root")
        self.pal = pal

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 10)
        outer.setSpacing(10)

        head = QHBoxLayout(); head.setSpacing(12)
        self.kpi_total_card, self.kpi_total = _kpi("Networks ever")
        self.kpi_new_card, self.kpi_new = _kpi("New today")
        self.kpi_active_card, self.kpi_active = _kpi("Active (1h)")
        self.kpi_alerts_card, self.kpi_alerts = _kpi("Alerts logged")
        for c in (self.kpi_total_card, self.kpi_new_card, self.kpi_active_card, self.kpi_alerts_card):
            head.addWidget(c)
        head.addStretch(1)
        self.refresh_btn = QPushButton("↻ Refresh")
        self.refresh_btn.clicked.connect(self.refreshRequested)
        self.csv_btn = QPushButton("Export CSV")
        self.csv_btn.clicked.connect(self.exportCsvRequested)
        self.pdf_btn = QPushButton("Export PDF"); self.pdf_btn.setObjectName("primary")
        self.pdf_btn.clicked.connect(self.exportPdfRequested)
        for b in (self.refresh_btn, self.csv_btn, self.pdf_btn):
            head.addWidget(b)
        outer.addLayout(head)

        self.model = HistoryModel(self)
        self.table = QTableView(); self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(30)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(False)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Stretch)
        for c in range(1, len(_HEADERS)):
            hh.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        outer.addWidget(self.table, 1)

        self.status = QLabel(""); self.status.setObjectName("muted")
        outer.addWidget(self.status)

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        self.table.viewport().update()

    def set_summary(self, s: dict) -> None:
        self.kpi_total.setText(str(s.get("total", 0)))
        self.kpi_new.setText(str(s.get("new_today", 0)))
        self.kpi_active.setText(str(s.get("active_hour", 0)))
        self.kpi_alerts.setText(str(s.get("alerts", 0)))

    def set_networks(self, rows: list[dict]) -> None:
        self.model.set_rows(rows)

    def flash(self, msg: str) -> None:
        self.status.setText(msg)
