"""The Security view (Phase 4).

A defensive dashboard: a posture summary, a risk-sorted list of per-network
findings (score + anomaly badges), a live alerts feed (new/lost/changed/
evil-twin), and a detail pane explaining why a network was flagged.

Read-only and presentation-only: it consumes Findings from ``threats`` and
Alerts from a ``SecurityMonitor`` via ``update_view``.
"""
from __future__ import annotations

import time

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QScrollArea,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from . import threats
from .theme import Palette

FindRole = Qt.UserRole + 21
_HEADERS = ["Network", "Score", "Issues"]


def sev_color(sev: str, pal: Palette) -> str:
    return {"critical": pal.bad, "warn": pal.warn, "info": pal.accent, "ok": pal.good}.get(sev, pal.text_dim)


def _fmt_ago(t: float, now: float) -> str:
    s = max(0, int(now - t))
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    return f"{s // 3600}h ago"


class FindingsModel(QAbstractTableModel):
    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.pal = pal
        self._rows: list[threats.Finding] = []

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal

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
        f = self._rows[index.row()]
        col = index.column()
        if role == FindRole:
            return f
        if role == Qt.DisplayRole:
            if col == 0:
                return f.label
            if col == 1:
                return str(f.score)
            if col == 2:
                return ", ".join(f.badges) if f.badges else "—"
        if role == Qt.ForegroundRole and col in (0, 1):
            return QColor(sev_color(f.severity, self.pal))
        if role == Qt.TextAlignmentRole and col == 1:
            return int(Qt.AlignCenter)
        return None

    def set_findings(self, findings: list[threats.Finding]) -> None:
        self.beginResetModel()
        self._rows = findings
        self.endResetModel()

    def finding_at(self, row: int):
        return self._rows[row] if 0 <= row < len(self._rows) else None


def _kpi(title: str) -> tuple[QFrame, QLabel]:
    card = QFrame(); card.setObjectName("card")
    lay = QVBoxLayout(card); lay.setContentsMargins(14, 10, 14, 10); lay.setSpacing(2)
    val = QLabel("—"); val.setObjectName("kpiValue"); lay.addWidget(val)
    lbl = QLabel(title); lbl.setObjectName("kpiLabel"); lay.addWidget(lbl)
    return card, val


class SecurityView(QWidget):
    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("root")
        self.pal = pal

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 10)
        outer.setSpacing(10)

        # posture header
        head = QHBoxLayout(); head.setSpacing(12)
        self.kpi_score_card, self.kpi_score = _kpi("Posture score")
        self.kpi_threat_card, self.kpi_threat = _kpi("Threats")
        self.kpi_warn_card, self.kpi_warn = _kpi("Warnings")
        self.kpi_total_card, self.kpi_total = _kpi("Networks")
        for c in (self.kpi_score_card, self.kpi_threat_card, self.kpi_warn_card, self.kpi_total_card):
            head.addWidget(c)
        head.addStretch(1)
        outer.addLayout(head)

        # body: findings | (alerts over detail)
        self.model = FindingsModel(pal, self)
        self.table = QTableView(); self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Stretch)
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.selectionModel().selectionChanged.connect(self._on_select)

        right = QSplitter(Qt.Vertical)
        # alerts feed
        alerts_card = QFrame(); alerts_card.setObjectName("card")
        al = QVBoxLayout(alerts_card); al.setContentsMargins(12, 10, 12, 10)
        at = QLabel("Alerts"); at.setObjectName("h2"); al.addWidget(at)
        self.alerts_scroll = QScrollArea(); self.alerts_scroll.setWidgetResizable(True)
        self.alerts_scroll.setFrameShape(QFrame.NoFrame)
        # the scroll viewport defaults to the white "base" colour — make the
        # whole feed transparent so the card background shows through
        self.alerts_scroll.setStyleSheet("background: transparent;")
        self.alerts_scroll.viewport().setStyleSheet("background: transparent;")
        self.alerts_body = QLabel("No alerts yet."); self.alerts_body.setObjectName("muted")
        self.alerts_body.setStyleSheet("background: transparent;")
        self.alerts_body.setWordWrap(True); self.alerts_body.setTextFormat(Qt.RichText)
        self.alerts_body.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.alerts_scroll.setWidget(self.alerts_body)
        al.addWidget(self.alerts_scroll, 1)
        # finding detail
        detail_card = QFrame(); detail_card.setObjectName("detailPanel")
        dl = QVBoxLayout(detail_card); dl.setContentsMargins(16, 14, 16, 14); dl.setSpacing(8)
        self.detail_title = QLabel("Select a network"); self.detail_title.setObjectName("h1")
        self.detail_title.setWordWrap(True)
        self.detail_sub = QLabel(""); self.detail_sub.setObjectName("muted"); self.detail_sub.setWordWrap(True)
        self.detail_body = QLabel(""); self.detail_body.setObjectName("muted")
        self.detail_body.setWordWrap(True); self.detail_body.setTextFormat(Qt.RichText)
        self.detail_body.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        dl.addWidget(self.detail_title); dl.addWidget(self.detail_sub); dl.addWidget(self.detail_body, 1)

        right.addWidget(alerts_card)
        right.addWidget(detail_card)
        right.setStretchFactor(0, 3)
        right.setStretchFactor(1, 4)

        split = QSplitter(Qt.Horizontal)
        split.addWidget(self.table)
        split.addWidget(right)
        split.setStretchFactor(0, 5)
        split.setStretchFactor(1, 4)
        split.setChildrenCollapsible(False)
        outer.addWidget(split, 1)

    # -- palette -----------------------------------------------------------
    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        self.model.set_palette(pal)
        self.table.viewport().update()
        self._render_alerts(self._last_alerts)
        f = self._selected_finding()
        self._render_detail(f)

    # -- data --------------------------------------------------------------
    _last_alerts: list = []

    def update_view(self, aps, monitor) -> None:
        keep = self._selected_bssid()
        findings = threats.analyze(aps)
        self.model.set_findings(findings)
        post = threats.posture(findings)
        self.kpi_score.setText("—" if post["overall"] is None else str(post["overall"]))
        self.kpi_score.setStyleSheet(f"color:{sev_color(post['worst'], self.pal)}")
        self.kpi_threat.setText(str(post["critical"]))
        self.kpi_warn.setText(str(post["warn"]))
        self.kpi_total.setText(str(post["total"]))

        self._last_alerts = monitor.recent(60)
        self._render_alerts(self._last_alerts)

        if keep and self._select_bssid(keep):
            pass
        elif self.model.rowCount():
            self.table.selectRow(0)
        self._render_detail(self._selected_finding())

    def _render_alerts(self, alerts) -> None:
        if not alerts:
            self.alerts_body.setText("<i>No alerts yet — all quiet.</i>")
            return
        now = time.time()
        rows = []
        for a in alerts:
            col = sev_color(a.severity, self.pal)
            rows.append(
                f"<div style='margin-bottom:7px'>"
                f"<span style='color:{col}'>●</span> "
                f"<span style='color:{self.pal.text_dim}'>{_fmt_ago(a.time, now)}</span><br>"
                f"<span style='color:{self.pal.text}'>{a.message}</span></div>")
        self.alerts_body.setText("".join(rows))

    def _render_detail(self, f) -> None:
        if f is None:
            self.detail_title.setText("Select a network")
            self.detail_sub.setText("")
            self.detail_body.setText("")
            return
        col = sev_color(f.severity, self.pal)
        self.detail_title.setText(f.label)
        self.detail_sub.setText(
            f"<span style='color:{col}'>●</span> {f.severity.upper()} · score {f.score}/100 · {f.bssid}")
        badge_html = " ".join(
            f"<span style='color:{col}'>[{b}]</span>" for b in f.badges) or ""
        reasons = "".join(f"<div style='margin-bottom:5px'>• {r}</div>" for r in f.reasons)
        self.detail_body.setText(
            (f"<div style='margin-bottom:8px'>{badge_html}</div>" if badge_html else "") + reasons)

    # -- selection ---------------------------------------------------------
    def _selected_finding(self):
        idxs = self.table.selectionModel().selectedRows()
        return idxs[0].data(FindRole) if idxs else None

    def _selected_bssid(self):
        f = self._selected_finding()
        return f.bssid if f else None

    def _select_bssid(self, bssid: str) -> bool:
        for r in range(self.model.rowCount()):
            if self.model.index(r, 0).data(FindRole).bssid == bssid:
                self.table.selectRow(r)
                return True
        return False

    def _on_select(self, *_a) -> None:
        self._render_detail(self._selected_finding())
