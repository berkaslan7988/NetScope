"""Right-hand detail panel for the selected access point.

Shows everything we know about one BSSID in a calm, readable layout, plus a
small live signal sparkline so you can watch a network's strength move as you
walk around. The sparkline history is kept per-BSSID so switching selection
doesn't lose the trace.
"""
from __future__ import annotations

from collections import deque

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ..models import AccessPoint
from .theme import Palette, security_color, signal_color


class Sparkline(QWidget):
    """Tiny line chart of recent signal % for the selected network."""

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.pal = pal
        self._pts: deque[int] = deque(maxlen=60)
        self.setMinimumHeight(56)

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        self.update()

    def reset(self, history: deque[int] | None = None) -> None:
        self._pts = deque(history or [], maxlen=60)
        self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        r = QRectF(2, 4, self.width() - 4, self.height() - 8)
        p.setPen(QPen(QColor(self.pal.grid), 1, Qt.DashLine))
        for frac in (0.0, 0.5, 1.0):
            y = r.bottom() - r.height() * frac
            p.drawLine(QPointF(r.left(), y), QPointF(r.right(), y))

        if len(self._pts) < 2:
            p.setPen(QPen(QColor(self.pal.text_dim)))
            p.drawText(r, int(Qt.AlignCenter), "collecting…")
            p.end()
            return

        n = len(self._pts)
        dx = r.width() / max(1, n - 1)
        last = self._pts[-1]
        color = signal_color(last, self.pal)
        pen = QPen(color, 2)
        p.setPen(pen)
        prev = None
        for i, v in enumerate(self._pts):
            x = r.left() + i * dx
            y = r.bottom() - r.height() * (v / 100.0)
            if prev is not None:
                p.drawLine(prev, QPointF(x, y))
            prev = QPointF(x, y)
        p.end()


class DetailPanel(QFrame):
    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("detailPanel")
        self.pal = pal
        self._histories: dict[str, deque] = {}
        self._current: str | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(12)

        self.title = QLabel("Select a network")
        self.title.setObjectName("h1")
        self.title.setWordWrap(True)
        self.subtitle = QLabel("Click any row to inspect it.")
        self.subtitle.setObjectName("muted")
        self.subtitle.setWordWrap(True)
        root.addWidget(self.title)
        root.addWidget(self.subtitle)

        spark_label = QLabel("SIGNAL HISTORY")
        spark_label.setObjectName("kpiLabel")
        root.addWidget(spark_label)
        self.spark = Sparkline(pal)
        root.addWidget(self.spark)

        self._grid = QGridLayout()
        self._grid.setVerticalSpacing(10)
        self._grid.setHorizontalSpacing(12)
        root.addLayout(self._grid)
        self._value_labels: dict[str, QLabel] = {}
        for i, field in enumerate(
            ["BSSID", "Vendor", "Security", "Band", "Channel", "Radio", "Signal", "Status"]
        ):
            key = QLabel(field.upper())
            key.setObjectName("kpiLabel")
            val = QLabel("—")
            val.setObjectName("h2")
            val.setWordWrap(True)
            self._grid.addWidget(key, i, 0, Qt.AlignTop)
            self._grid.addWidget(val, i, 1)
            self._value_labels[field] = val

        root.addStretch(1)

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        self.spark.set_palette(pal)

    def record(self, aps: list[AccessPoint]) -> None:
        """Append the latest signal sample for every visible network."""
        for ap in aps:
            self._histories.setdefault(ap.bssid, deque(maxlen=60)).append(ap.signal_percent)
        if self._current and self._current in self._histories:
            self.spark.reset(self._histories[self._current])

    def show_ap(self, ap: AccessPoint | None) -> None:
        if ap is None:
            self.title.setText("Select a network")
            self.subtitle.setText("Click any row to inspect it.")
            for v in self._value_labels.values():
                v.setText("—")
            self._current = None
            self.spark.reset([])
            return

        self._current = ap.bssid
        name = ap.ssid if ap.ssid else "‹hidden network›"
        self.title.setText(name)
        color = security_color(ap.security, self.pal)
        self.subtitle.setText(
            f"<span style='color:{color.name()}'>●</span> "
            f"{ap.security.value} · {ap.band.value} · channel {ap.channel}"
        )
        weak = ap.security.is_weak
        self._value_labels["BSSID"].setText(ap.bssid)
        self._value_labels["Vendor"].setText(ap.vendor or "Unknown")
        self._value_labels["Security"].setText(
            ap.security.value + ("  ⚠ weak" if weak else "")
        )
        self._value_labels["Band"].setText(ap.band.value)
        self._value_labels["Channel"].setText(str(ap.channel) if ap.channel else "—")
        self._value_labels["Radio"].setText(ap.radio_type or "—")
        dbm = f"{ap.signal_dbm} dBm" if ap.has_real_rssi else f"~{ap.signal_dbm} dBm (est.)"
        self._value_labels["Signal"].setText(f"{ap.signal_percent}%  ({dbm})")
        self._value_labels["Status"].setText("Hidden SSID" if ap.is_hidden else "Visible")

        hist = self._histories.get(ap.bssid)
        self.spark.reset(hist)
