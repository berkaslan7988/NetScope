"""The Analytics view (Phase 2).

A second top-level view (toggled from the toolbar) that turns the live scan +
its history into four custom-painted panels:

  * Signal over time  — multi-network RSSI lines from the history store.
  * Cleanest channels — per-band congestion leaderboard + recommendation.
  * Bands             — how networks split across 2.4 / 5 / 6 GHz.
  * Security          — an airspace security score + a per-type breakdown.

No charting dependency: every panel paints itself, sharing the app's palette and
the same security colour language as the Networks view.
"""
from __future__ import annotations

import time
import zlib

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ..models import AccessPoint, Band, Security
from . import analysis
from .history import SignalHistory, Track
from .theme import Palette, security_color, signal_color

_BANDS = [Band.BAND_2_4, Band.BAND_5, Band.BAND_6]


def track_color(bssid: str, pal: Palette) -> QColor:
    """A stable, distinct colour per BSSID (deterministic across the session)."""
    hue = zlib.crc32(bssid.encode("utf-8")) % 360
    val = 235 if pal.bg < "#808080" else 200  # brighter on dark themes
    return QColor.fromHsv(hue, 175, val)


def _card(title: str) -> tuple[QFrame, QVBoxLayout, QHBoxLayout]:
    card = QFrame()
    card.setObjectName("card")
    lay = QVBoxLayout(card)
    lay.setContentsMargins(14, 12, 14, 12)
    lay.setSpacing(8)
    head = QHBoxLayout()
    lbl = QLabel(title)
    lbl.setObjectName("h2")
    head.addWidget(lbl)
    head.addStretch(1)
    lay.addLayout(head)
    return card, lay, head


# --------------------------------------------------------------------------
class SignalTimeChart(QWidget):
    """Multi-network signal-over-time lines (percent on Y, time on X)."""

    MAX_LINES = 10

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.pal = pal
        self._tracks: list[Track] = []
        self._span = 60.0
        self.setMinimumHeight(240)

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        self.update()

    def set_data(self, tracks: list[Track], span: float) -> None:
        self._tracks = tracks[: self.MAX_LINES]
        self._span = max(15.0, span)
        self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w, h = self.width(), self.height()
        # reserve a column on the right for the legend so lines never sit under it
        legend_w = 150 if self._tracks else 0
        ml, mr, mt, mb = 40, 12 + legend_w, 12, 22
        plot = QRectF(ml, mt, w - ml - mr, h - mt - mb)

        small = QFont(); small.setPointSize(8)
        p.setFont(small)
        for pct in (0, 25, 50, 75, 100):
            y = plot.bottom() - plot.height() * pct / 100.0
            p.setPen(QPen(QColor(self.pal.grid), 1, Qt.DotLine))
            p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            p.setPen(QPen(QColor(self.pal.text_dim)))
            p.drawText(QRectF(0, y - 8, ml - 6, 16), int(Qt.AlignRight | Qt.AlignVCenter), f"{pct}%")

        if not self._tracks:
            p.setPen(QPen(QColor(self.pal.text_dim)))
            p.drawText(plot, int(Qt.AlignCenter), "Collecting signal history…")
            p.end()
            return

        # Sample-indexed X axis: spread the last N samples across the width and
        # right-align every track by recency, so the chart always fills cleanly
        # (scans are evenly spaced in time, so index ~= time).
        window = max(2, max(len(tr.samples) for tr in self._tracks))
        dx = plot.width() / (window - 1)

        def y_for(pct):
            return plot.bottom() - plot.height() * (max(0, min(100, pct)) / 100.0)

        for tr in self._tracks:
            col = track_color(tr.bssid, self.pal)
            samples = list(tr.samples)
            m = len(samples)
            pts = []
            for i, (_t, pct, _dbm) in enumerate(samples):
                idx = window - m + i
                pts.append(QPointF(plot.left() + idx * dx, y_for(pct)))
            if len(pts) >= 2:
                p.setPen(QPen(col, 2))
                for a, b in zip(pts, pts[1:]):
                    p.drawLine(a, b)
            if pts:
                p.setBrush(col); p.setPen(Qt.NoPen)
                p.drawEllipse(pts[-1], 2.6, 2.6)

        # legend in the reserved right column
        p.setFont(small)
        lx = w - legend_w + 4
        ly = mt + 2
        for tr in self._tracks[:8]:
            col = track_color(tr.bssid, self.pal)
            p.setBrush(col); p.setPen(Qt.NoPen)
            p.drawRoundedRect(QRectF(lx, ly, 10, 10), 2, 2)
            p.setPen(QPen(QColor(self.pal.text)))
            p.drawText(QRectF(lx + 14, ly - 3, legend_w - 18, 16),
                       int(Qt.AlignLeft | Qt.AlignVCenter), tr.label[:16])
            ly += 16
        p.end()


# --------------------------------------------------------------------------
class ChannelLeaderboard(QWidget):
    """Cleanest-channels leaderboard for one band (lower load = better)."""

    MAX_ROWS = 12

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.pal = pal
        self._rows: list[tuple[int, float, int]] = []  # (channel, load, population)
        self._best: int | None = None
        self.setMinimumHeight(200)

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        self.update()

    def set_data(self, aps: list[AccessPoint], band: Band) -> None:
        load = analysis.channel_load_scores(aps, band)
        pop = analysis.channel_population(aps, band)
        rec = analysis.recommend_channel(aps, band)
        self._best = rec[0] if rec else None
        rows = sorted(load.items(), key=lambda kv: kv[1])[: self.MAX_ROWS]
        self._rows = [(ch, ld, pop.get(ch, 0)) for ch, ld in rows]
        self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w, h = self.width(), self.height()
        if not self._rows:
            p.setPen(QPen(QColor(self.pal.text_dim)))
            p.drawText(self.rect(), int(Qt.AlignCenter), "No networks on this band")
            p.end()
            return

        max_load = max((ld for _c, ld, _p in self._rows), default=1.0) or 1.0
        n = len(self._rows)
        row_h = min(26.0, (h - 6) / n)
        label_w = 58
        bar_x = label_w + 8
        bar_w = w - bar_x - 64
        f = QFont(); f.setPointSize(9)
        fb = QFont(); fb.setPointSize(9); fb.setBold(True)

        for i, (ch, load, pop) in enumerate(self._rows):
            y = 3 + i * row_h
            cy = y + row_h / 2
            is_best = ch == self._best
            # channel label
            p.setFont(fb if is_best else f)
            p.setPen(QPen(QColor(self.pal.accent if is_best else self.pal.text)))
            star = "★ " if is_best else ""
            p.drawText(QRectF(0, y, label_w, row_h), int(Qt.AlignVCenter | Qt.AlignRight),
                       f"{star}ch {ch}")
            # track
            track = QRectF(bar_x, cy - 5, bar_w, 10)
            p.setPen(Qt.NoPen); p.setBrush(QColor(self.pal.grid))
            p.drawRoundedRect(track, 5, 5)
            # fill — proportion of worst load; colour by congestion (low=green)
            frac = load / max_load
            fill_w = max(3.0, bar_w * frac)
            sig = int(100 * (1 - frac))  # reuse signal palette: clean=green
            p.setBrush(signal_color(sig, self.pal))
            p.drawRoundedRect(QRectF(bar_x, cy - 5, fill_w, 10), 5, 5)
            # population count
            p.setFont(f); p.setPen(QPen(QColor(self.pal.text_dim)))
            p.drawText(QRectF(bar_x + bar_w + 6, y, 58, row_h),
                       int(Qt.AlignVCenter | Qt.AlignLeft),
                       f"{pop} net" + ("s" if pop != 1 else ""))
        p.end()


# --------------------------------------------------------------------------
class BandBars(QWidget):
    """Count of networks per band as simple bars."""

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.pal = pal
        self._counts: list[tuple[str, int]] = []
        self.setMinimumHeight(120)

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        self.update()

    def set_data(self, aps: list[AccessPoint]) -> None:
        dist = analysis.band_distribution(aps)
        self._counts = [(b.value, dist.get(b, 0)) for b in _BANDS]
        self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w, h = self.width(), self.height()
        total = max(1, sum(c for _n, c in self._counts))
        f = QFont(); f.setPointSize(9)
        p.setFont(f)
        label_w = 56
        bar_x = label_w + 6
        bar_w = w - bar_x - 30
        rows = self._counts or [("—", 0)]
        row_h = (h - 6) / max(1, len(rows))
        for i, (name, count) in enumerate(rows):
            y = 3 + i * row_h
            cy = y + row_h / 2
            p.setPen(QPen(QColor(self.pal.text)))
            p.drawText(QRectF(0, y, label_w, row_h), int(Qt.AlignVCenter | Qt.AlignRight), name)
            track = QRectF(bar_x, cy - 7, bar_w, 14)
            p.setPen(Qt.NoPen); p.setBrush(QColor(self.pal.grid))
            p.drawRoundedRect(track, 7, 7)
            fw = bar_w * (count / total)
            p.setBrush(QColor(self.pal.accent))
            p.drawRoundedRect(QRectF(bar_x, cy - 7, max(0.0, fw), 14), 7, 7)
            p.setPen(QPen(QColor(self.pal.text)))
            p.drawText(QRectF(bar_x + bar_w + 4, y, 28, row_h),
                       int(Qt.AlignVCenter | Qt.AlignLeft), str(count))
        p.end()


# --------------------------------------------------------------------------
class SecurityPanel(QWidget):
    """Airspace security score + per-type breakdown chips."""

    _ORDER = [Security.OPEN, Security.WEP, Security.WPA, Security.WPA2,
              Security.WPA2_WPA3, Security.WPA3, Security.UNKNOWN]

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.pal = pal
        self._score: int | None = None
        self._dist = {}
        self._weak = 0
        self.setMinimumHeight(150)

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        self.update()

    def set_data(self, aps: list[AccessPoint]) -> None:
        self._score = analysis.security_score(aps)
        self._dist = analysis.security_distribution(aps)
        self._weak = analysis.weak_count(aps)
        self.update()

    def _score_color(self) -> QColor:
        s = self._score or 0
        if s >= 80:
            return QColor(self.pal.good)
        if s >= 55:
            return QColor(self.pal.warn)
        return QColor(self.pal.bad)

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w, h = self.width(), self.height()

        # score ring (left)
        ring_d = min(96, h - 16)
        cx, cy = 14 + ring_d / 2, h / 2
        ring = QRectF(14, cy - ring_d / 2, ring_d, ring_d)
        p.setPen(QPen(QColor(self.pal.grid), 9))
        p.drawArc(ring, 0, 360 * 16)
        if self._score is not None:
            pen = QPen(self._score_color(), 9)
            pen.setCapStyle(Qt.RoundCap)
            p.setPen(pen)
            p.drawArc(ring, 90 * 16, -int(360 * 16 * self._score / 100))
        big = QFont(); big.setPointSize(20); big.setBold(True)
        p.setFont(big); p.setPen(QPen(QColor(self.pal.text)))
        p.drawText(ring, int(Qt.AlignCenter), "—" if self._score is None else str(self._score))
        small = QFont(); small.setPointSize(8)
        p.setFont(small); p.setPen(QPen(QColor(self.pal.text_dim)))
        p.drawText(QRectF(14, cy + ring_d / 2 + 8, ring_d, 16),
                   int(Qt.AlignHCenter | Qt.AlignTop), "SECURITY")

        # chips (right): one per present security level
        chip_x = 14 + ring_d + 18
        x, y = chip_x, 10
        cf = QFont(); cf.setPointSize(9); cf.setBold(True)
        p.setFont(cf)
        max_x = w - 8
        for sec in self._ORDER:
            count = self._dist.get(sec, 0)
            if not count:
                continue
            text = f"{sec.value} ×{count}"
            tw = p.fontMetrics().horizontalAdvance(text) + 20
            if x + tw > max_x:
                x = chip_x; y += 28
            col = security_color(sec, self.pal)
            bg = QColor(col); bg.setAlpha(40)
            p.setBrush(bg); p.setPen(Qt.NoPen)
            p.drawRoundedRect(QRectF(x, y, tw, 22), 11, 11)
            p.setPen(QPen(col))
            p.drawText(QRectF(x, y, tw, 22), int(Qt.AlignCenter), text)
            x += tw + 8
        # weak callout
        p.setFont(small)
        p.setPen(QPen(QColor(self.pal.bad if self._weak else self.pal.text_dim)))
        p.drawText(QRectF(chip_x, h - 24, w - chip_x - 8, 18),
                   int(Qt.AlignLeft | Qt.AlignVCenter),
                   f"⚠ {self._weak} weak / open network" + ("s" if self._weak != 1 else ""))
        p.end()


# --------------------------------------------------------------------------
class AnalyticsView(QWidget):
    """Assembles the four panels into one view."""

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("root")
        self.pal = pal
        self._aps: list[AccessPoint] = []

        grid = QGridLayout(self)
        grid.setContentsMargins(14, 10, 14, 10)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)

        # top: signal-over-time (full width)
        chart_card, chart_lay, _ = _card("Signal over time")
        self.chart = SignalTimeChart(pal)
        chart_lay.addWidget(self.chart)
        grid.addWidget(chart_card, 0, 0, 1, 2)

        # bottom-left: channel leaderboard with band selector
        chan_card, chan_lay, chan_head = _card("Cleanest channels")
        self.band_combo = QComboBox()
        for b in _BANDS:
            self.band_combo.addItem(b.value)
        self.band_combo.currentIndexChanged.connect(self._on_band)
        chan_head.addWidget(self.band_combo)
        self.rec_label = QLabel("—")
        self.rec_label.setObjectName("kpiValue")
        chan_lay.addWidget(self.rec_label)
        rec_sub = QLabel("recommended channel")
        rec_sub.setObjectName("kpiLabel")
        chan_lay.addWidget(rec_sub)
        self.leaderboard = ChannelLeaderboard(pal)
        chan_lay.addWidget(self.leaderboard, 1)
        grid.addWidget(chan_card, 1, 0)

        # bottom-right: bands + security stacked
        right = QVBoxLayout()
        right.setSpacing(12)
        band_card, band_lay, _ = _card("Bands")
        self.bands = BandBars(pal)
        band_lay.addWidget(self.bands)
        sec_card, sec_lay, _ = _card("Security")
        self.security = SecurityPanel(pal)
        sec_lay.addWidget(self.security)
        right.addWidget(band_card)
        right.addWidget(sec_card)
        right_w = QWidget()
        right_w.setLayout(right)
        grid.addWidget(right_w, 1, 1)

        grid.setColumnStretch(0, 3)
        grid.setColumnStretch(1, 2)
        grid.setRowStretch(0, 3)
        grid.setRowStretch(1, 4)

    def _current_band(self) -> Band:
        return _BANDS[self.band_combo.currentIndex()]

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        for wdg in (self.chart, self.leaderboard, self.bands, self.security):
            wdg.set_palette(pal)

    def update_view(self, aps: list[AccessPoint], history: SignalHistory) -> None:
        self._aps = aps
        self.chart.set_data(history.active_tracks(), history.span_seconds())
        band = self._current_band()
        self.leaderboard.set_data(aps, band)
        rec = analysis.recommend_channel(aps, band)
        self.rec_label.setText(f"ch {rec[0]}" if rec else "—")
        self.bands.set_data(aps)
        self.security.set_data(aps)

    def _on_band(self) -> None:
        self.leaderboard.set_data(self._aps, self._current_band())
        rec = analysis.recommend_channel(self._aps, self._current_band())
        self.rec_label.setText(f"ch {rec[0]}" if rec else "—")
