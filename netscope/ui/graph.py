"""Channel occupancy graph — the classic WiFi-analyzer 'mountains'.

Each network is drawn as a rounded arch centered on its channel, with width
roughly matching its channel width and height matching signal strength. It's a
custom-painted QWidget (no charting dependency) so it stays light and themable.

This is the seed of Phase 2; for now it shows the 2.4 GHz band, where overlap
actually matters most. The band can be switched from the toolbar.
"""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget

from ..models import AccessPoint, Band
from .theme import Palette, security_color

# Center frequency offset per band, expressed as channel-number tick labels.
_BANDS = {
    Band.BAND_2_4: list(range(1, 14)),
    Band.BAND_5: [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                  116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165],
}


class ChannelGraph(QWidget):
    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.pal = pal
        self._aps: list[AccessPoint] = []
        self._band = Band.BAND_2_4
        self.setMinimumHeight(190)
        self.setMouseTracking(True)

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        self.update()

    def set_band(self, band) -> None:
        # band may arrive as a plain str (Qt coerces the str-Enum in QVariant);
        # rebuild the enum so membership checks and .value work.
        if not isinstance(band, Band):
            try:
                band = Band(band)
            except (ValueError, TypeError):
                band = Band.BAND_2_4
        self._band = band if band in _BANDS else Band.BAND_2_4
        self.update()

    def set_data(self, aps: list[AccessPoint]) -> None:
        self._aps = aps
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w = self.width()
        h = self.height()

        margin_l, margin_r, margin_t, margin_b = 12, 12, 14, 24
        plot = QRectF(margin_l, margin_t, w - margin_l - margin_r, h - margin_t - margin_b)

        channels = _BANDS[self._band]
        cmin, cmax = channels[0], channels[-1]
        span = max(1, cmax - cmin)

        def x_for(ch: float) -> float:
            return plot.left() + (ch - cmin) / span * plot.width()

        # baseline + channel ticks
        p.setPen(QPen(QColor(self.pal.grid), 1))
        base_y = plot.bottom()
        p.drawLine(QPointF(plot.left(), base_y), QPointF(plot.right(), base_y))

        tick_font = QFont()
        tick_font.setPointSize(8)
        p.setFont(tick_font)
        step = 1 if self._band == Band.BAND_2_4 else 4
        for i, ch in enumerate(channels):
            if i % step != 0 and ch not in (channels[0], channels[-1]):
                continue
            x = x_for(ch)
            p.setPen(QPen(QColor(self.pal.grid), 1, Qt.DotLine))
            p.drawLine(QPointF(x, plot.top()), QPointF(x, base_y))
            p.setPen(QPen(QColor(self.pal.text_dim)))
            p.drawText(QRectF(x - 14, base_y + 4, 28, 18), int(Qt.AlignHCenter | Qt.AlignTop), str(ch))

        band_aps = [a for a in self._aps if a.band == self._band and a.channel]
        if not band_aps:
            p.setPen(QPen(QColor(self.pal.text_dim)))
            p.drawText(plot, int(Qt.AlignCenter), f"No networks on {self._band.value}")
            p.end()
            return

        # channel "width" in channel-units for the arch half-width
        half = 1.4 if self._band == Band.BAND_2_4 else 2.2

        label_font = QFont()
        label_font.setPointSize(8)
        label_font.setBold(True)

        # Pass 1: draw the arches weakest-first so strong ones sit on top.
        for ap in sorted(band_aps, key=lambda a: a.signal_percent):
            cx = x_for(ap.channel)
            peak = base_y - plot.height() * (ap.signal_percent / 100.0)
            lx = x_for(ap.channel - half)
            rx = x_for(ap.channel + half)

            path = QPainterPath()
            path.moveTo(lx, base_y)
            path.cubicTo(QPointF(cx - (cx - lx) * 0.45, base_y),
                         QPointF(cx - (cx - lx) * 0.55, peak),
                         QPointF(cx, peak))
            path.cubicTo(QPointF(cx + (rx - cx) * 0.55, peak),
                         QPointF(cx + (rx - cx) * 0.45, base_y),
                         QPointF(rx, base_y))

            color = security_color(ap.security, self.pal)
            fill = QColor(color)
            fill.setAlpha(46)
            p.setBrush(fill)
            p.setPen(QPen(color, 1.6))
            p.drawPath(path)

        # Pass 2: labels strongest-first, skipping any that would collide with
        # an already-placed label. Keeps the graph readable when channels stack.
        p.setFont(label_font)
        placed: list[QRectF] = []
        for ap in sorted(band_aps, key=lambda a: a.signal_percent, reverse=True):
            cx = x_for(ap.channel)
            peak = base_y - plot.height() * (ap.signal_percent / 100.0)
            name = (ap.ssid if ap.ssid else "‹hidden›")[:16]
            # clamp the label box so edge channels aren't clipped by the margin
            lx0 = min(max(cx - 58, 2.0), w - 118.0)
            lbl = QRectF(lx0, peak - 16, 116, 14)
            hit = QRectF(cx - 34, peak - 15, 68, 13)
            if any(hit.intersects(r) for r in placed):
                continue
            placed.append(hit)
            p.setPen(QPen(security_color(ap.security, self.pal)))
            p.drawText(lbl, int(Qt.AlignHCenter | Qt.AlignBottom), name)

        p.end()
