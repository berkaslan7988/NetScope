"""The live network table: model, filter/sort proxy, and painted delegates.

Design notes
------------
* The model keeps AccessPoints keyed by BSSID and *updates in place* between
  scans instead of rebuilding. That keeps the selection stable and lets us
  flag rows as new / gone / changed for the next phases.
* Sorting and filtering live in a QSortFilterProxyModel so the model stays a
  dumb data container. A hidden Qt.UserRole returns the raw value so numeric
  columns (signal, channel) sort numerically, not as text.
* Signal strength and security are drawn by delegates rather than stored as
  text, so they look like a product instead of a spreadsheet.
"""
from __future__ import annotations

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    QRect,
    Qt,
)
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QStyle, QStyledItemDelegate

from ..models import AccessPoint, Band, Security
from .theme import Palette, security_color, signal_color

# Column layout (single source of truth)
COL_SSID = 0
COL_VENDOR = 1
COL_BAND = 2
COL_CHANNEL = 3
COL_SECURITY = 4
COL_SIGNAL = 5
COL_BSSID = 6
HEADERS = ["Network", "Vendor", "Band", "Ch", "Security", "Signal", "BSSID"]

# Custom roles
SortRole = Qt.UserRole + 1
ApRole = Qt.UserRole + 2


class NetworkTableModel(QAbstractTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[AccessPoint] = []
        self._index: dict[str, AccessPoint] = {}

    # --- Qt model API -----------------------------------------------------
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        ap = self._rows[index.row()]
        col = index.column()

        if role == ApRole:
            return ap

        if role == SortRole:
            return {
                COL_SSID: (ap.ssid or "￿").lower(),  # hidden sort last
                COL_VENDOR: ap.vendor.lower(),
                COL_BAND: ap.band.value,
                COL_CHANNEL: ap.channel,
                COL_SECURITY: _sec_rank(ap.security),
                COL_SIGNAL: ap.signal_percent,
                COL_BSSID: ap.bssid,
            }[col]

        if role == Qt.DisplayRole:
            if col == COL_SSID:
                return ap.ssid if ap.ssid else "‹hidden›"
            if col == COL_VENDOR:
                return ap.vendor or "—"
            if col == COL_BAND:
                return ap.band.value
            if col == COL_CHANNEL:
                return str(ap.channel) if ap.channel else "—"
            if col == COL_SECURITY:
                return ap.security.value
            if col == COL_SIGNAL:
                return f"{ap.signal_percent}%"
            if col == COL_BSSID:
                return ap.bssid
            return None

        if role == Qt.TextAlignmentRole:
            if col in (COL_CHANNEL,):
                return int(Qt.AlignCenter)
            if col == COL_SIGNAL:
                return int(Qt.AlignVCenter | Qt.AlignLeft)
            return int(Qt.AlignVCenter | Qt.AlignLeft)

        if role == Qt.ToolTipRole:
            return (
                f"{ap.ssid or 'hidden network'}\n"
                f"BSSID: {ap.bssid}\n"
                f"{ap.security.value} · {ap.band.value} · ch {ap.channel}\n"
                f"{ap.signal_percent}% (~{ap.signal_dbm} dBm)"
            )

        if role == Qt.FontRole and col == COL_SSID and ap.is_hidden:
            from PySide6.QtGui import QFont
            f = QFont()
            f.setItalic(True)
            return f

        return None

    # --- domain API -------------------------------------------------------
    def update(self, aps: list[AccessPoint]) -> None:
        """Merge a fresh scan *in place*.

        Rebuilding the whole model every scan (beginResetModel) drops the
        selection and makes the list visibly flicker. Instead we keep row
        identity stable: drop BSSIDs that vanished, refresh the ones still
        present, and append newcomers. The view's sort/filter proxy handles
        ordering, so we never reorder rows here. Selection — which Qt tracks by
        source row — survives untouched.
        """
        new = {ap.bssid: ap for ap in aps}

        # 1) remove rows whose BSSID is gone (reverse order keeps indices valid)
        for row in range(len(self._rows) - 1, -1, -1):
            if self._rows[row].bssid not in new:
                self.beginRemoveRows(QModelIndex(), row, row)
                del self._rows[row]
                self.endRemoveRows()

        # 2) refresh rows that are still present
        pos = {ap.bssid: i for i, ap in enumerate(self._rows)}
        for bssid, ap in new.items():
            if bssid in pos:
                row = pos[bssid]
                self._rows[row] = ap
                self.dataChanged.emit(
                    self.index(row, 0), self.index(row, self.columnCount() - 1)
                )

        # 3) append newcomers
        fresh = [ap for bssid, ap in new.items() if bssid not in pos]
        if fresh:
            start = len(self._rows)
            self.beginInsertRows(QModelIndex(), start, start + len(fresh) - 1)
            self._rows.extend(fresh)
            self.endInsertRows()

        self._index = new

    def ap_at(self, row: int) -> AccessPoint | None:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None


def _sec_rank(sec: Security) -> int:
    """Higher = stronger, so sorting by security is meaningful."""
    return {
        Security.OPEN: 0,
        Security.WEP: 1,
        Security.WPA: 2,
        Security.WPA2: 3,
        Security.WPA2_WPA3: 4,
        Security.WPA3: 5,
        Security.UNKNOWN: -1,
    }.get(sec, -1)


class NetworkFilterProxy(QSortFilterProxyModel):
    """Search box + band filter + security filter, all combinable."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setSortRole(SortRole)
        self._text = ""
        self._band: Band | None = None
        self._weak_only = False

    def set_text(self, text: str) -> None:
        self._text = text.strip().lower()
        self.invalidateFilter()

    def set_band(self, band: Band | None) -> None:
        self._band = band
        self.invalidateFilter()

    def set_weak_only(self, on: bool) -> None:
        self._weak_only = on
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        model = self.sourceModel()
        ap: AccessPoint = model.data(model.index(source_row, 0), ApRole)
        if ap is None:
            return False
        if self._band is not None and ap.band != self._band:
            return False
        if self._weak_only and not ap.security.is_weak:
            return False
        if self._text:
            hay = f"{ap.ssid} {ap.bssid} {ap.vendor}".lower()
            if self._text not in hay:
                return False
        return True


class SignalDelegate(QStyledItemDelegate):
    """Paints a rounded signal bar + the percentage, colored by strength."""

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.pal = pal

    def paint(self, painter: QPainter, option, index):
        if option.state & QStyle.State_Selected:
            painter.fillRect(option.rect, QColor(self.pal.accent_soft))
        ap: AccessPoint = index.data(ApRole)
        pct = ap.signal_percent if ap else 0
        rect = option.rect.adjusted(8, 0, -8, 0)

        bar_w = int(rect.width() * 0.62)
        bar_h = 8
        bx = rect.left()
        by = rect.center().y() - bar_h // 2

        painter.save()
        painter.setRenderHint(QPainter.Antialiasing, True)
        # track
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(self.pal.grid))
        painter.drawRoundedRect(QRect(bx, by, bar_w, bar_h), 4, 4)
        # fill
        fill_w = max(2, int(bar_w * pct / 100))
        painter.setBrush(signal_color(pct, self.pal))
        painter.drawRoundedRect(QRect(bx, by, fill_w, bar_h), 4, 4)
        # label
        painter.setPen(QPen(QColor(self.pal.text_dim)))
        label_rect = QRect(bx + bar_w + 8, rect.top(), rect.width() - bar_w - 8, rect.height())
        dbm = ap.signal_dbm if ap else -100
        painter.drawText(label_rect, int(Qt.AlignVCenter | Qt.AlignLeft), f"{pct}%  {dbm} dBm")
        painter.restore()


class SecurityDelegate(QStyledItemDelegate):
    """Paints a colored pill for the security type."""

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.pal = pal

    def paint(self, painter: QPainter, option, index):
        if option.state & QStyle.State_Selected:
            painter.fillRect(option.rect, QColor(self.pal.accent_soft))
        ap: AccessPoint = index.data(ApRole)
        if ap is None:
            return
        sec = ap.security
        color = security_color(sec, self.pal)

        painter.save()
        painter.setRenderHint(QPainter.Antialiasing, True)
        text = sec.value
        fm = option.fontMetrics
        tw = fm.horizontalAdvance(text)
        pad = 10
        pill_w = tw + pad * 2
        pill_h = 20
        px = option.rect.left() + 8
        py = option.rect.center().y() - pill_h // 2
        pill = QRect(px, py, pill_w, pill_h)

        bg = QColor(color)
        bg.setAlpha(38)
        painter.setPen(Qt.NoPen)
        painter.setBrush(bg)
        painter.drawRoundedRect(pill, 10, 10)
        painter.setPen(QPen(color))
        painter.drawText(pill, int(Qt.AlignCenter), text)
        painter.restore()
