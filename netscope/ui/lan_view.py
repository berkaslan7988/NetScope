"""The LAN / Devices view (Phase 3).

A third top-level view for analysing the network you're connected to:

  * Device table     — every host found on the subnet (IP, host, vendor, MAC,
                       latency, open-port count).
  * Topology map     — router in the centre, devices around it.
  * Device panel     — details for the selected host + an on-demand TCP
                       port/service scan.
  * Throughput       — live down/up bandwidth for this machine.

The view is presentation-only: it emits ``discoverRequested`` /
``portsRequested`` and receives results through setter methods, so all the
threading lives in LanController.
"""
from __future__ import annotations

import math

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ..lan import Device, PortResult
from .theme import Palette

DevRole = Qt.UserRole + 11
_HEADERS = ["Host", "IP", "Vendor", "MAC", "Latency", "Ports"]


def _last_octet(ip: str) -> str:
    return ip.rsplit(".", 1)[-1] if "." in ip else ip


# --------------------------------------------------------------------------
class DeviceTableModel(QAbstractTableModel):
    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.pal = pal
        self._rows: list[Device] = []

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
        d = self._rows[index.row()]
        col = index.column()
        if role == DevRole:
            return d
        if role == Qt.DisplayRole:
            if col == 0:
                return (d.hostname or "—") + ("  ★" if d.is_gateway else ("  •" if d.is_self else ""))
            if col == 1:
                return d.ip
            if col == 2:
                return d.vendor or "—"
            if col == 3:
                return d.mac or "—"
            if col == 4:
                return "—" if d.rtt_ms is None else f"{d.rtt_ms:.0f} ms"
            if col == 5:
                if not d.ports_scanned:
                    return "·"
                n = len(d.open_ports)
                return str(n) if n else "0"
        if role == Qt.ForegroundRole and col in (0, 1):
            if d.is_gateway:
                return QColor(self.pal.accent)
            if d.is_self:
                return QColor(self.pal.good)
        if role == Qt.TextAlignmentRole and col in (4, 5):
            return int(Qt.AlignCenter)
        return None

    def set_devices(self, devices: list[Device]) -> None:
        self.beginResetModel()
        self._rows = sorted(devices, key=lambda d: d.ip_sort_key)
        self.endResetModel()

    def update_ports(self, ip: str, ports: list[PortResult]) -> None:
        for r, d in enumerate(self._rows):
            if d.ip == ip:
                d.ports = ports
                d.ports_scanned = True
                self.dataChanged.emit(self.index(r, 5), self.index(r, 5))
                return

    def device_at(self, row: int) -> Device | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None


# --------------------------------------------------------------------------
class TopologyMap(QWidget):
    nodeClicked = Signal(str)  # ip

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.pal = pal
        self._devices: list[Device] = []
        self._selected: str | None = None
        self._nodes: list[tuple[Device, float, float]] = []
        self.setMinimumHeight(220)

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        self.update()

    def set_devices(self, devices: list[Device]) -> None:
        self._devices = devices
        self.update()

    def set_selected(self, ip: str | None) -> None:
        self._selected = ip
        self.update()

    def mousePressEvent(self, ev) -> None:
        pos = ev.position()
        for dev, x, y in self._nodes:
            if (pos.x() - x) ** 2 + (pos.y() - y) ** 2 <= 22 * 22:
                self.nodeClicked.emit(dev.ip)
                return

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        self._nodes = []

        if not self._devices:
            p.setPen(QPen(QColor(self.pal.text_dim)))
            p.drawText(self.rect(), int(Qt.AlignCenter), "Run a scan to map the network")
            p.end()
            return

        gateway = next((d for d in self._devices if d.is_gateway), None)
        others = [d for d in self._devices if not d.is_gateway]
        radius = max(60, min(w, h) / 2 - 56)

        # spokes + outer nodes
        f = QFont(); f.setPointSize(8)
        p.setFont(f)
        n = max(1, len(others))
        for i, dev in enumerate(others):
            ang = -math.pi / 2 + 2 * math.pi * i / n
            x = cx + radius * math.cos(ang)
            y = cy + radius * math.sin(ang)
            self._nodes.append((dev, x, y))
            p.setPen(QPen(QColor(self.pal.grid), 1.5))
            p.drawLine(QPointF(cx, cy), QPointF(x, y))
        for dev, x, y in self._nodes:
            self._draw_node(p, dev, x, y, big=False)

        # gateway / hub in the centre
        if gateway is not None:
            self._nodes.append((gateway, cx, cy))
            self._draw_node(p, gateway, cx, cy, big=True)
        else:
            p.setBrush(QColor(self.pal.surface_alt)); p.setPen(QPen(QColor(self.pal.border)))
            p.drawEllipse(QPointF(cx, cy), 26, 26)
            p.setPen(QPen(QColor(self.pal.text_dim)))
            p.drawText(QRectF(cx - 30, cy - 8, 60, 16), int(Qt.AlignCenter), "LAN")
        p.end()

    def _draw_node(self, p: QPainter, dev: Device, x: float, y: float, big: bool) -> None:
        r = 24 if big else 19
        selected = dev.ip == self._selected
        if dev.is_gateway:
            fill = QColor(self.pal.accent); border = QColor(self.pal.accent)
        elif dev.is_self:
            fill = QColor(self.pal.surface_alt); border = QColor(self.pal.good)
        else:
            fill = QColor(self.pal.surface_alt); border = QColor(self.pal.border)
        p.setBrush(fill)
        p.setPen(QPen(QColor(self.pal.text if selected else border), 3 if selected else 1.6))
        p.drawEllipse(QPointF(x, y), r, r)
        # last octet inside
        p.setPen(QPen(QColor("#06121c" if dev.is_gateway else self.pal.text)))
        fb = QFont(); fb.setPointSize(9); fb.setBold(True); p.setFont(fb)
        p.drawText(QRectF(x - r, y - r, 2 * r, 2 * r), int(Qt.AlignCenter), _last_octet(dev.ip))
        # label below
        fs = QFont(); fs.setPointSize(8); p.setFont(fs)
        p.setPen(QPen(QColor(self.pal.text_dim)))
        name = dev.hostname or dev.vendor or dev.ip
        p.drawText(QRectF(x - 52, y + r + 1, 104, 14), int(Qt.AlignHCenter | Qt.AlignTop), name[:16])


# --------------------------------------------------------------------------
class ThroughputChart(QWidget):
    """Down/up bandwidth sparklines for this machine."""

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.pal = pal
        self._down = []
        self._up = []
        self.setMinimumHeight(46)
        self.setMinimumWidth(160)

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        self.update()

    def set_series(self, down, up) -> None:
        self._down = list(down)
        self._up = list(up)
        self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        r = QRectF(1, 3, self.width() - 2, self.height() - 6)
        peak = max([1.0] + self._down + self._up)

        def draw(series, color):
            if len(series) < 2:
                return
            dx = r.width() / (len(series) - 1)
            p.setPen(QPen(QColor(color), 1.8))
            prev = None
            for i, v in enumerate(series):
                x = r.left() + i * dx
                yv = r.bottom() - r.height() * (v / peak)
                if prev is not None:
                    p.drawLine(prev, QPointF(x, yv))
                prev = QPointF(x, yv)

        draw(self._down, self.pal.accent)
        draw(self._up, self.pal.warn)
        p.end()


# --------------------------------------------------------------------------
class DevicePanel(QFrame):
    portsRequested = Signal(str)

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("detailPanel")
        self.pal = pal
        self._device: Device | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)
        self.title = QLabel("Select a device"); self.title.setObjectName("h1")
        self.title.setWordWrap(True)
        self.subtitle = QLabel("Pick a host to inspect it."); self.subtitle.setObjectName("muted")
        self.subtitle.setWordWrap(True)
        root.addWidget(self.title)
        root.addWidget(self.subtitle)

        self._fields = {}
        for f in ["IP", "MAC", "Vendor", "Hostname", "Latency", "Role"]:
            row = QHBoxLayout()
            k = QLabel(f.upper()); k.setObjectName("kpiLabel"); k.setMinimumWidth(78)
            v = QLabel("—"); v.setObjectName("h2"); v.setWordWrap(True)
            row.addWidget(k); row.addWidget(v, 1)
            root.addLayout(row)
            self._fields[f] = v

        self.scan_btn = QPushButton("Scan ports")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self._request_ports)
        self.scan_btn.setEnabled(False)
        root.addWidget(self.scan_btn)

        self.ports_label = QLabel("OPEN PORTS"); self.ports_label.setObjectName("kpiLabel")
        root.addWidget(self.ports_label)
        self.ports_box = QLabel("—"); self.ports_box.setObjectName("muted")
        self.ports_box.setWordWrap(True)
        self.ports_box.setTextFormat(Qt.RichText)
        root.addWidget(self.ports_box)
        root.addStretch(1)

    def set_palette(self, pal: Palette) -> None:
        self.pal = pal
        if self._device:
            self.show_device(self._device)

    def _request_ports(self) -> None:
        if self._device:
            self.scan_btn.setEnabled(False)
            self.scan_btn.setText("Scanning…")
            self.portsRequested.emit(self._device.ip)

    def show_device(self, dev: Device | None) -> None:
        self._device = dev
        if dev is None:
            self.title.setText("Select a device")
            self.subtitle.setText("Pick a host to inspect it.")
            for v in self._fields.values():
                v.setText("—")
            self.scan_btn.setEnabled(False)
            self.ports_box.setText("—")
            return
        self.title.setText(dev.label)
        self.subtitle.setText(dev.role)
        self._fields["IP"].setText(dev.ip)
        self._fields["MAC"].setText(dev.mac or "Unknown")
        self._fields["Vendor"].setText(dev.vendor or "Unknown")
        self._fields["Hostname"].setText(dev.hostname or "—")
        self._fields["Latency"].setText("—" if dev.rtt_ms is None else f"{dev.rtt_ms:.0f} ms")
        self._fields["Role"].setText(dev.role)
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan ports")
        self._render_ports(dev)

    def set_ports(self, ip: str, ports: list[PortResult]) -> None:
        if self._device and self._device.ip == ip:
            self._device.ports = ports
            self._device.ports_scanned = True
            self.scan_btn.setEnabled(True)
            self.scan_btn.setText("Scan ports")
            self._render_ports(self._device)

    def _render_ports(self, dev: Device) -> None:
        if not dev.ports_scanned:
            self.ports_box.setText("<i>not scanned yet</i>")
            return
        opens = dev.open_ports
        if not opens:
            self.ports_box.setText("<i>no common ports open</i>")
            return
        acc = self.pal.accent
        chips = "&nbsp; ".join(
            f"<span style='color:{acc}'>●</span> {pr.port} {pr.service}" for pr in opens
        )
        self.ports_box.setText(chips)


# --------------------------------------------------------------------------
class LanView(QWidget):
    discoverRequested = Signal()
    portsRequested = Signal(str)

    def __init__(self, pal: Palette, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("root")
        self.pal = pal

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 10)
        outer.setSpacing(10)

        # header
        head = QHBoxLayout()
        self.subnet_label = QLabel("Subnet —"); self.subnet_label.setObjectName("h2")
        head.addWidget(self.subnet_label)
        head.addSpacing(12)
        self.scan_btn = QPushButton("⌖ Scan LAN"); self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self.discoverRequested)
        head.addWidget(self.scan_btn)
        self.progress = QLabel(""); self.progress.setObjectName("muted")
        head.addWidget(self.progress)
        head.addStretch(1)
        self.bw_label = QLabel("↓ 0 B/s   ↑ 0 B/s"); self.bw_label.setObjectName("muted")
        head.addWidget(self.bw_label)
        self.throughput = ThroughputChart(pal)
        head.addWidget(self.throughput)
        outer.addLayout(head)

        # body: table | (topology over device panel)
        self.model = DeviceTableModel(pal, self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(32)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        hh = self.table.horizontalHeader()
        hh.setStretchLastSection(False)
        hh.setSectionResizeMode(0, QHeaderView.Stretch)
        for c in (1, 2, 3, 4, 5):
            hh.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.table.selectionModel().selectionChanged.connect(self._on_select)

        right = QSplitter(Qt.Vertical)
        topo_card = QFrame(); topo_card.setObjectName("card")
        tl = QVBoxLayout(topo_card); tl.setContentsMargins(12, 10, 12, 12)
        tt = QLabel("Topology"); tt.setObjectName("h2"); tl.addWidget(tt)
        self.topology = TopologyMap(pal)
        self.topology.nodeClicked.connect(self._select_ip)
        tl.addWidget(self.topology)
        self.detail = DevicePanel(pal)
        self.detail.portsRequested.connect(self.portsRequested)
        right.addWidget(topo_card)
        right.addWidget(self.detail)
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
        self.topology.set_palette(pal)
        self.detail.set_palette(pal)
        self.throughput.set_palette(pal)
        self.table.viewport().update()

    # -- inbound data ------------------------------------------------------
    def set_subnet(self, text: str) -> None:
        self.subnet_label.setText(f"Subnet  {text}")

    def set_busy(self, busy: bool) -> None:
        self.scan_btn.setEnabled(not busy)
        self.scan_btn.setText("Scanning…" if busy else "⌖ Scan LAN")
        if not busy:
            self.progress.setText("")

    def set_progress(self, done: int, total: int) -> None:
        self.progress.setText(f"pinging {done}/{total}…")

    def set_devices(self, devices: list[Device]) -> None:
        cur = self._selected_ip()
        self.model.set_devices(devices)
        self.topology.set_devices(devices)
        if cur and not self._select_ip(cur):
            self.detail.show_device(None)
            self.topology.set_selected(None)
        elif not cur and self.model.rowCount():
            self.table.selectRow(0)

    def set_ports(self, ip: str, ports: list[PortResult]) -> None:
        self.model.update_ports(ip, ports)
        self.detail.set_ports(ip, ports)

    def set_throughput(self, down_bps: float, up_bps: float, down_hist, up_hist) -> None:
        from ..lan.traffic import human_rate
        self.bw_label.setText(f"↓ {human_rate(down_bps)}   ↑ {human_rate(up_bps)}")
        self.throughput.set_series(down_hist, up_hist)

    # -- selection ---------------------------------------------------------
    def _selected_ip(self) -> str | None:
        idxs = self.table.selectionModel().selectedRows()
        if idxs:
            d = idxs[0].data(DevRole)
            return d.ip if d else None
        return None

    def _select_ip(self, ip: str) -> bool:
        for r in range(self.model.rowCount()):
            if self.model.index(r, 0).data(DevRole).ip == ip:
                self.table.selectRow(r)
                return True
        return False

    def _on_select(self, *_a) -> None:
        idxs = self.table.selectionModel().selectedRows()
        dev = idxs[0].data(DevRole) if idxs else None
        self.detail.show_device(dev)
        self.topology.set_selected(dev.ip if dev else None)
