"""Colors + global stylesheet. Dark-first, with a light palette available.

Everything visual lives here so the look can be retuned in one place. The
security colors are shared between the table badges and the channel graph so
the whole app speaks one consistent color language.
"""
from __future__ import annotations

from PySide6.QtGui import QColor

from ..models import Security


class Palette:
    """A flat color palette. Two instances: DARK (default) and LIGHT."""

    def __init__(
        self,
        *,
        bg: str,
        surface: str,
        surface_alt: str,
        border: str,
        text: str,
        text_dim: str,
        accent: str,
        accent_soft: str,
        grid: str,
        good: str,
        warn: str,
        bad: str,
        great: str,
    ) -> None:
        self.bg = bg
        self.surface = surface
        self.surface_alt = surface_alt
        self.border = border
        self.text = text
        self.text_dim = text_dim
        self.accent = accent
        self.accent_soft = accent_soft
        self.grid = grid
        self.good = good
        self.warn = warn
        self.bad = bad
        self.great = great


DARK = Palette(
    bg="#0e1116",
    surface="#161b22",
    surface_alt="#1c2330",
    border="#2a3242",
    text="#e6edf3",
    text_dim="#8b97a7",
    accent="#3fb6ff",
    accent_soft="#163243",
    grid="#222b38",
    good="#3fb950",
    warn="#e3b341",
    bad="#f85149",
    great="#56d364",
)

LIGHT = Palette(
    bg="#f4f6fa",
    surface="#ffffff",
    surface_alt="#eef1f6",
    border="#d4dae3",
    text="#10141a",
    text_dim="#5b6675",
    accent="#1769c4",
    accent_soft="#dbeaff",
    grid="#e3e8ef",
    good="#1a7f37",
    warn="#9a6700",
    bad="#cf222e",
    great="#1a7f37",
)


def security_color(sec: Security, pal: Palette) -> QColor:
    """One color language for security strength, used by badges and graph."""
    return QColor(
        {
            Security.OPEN: pal.bad,
            Security.WEP: pal.bad,
            Security.WPA: pal.warn,
            Security.WPA2: pal.good,
            Security.WPA3: pal.great,
            Security.WPA2_WPA3: pal.great,
            Security.UNKNOWN: pal.text_dim,
        }.get(sec, pal.text_dim)
    )


def signal_color(percent: int, pal: Palette) -> QColor:
    """Green (strong) -> amber -> red (weak), independent of security."""
    if percent >= 66:
        return QColor(pal.good)
    if percent >= 40:
        return QColor(pal.warn)
    return QColor(pal.bad)


def stylesheet(pal: Palette) -> str:
    """The global Qt Style Sheet built from a palette."""
    return f"""
    * {{
        font-family: "Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif;
        font-size: 13px;
        color: {pal.text};
    }}
    QMainWindow, QWidget#root {{
        background: {pal.bg};
    }}
    QFrame#card, QWidget#detailPanel {{
        background: {pal.surface};
        border: 1px solid {pal.border};
        border-radius: 12px;
    }}
    QLabel#h1 {{
        font-size: 18px;
        font-weight: 700;
        color: {pal.text};
    }}
    QLabel#h2 {{
        font-size: 14px;
        font-weight: 600;
        color: {pal.text};
    }}
    QLabel#muted {{
        color: {pal.text_dim};
    }}
    QLabel#brand {{
        font-size: 20px;
        font-weight: 800;
        color: {pal.accent};
    }}
    QLabel#kpiValue {{
        font-size: 22px;
        font-weight: 800;
        color: {pal.text};
    }}
    QLabel#kpiLabel {{
        font-size: 11px;
        color: {pal.text_dim};
        text-transform: uppercase;
        letter-spacing: 1px;
    }}

    QToolBar {{
        background: {pal.surface};
        border: none;
        border-bottom: 1px solid {pal.border};
        padding: 6px 10px;
        spacing: 8px;
    }}

    QLineEdit {{
        background: {pal.surface_alt};
        border: 1px solid {pal.border};
        border-radius: 8px;
        padding: 6px 10px;
        selection-background-color: {pal.accent};
    }}
    QLineEdit:focus {{
        border: 1px solid {pal.accent};
    }}

    QComboBox {{
        background: {pal.surface_alt};
        border: 1px solid {pal.border};
        border-radius: 8px;
        padding: 5px 10px;
        min-width: 90px;
    }}
    QComboBox:focus {{ border: 1px solid {pal.accent}; }}
    QComboBox QAbstractItemView {{
        background: {pal.surface};
        border: 1px solid {pal.border};
        selection-background-color: {pal.accent_soft};
        outline: none;
    }}

    QPushButton {{
        background: {pal.surface_alt};
        border: 1px solid {pal.border};
        border-radius: 8px;
        padding: 6px 14px;
        font-weight: 600;
    }}
    QPushButton:hover {{ border: 1px solid {pal.accent}; }}
    QPushButton:pressed {{ background: {pal.accent_soft}; }}
    QPushButton#primary {{
        background: {pal.accent};
        border: 1px solid {pal.accent};
        color: #06121c;
    }}
    QPushButton#primary:hover {{ background: {pal.great}; border-color: {pal.great}; }}
    QPushButton:checked {{
        background: {pal.accent_soft};
        border: 1px solid {pal.accent};
        color: {pal.accent};
    }}

    QTableView {{
        background: {pal.surface};
        alternate-background-color: {pal.surface_alt};
        border: 1px solid {pal.border};
        border-radius: 12px;
        gridline-color: {pal.grid};
        selection-background-color: {pal.accent_soft};
        selection-color: {pal.text};
        outline: none;
    }}
    QTableView::item {{ padding: 6px 8px; }}
    QHeaderView::section {{
        background: {pal.surface_alt};
        color: {pal.text_dim};
        border: none;
        border-bottom: 1px solid {pal.border};
        padding: 8px;
        font-weight: 700;
    }}
    QTableView QTableCornerButton::section {{
        background: {pal.surface_alt};
        border: none;
    }}

    QScrollBar:vertical {{
        background: transparent; width: 10px; margin: 2px;
    }}
    QScrollBar::handle:vertical {{
        background: {pal.border}; border-radius: 5px; min-height: 30px;
    }}
    QScrollBar::handle:vertical:hover {{ background: {pal.accent}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}

    QStatusBar {{
        background: {pal.surface};
        border-top: 1px solid {pal.border};
        color: {pal.text_dim};
    }}
    QStatusBar::item {{ border: none; }}

    QDialog {{
        background: {pal.bg};
    }}
    QGroupBox {{
        border: 1px solid {pal.border};
        border-radius: 10px;
        margin-top: 10px;
        padding: 12px 8px 8px 8px;
        font-weight: 600;
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 12px;
        padding: 0 5px;
        color: {pal.text_dim};
    }}
    QCheckBox {{
        color: {pal.text};
        spacing: 8px;
        background: transparent;
    }}
    QSpinBox, QDoubleSpinBox {{
        background: {pal.surface_alt};
        border: 1px solid {pal.border};
        border-radius: 8px;
        padding: 4px 8px;
        min-width: 70px;
    }}
    QSpinBox:focus, QDoubleSpinBox:focus {{ border: 1px solid {pal.accent}; }}
    QLabel {{ background: transparent; }}

    QToolTip {{
        background: {pal.surface_alt};
        color: {pal.text};
        border: 1px solid {pal.border};
        padding: 4px 8px;
    }}
    """
