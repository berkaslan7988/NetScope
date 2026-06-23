"""Preferences dialog (General / Security / Data), persisted via Config.

The dialog edits a snapshot of the values and only commits them to the caller
when Save is pressed (read back with ``values()``). Destructive data actions
(clear history) and "open data folder" run through callbacks so the dialog
stays decoupled from the store and the filesystem.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..config import Config

_VIEW_LABELS = [
    ("networks", "Networks"), ("analytics", "Analytics"), ("lan", "LAN"),
    ("security", "Security"), ("history", "History"),
]


class SettingsDialog(QDialog):
    def __init__(self, config: Config, parent=None,
                 on_clear_history=None, on_open_folder=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NetScope — Settings")
        self.setModal(True)
        self.setMinimumWidth(440)
        self._cfg = config
        self._on_clear_history = on_clear_history
        self._on_open_folder = on_open_folder
        self._result: dict = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 14)
        root.setSpacing(12)

        # --- General -----------------------------------------------------
        gen = QGroupBox("General")
        gf = QFormLayout(gen); gf.setLabelAlignment(Qt.AlignRight); gf.setSpacing(8)
        self.theme = QComboBox(); self.theme.addItems(["Dark", "Light"])
        self.theme.setCurrentIndex(0 if config.get("theme") == "dark" else 1)
        gf.addRow("Theme", self.theme)
        self.start_view = QComboBox()
        for _key, label in _VIEW_LABELS:
            self.start_view.addItem(label)
        self.start_view.setCurrentIndex(
            max(0, [k for k, _ in _VIEW_LABELS].index(config.get("start_view"))
                if config.get("start_view") in [k for k, _ in _VIEW_LABELS] else 0))
        gf.addRow("Start view", self.start_view)
        self.auto_start = QCheckBox("Start scanning automatically on launch")
        self.auto_start.setChecked(bool(config.get("auto_start")))
        gf.addRow("", self.auto_start)
        self.scan_interval = QSpinBox(); self.scan_interval.setRange(1, 60)
        self.scan_interval.setSuffix(" s"); self.scan_interval.setValue(int(config.get("scan_interval")))
        gf.addRow("Scan interval", self.scan_interval)
        root.addWidget(gen)

        # --- Security ----------------------------------------------------
        sec = QGroupBox("Security && alerts")
        sf = QFormLayout(sec); sf.setLabelAlignment(Qt.AlignRight); sf.setSpacing(8)
        self.alerts_enabled = QCheckBox("Record security alerts")
        self.alerts_enabled.setChecked(bool(config.get("alerts_enabled")))
        sf.addRow("", self.alerts_enabled)
        self.lost_after = QSpinBox(); self.lost_after.setRange(5, 600)
        self.lost_after.setSuffix(" s"); self.lost_after.setValue(int(config.get("lost_after")))
        sf.addRow("‘Lost network’ after", self.lost_after)
        self.warn_weak = QCheckBox("Flag new open / WEP networks as warnings")
        self.warn_weak.setChecked(bool(config.get("warn_weak")))
        sf.addRow("", self.warn_weak)
        root.addWidget(sec)

        # --- Data --------------------------------------------------------
        data = QGroupBox("Data && history")
        df = QFormLayout(data); df.setLabelAlignment(Qt.AlignRight); df.setSpacing(8)
        path_row = QHBoxLayout()
        self.db_path = QLineEdit(str(config.get("db_path")))
        browse = QPushButton("Browse…"); browse.clicked.connect(self._browse_db)
        path_row.addWidget(self.db_path, 1); path_row.addWidget(browse)
        path_w = QWidget(); path_w.setLayout(path_row)
        df.addRow("Database", path_w)
        hint = QLabel("Changing the database location takes effect after restart.")
        hint.setObjectName("muted"); hint.setWordWrap(True)
        df.addRow("", hint)
        self.retention = QSpinBox(); self.retention.setRange(0, 3650)
        self.retention.setSpecialValueText("keep forever")
        self.retention.setSuffix(" days"); self.retention.setValue(int(config.get("retention_days")))
        df.addRow("Retention", self.retention)
        actions = QHBoxLayout()
        self.clear_btn = QPushButton("Clear history…"); self.clear_btn.clicked.connect(self._clear_history)
        self.folder_btn = QPushButton("Open data folder"); self.folder_btn.clicked.connect(self._open_folder)
        actions.addWidget(self.clear_btn); actions.addWidget(self.folder_btn); actions.addStretch(1)
        actions_w = QWidget(); actions_w.setLayout(actions)
        df.addRow("", actions_w)
        root.addWidget(data)

        self.status = QLabel(""); self.status.setObjectName("muted")
        root.addWidget(self.status)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Save).setObjectName("primary")
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    # -- helpers -----------------------------------------------------------
    def _browse_db(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Choose database file", self.db_path.text(), "SQLite (*.db)")
        if path:
            self.db_path.setText(path)

    def _clear_history(self) -> None:
        if QMessageBox.question(
                self, "Clear history",
                "Delete all stored networks, alerts and devices? This cannot be undone.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        if self._on_clear_history:
            self._on_clear_history()
        self.status.setText("History cleared.")

    def _open_folder(self) -> None:
        if self._on_open_folder:
            self._on_open_folder()

    def _save(self) -> None:
        self._result = {
            "theme": "dark" if self.theme.currentIndex() == 0 else "light",
            "start_view": _VIEW_LABELS[self.start_view.currentIndex()][0],
            "auto_start": self.auto_start.isChecked(),
            "scan_interval": self.scan_interval.value(),
            "alerts_enabled": self.alerts_enabled.isChecked(),
            "lost_after": float(self.lost_after.value()),
            "warn_weak": self.warn_weak.isChecked(),
            "db_path": self.db_path.text().strip(),
            "retention_days": self.retention.value(),
        }
        self.accept()

    def values(self) -> dict:
        return self._result
