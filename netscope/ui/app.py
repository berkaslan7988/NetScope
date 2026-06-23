"""Application entry point for the PySide6 UI.

    python gui.py            # real scanner on Windows, mock elsewhere
    python gui.py --mock     # force mock data (dev / any OS)
"""
from __future__ import annotations

import argparse
import sys


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="NetScope desktop UI")
    parser.add_argument("--mock", action="store_true", help="force the mock scanner")
    args = parser.parse_args(argv)

    # Import inside main so `--help` works even without PySide6 installed.
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        sys.stderr.write(
            "PySide6 is not installed. Run:  pip install -r requirements.txt\n"
        )
        return 2

    from .main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("NetScope")
    win = MainWindow(force_mock=args.mock)
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
