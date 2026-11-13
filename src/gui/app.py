"""QApplication bootstrap — wires theme, controller, and window together."""
from __future__ import annotations

import sys

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from gui import icons, theme
from gui.controller import Controller
from gui.window import MainWindow
from tools.utils_gui import (
    get_settings, migrate_settings_file, repair_settings,
)


def main() -> int:
    migrate_settings_file()
    repair_settings()

    app = QApplication(sys.argv)
    app.setApplicationName('cutter')
    app.setApplicationDisplayName('cutter')
    app.setWindowIcon(icons.app_icon())
    app.setQuitOnLastWindowClosed(False)  # tray keeps us alive

    theme.apply(app, dark=bool(get_settings('dark')))

    controller = Controller()
    window = MainWindow(controller)
    window.show()
    # Paint the UI first, then bring the engine up in the background. Doing it
    # inline (engine build + scapy import + clearing firewall rules, ~3 s) ran
    # before the first paint and left an empty bordered shell on screen.
    app.processEvents()
    QTimer.singleShot(0, controller.start_async)

    return app.exec()


if __name__ == '__main__':
    raise SystemExit(main())
