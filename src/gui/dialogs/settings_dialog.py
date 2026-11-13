"""Settings — interface, appearance, scan params, behavior.

Emits changes to the Controller (interface, scan params, remember) or persists a
setting; it never reaches back into the window to mutate it.
"""
from __future__ import annotations

from PySide6.QtWidgets import (
    QApplication, QComboBox, QHBoxLayout, QLabel, QSpinBox, QWidget,
)

from gui.dialogs.base import Dialog
from gui.theme import retheme
from gui.widgets.controls import SegmentedControl, ToggleSwitch, hline, label
from tools import stealth
from tools.utils import get_ifaces
from tools.utils_gui import get_settings, is_admin, set_settings


class SettingsDialog(Dialog):
    def __init__(self, controller, parent=None) -> None:
        super().__init__('Settings', parent, width=460)
        self.ctrl = controller

        # --- interface ---
        self.content.addWidget(self.section('Network interface'))
        self._iface = QComboBox()
        self._ifaces = list(get_ifaces())
        current = controller.iface_name()
        for i, face in enumerate(self._ifaces):
            self._iface.addItem(f'{face.name}   ({face.ip})', face.name)
            if face.name == current:
                self._iface.setCurrentIndex(i)
        self._iface.currentIndexChanged.connect(self._change_iface)
        self.content.addWidget(self._iface)

        self.content.addWidget(hline())

        # --- appearance ---
        self.content.addWidget(self.section('Appearance'))
        theme = SegmentedControl([('dark', 'Dark'), ('light', 'Light')])
        theme.set_value('dark' if get_settings('dark') else 'light')
        theme.changed.connect(self._change_theme)
        self.content.addWidget(theme)

        self.content.addWidget(hline())

        # --- privacy --- one toggle: mask the device list AND (Windows, admin)
        # stop this PC answering NetBIOS/LLMNR/mDNS name queries.
        self.content.addWidget(self.section('Privacy'))
        self.content.addWidget(self.caption(
            'On Windows, randomises this PC\'s MAC address (rotating the DHCP IP) '
            'and stops it answering NetBIOS, LLMNR and mDNS name queries — '
            'so other devices cannot identify it. Fully reversible.'
            if stealth.available() else
            'Identity shield is Windows-only.'))
        self._privacy = ToggleSwitch()
        self._privacy.setChecked(bool(get_settings('privacy_mode')))
        self._privacy.toggled.connect(self._change_privacy)
        self.content.addLayout(self._row('Hide this device', self._privacy))
        if stealth.available() and not is_admin():
            self.content.addWidget(self.caption(
                'Requires administrator access — relaunch elevated to use.'))

        self.content.addWidget(hline())

        # --- scan ---
        self.content.addWidget(self.section('Scanning'))
        self._count = self._spin(2, 255, int(get_settings('count') or 255))
        self._threads = self._spin(1, 64, int(get_settings('threads') or 12))
        self._count.valueChanged.connect(self._change_scan)
        self._threads.valueChanged.connect(self._change_scan)
        self.content.addLayout(self._row('Addresses to scan', self._count))
        self.content.addLayout(self._row('Parallel threads', self._threads))

        self.content.addWidget(hline())

        # --- behavior ---
        self.content.addWidget(self.section('Behavior'))
        self._minimized = ToggleSwitch()
        self._minimized.setChecked(bool(get_settings('minimized')))
        self._minimized.toggled.connect(lambda v: set_settings('minimized', v))
        self._remember = ToggleSwitch()
        self._remember.setChecked(bool(get_settings('remember')))
        self._remember.toggled.connect(self.ctrl.set_remember)
        self.content.addLayout(self._row('Keep running in the menu bar on close', self._minimized))
        self.content.addLayout(self._row('Remember cut devices between scans', self._remember))

    # -- helpers -------------------------------------------------------------

    def _spin(self, lo: int, hi: int, val: int) -> QSpinBox:
        s = QSpinBox()
        s.setRange(lo, hi)
        s.setValue(val)
        s.setFixedWidth(90)
        return s

    def _row(self, text: str, widget: QWidget):
        row = QHBoxLayout()
        row.addWidget(label(text, 'body'), 1)
        row.addWidget(widget)
        return row

    # -- handlers ------------------------------------------------------------

    def _change_iface(self, index: int) -> None:
        self.ctrl.set_iface(self._iface.itemData(index))

    def _change_scan(self) -> None:
        self.ctrl.set_scan_params(self._count.value(), self._threads.value())

    def _change_theme(self, value: str) -> None:
        dark = value == 'dark'
        set_settings('dark', dark)
        retheme(QApplication.instance(), dark)

    def _change_privacy(self, value: bool) -> None:
        set_settings('privacy_mode', value)
        if not stealth.available():
            return
        if not is_admin():
            self.ctrl.status.emit(
                'Stealth requires administrator access.', 'danger')
            return
        ok, msg = stealth.enable() if value else stealth.disable()
        self.ctrl.status.emit(msg, 'good' if ok else 'danger')
