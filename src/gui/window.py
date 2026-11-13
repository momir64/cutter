"""MainWindow — presentation only. Renders controller state, emits user intent.

Device-centric: a scrollable list of device cards, one primary Cut per card, and
a right-click context menu for the rest (one-way, lag, blocker, traffic, info —
applies to the whole multi-selection when more than one device is selected). A
glass privilege banner with a real "Set Up Access" button replaces silent
failure. No packet/firewall logic here — all of that lives in the Controller.
"""
from __future__ import annotations

from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QAction, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox,
    QProgressBar, QPushButton, QScrollArea, QSystemTrayIcon, QVBoxLayout, QWidget,
)

from gui import icons
from gui.controller import Controller
from gui.theme import THEME, retheme
from gui.widgets.controls import IconButton, label
from gui.widgets.device_row import DeviceRow, display_name
from gui.widgets.glass import GlassWindow
from gui.widgets.titlebar import TitleBar
from tools.utils_gui import get_settings, set_settings


class MainWindow(GlassWindow):
    def __init__(self, controller: Controller) -> None:
        super().__init__()
        self.ctrl = controller
        self.setWindowTitle('cutter')
        self.setWindowIcon(icons.app_icon())
        self.resize(1120, 760)
        # The narrowest width where the toolbar's buttons + filter box still keep
        # their natural label sizes (measured) — below it Qt squeezes every button
        # down to icon-only, illegible labels.
        self.setMinimumSize(840, 470)

        self._rows: dict[str, DeviceRow] = {}
        self._selected: str | None = None  # anchor for shift-range + single-device dialogs
        self._multi: set[str] = set()      # ctrl/shift accumulated selection, for bulk actions
        self._sel_undo: list[tuple[frozenset, str | None]] = []
        self._sel_redo: list[tuple[frozenset, str | None]] = []
        self._dialogs: dict[str, QWidget] = {}
        self._quitting = False
        self._is_admin = True
        self._onboarded = False

        self._build_titlebar()
        self._build_toolbar()
        self._build_banner()
        self._build_list()
        self._build_statusbar()
        self._build_tray()
        self._build_selection_shortcuts()

        QApplication.instance().installEventFilter(self)

        c = self.ctrl
        c.devices_changed.connect(self._on_devices)
        c.states_changed.connect(self._refresh_states)
        c.status.connect(self._on_status)
        c.scan_started.connect(self._on_scan_started)
        c.scan_progress.connect(self._on_scan_progress)
        c.scan_finished.connect(self._on_scan_finished)
        c.privilege_changed.connect(self._on_privilege)
        c.host_blocks_changed.connect(lambda _: self._refresh_states())

    # -- construction --------------------------------------------------------

    def _content(self) -> QVBoxLayout:
        wrap = QWidget()
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(12)
        self.body.addWidget(wrap)
        return lay

    def _build_titlebar(self) -> None:
        self.titlebar = TitleBar(self, title='cutter', logo=True)
        self.body.addWidget(self.titlebar)
        self._root_lay = self._content()

    def changeEvent(self, event) -> None:
        from PySide6.QtCore import QEvent
        if event.type() == QEvent.Type.WindowStateChange:
            self.titlebar.sync_state()
        super().changeEvent(event)

    def _build_toolbar(self) -> None:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self._scan_btn = IconButton('scan', 'Scan', 'Fast ARP scan', variant='toolbar')
        self._scan_btn.clicked.connect(lambda: self.ctrl.scan(0))
        self._deep_btn = IconButton('deepscan', 'Deep', 'Thorough ping sweep', variant='toolbar')
        self._deep_btn.clicked.connect(lambda: self.ctrl.scan(1))
        bar.addWidget(self._scan_btn)
        bar.addWidget(self._deep_btn)

        self._search = QLineEdit()
        self._search.setPlaceholderText('Filter devices…')
        self._search.setClearButtonEnabled(True)
        self._search.addAction(icons.icon('search', THEME.text_faint, 16), QLineEdit.LeadingPosition)
        self._search.textChanged.connect(self._apply_filter)
        bar.addWidget(self._search, 1)

        bandwidth = IconButton('traffic', 'Bandwidth', 'Rank your devices by traffic used', variant='toolbar')
        bandwidth.clicked.connect(lambda: self._open('bandwidth'))
        bar.addWidget(bandwidth)

        restore = IconButton('restore', 'Restore All', 'Restore every device', variant='toolbar')
        restore.clicked.connect(self.ctrl.unkill_all)
        cut_all = IconButton('killall', 'Cut All', 'Cut every device', variant='solid')
        cut_all.set_active(True, 'danger')
        cut_all.clicked.connect(self._confirm_cut_all)
        settings = IconButton('settings', tooltip='Settings', variant='toolbar')
        settings.clicked.connect(lambda: self._open('settings'))
        bar.addWidget(restore)
        bar.addWidget(cut_all)
        bar.addWidget(settings)
        self._root_lay.addLayout(bar)

        self._progress = QProgressBar()
        self._progress.setObjectName('ScanBar')
        self._progress.setFixedHeight(3)
        self._progress.setTextVisible(False)
        self._progress.hide()
        self._root_lay.addWidget(self._progress)

    def _build_banner(self) -> None:
        self._banner = QFrame()
        self._banner.setObjectName('Banner')
        self._banner.setProperty('tone', 'warn')
        lay = QHBoxLayout(self._banner)
        lay.setContentsMargins(14, 11, 12, 11)
        lay.setSpacing(11)
        self._banner_icon = QLabel()
        self._banner_icon.setProperty('role', 'bannerIcon')
        self._banner_icon.setFixedSize(20, 20)
        self._banner_icon.setAlignment(Qt.AlignCenter)
        lay.addWidget(self._banner_icon, 0, Qt.AlignVCenter)   # level with the message, not pinned to the top
        self._banner_text = label('', 'banner')
        self._banner_text.setWordWrap(True)
        lay.addWidget(self._banner_text, 1, Qt.AlignVCenter)
        self._banner_btn = QPushButton('Set Up Access')
        self._banner_btn.setProperty('accent', 'primary')
        self._banner_btn.setCursor(Qt.PointingHandCursor)
        self._banner_btn.clicked.connect(self._open_privilege)
        lay.addWidget(self._banner_btn, 0, Qt.AlignVCenter)
        self._banner.hide()
        self._root_lay.addWidget(self._banner)

    def _build_list(self) -> None:
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        holder = QWidget()
        self._list = QVBoxLayout(holder)
        self._list.setContentsMargins(0, 0, 4, 0)
        self._list.setSpacing(8)
        self._list.addStretch(1)
        self._scroll.setWidget(holder)
        self._root_lay.addWidget(self._scroll, 1)

    def _build_statusbar(self) -> None:
        bar = QHBoxLayout()
        self._status = QLabel('Ready.')
        self._status.setObjectName('StatusLine')
        self._count = label('', 'faint')
        bar.addWidget(self._status, 1)
        bar.addWidget(self._count)
        self._root_lay.addLayout(bar)

    def _build_tray(self) -> None:
        self._tray = QSystemTrayIcon(icons.app_icon(), self)
        self._tray.setToolTip('cutter')
        menu = QMenu()
        menu.addAction(QAction('Show cutter', self, triggered=self._restore_window))
        menu.addSeparator()
        menu.addAction(QAction('Cut All', self, triggered=self.ctrl.kill_all))
        menu.addAction(QAction('Restore All', self, triggered=self.ctrl.unkill_all))
        menu.addSeparator()
        menu.addAction(QAction('Quit', self, triggered=self._real_quit))
        self._tray.setContextMenu(menu)
        self._tray.activated.connect(
            lambda r: self._restore_window() if r == QSystemTrayIcon.Trigger else None)
        self._tray.show()

    # -- controller signal handlers -----------------------------------------

    def _on_devices(self, devices: list) -> None:
        macs = {d['mac'] for d in devices}
        for mac in list(self._rows):
            if mac not in macs:
                self._rows.pop(mac).deleteLater()
        self._multi &= macs
        if self._selected and self._selected not in macs:
            self._selected = None
        for i in reversed(range(self._list.count() - 1)):
            item = self._list.takeAt(i)
            if item.widget():
                item.widget().setParent(None)
        for device in devices:
            row = self._rows.get(device['mac'])
            if row is None or row.device['ip'] != device['ip']:
                if row:
                    row.deleteLater()
                row = DeviceRow(device)
                row.clicked.connect(self._select)
                row.activated.connect(self._activate_device)
                row.cut_toggled.connect(self.ctrl.toggle_cut)
                row.spoof_toggled.connect(self._on_spoof_toggled)
                row.context_requested.connect(self._show_device_menu)
                self._rows[device['mac']] = row
            else:
                row.refresh_text(device)
            self._list.insertWidget(self._list.count() - 1, row)
        self._refresh_selection_visuals()
        self._refresh_states()
        self._apply_filter(self._search.text())
        self._update_count()

    def _on_spoof_toggled(self, mac: str) -> None:
        """Toggle routing-through-us. Turning it OFF while blocks depend on it
        warns first and clears them on confirm (keeps them on decline)."""
        if self.ctrl.is_spoofed(mac):
            blocks = self.ctrl.device_blocks(mac)
            if blocks:
                from PySide6.QtWidgets import QMessageBox
                resp = QMessageBox.warning(
                    self, 'Stop routing this device?',
                    'This device has active effects that need it routed through '
                    'your PC:\n\n  • ' + '\n  • '.join(blocks) + '\n\n'
                    'Stopping the spoof will clear them. Continue?',
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                if resp != QMessageBox.Yes:
                    self._refresh_states()          # re-sync the toggle we bounced
                    return
        self.ctrl.toggle_spoof(mac)

    def _refresh_states(self) -> None:
        for mac, row in self._rows.items():
            device = self.ctrl.device_by_mac(mac)
            if device:
                row.set_state(self.ctrl.state_of(device))
        self._update_count()

    def _on_status(self, message: str, level: str) -> None:
        self._status.setText(message)
        self._status.setProperty('level', level if level in
                                 ('danger', 'good', 'warn', 'accent') else None)
        self._status.style().unpolish(self._status)
        self._status.style().polish(self._status)

    def _on_scan_started(self, scan_type: int) -> None:
        self._progress.show()
        self._progress.setRange(0, 0) if scan_type == 0 else self._progress.setRange(0, 100)
        self._scan_btn.setEnabled(False)
        self._deep_btn.setEnabled(False)

    def _on_scan_progress(self, done: int, total: int) -> None:
        if total:
            self._progress.setRange(0, total)
            self._progress.setValue(done)

    def _on_scan_finished(self, _completed: bool) -> None:
        self._progress.hide()
        self._scan_btn.setEnabled(True)
        self._deep_btn.setEnabled(True)

    def _on_privilege(self, admin: bool, iface: str) -> None:
        self._is_admin = admin
        if admin:
            self._banner.hide()
        else:
            self._banner_text.setText(
                'cutter needs administrator access to scan and cut devices. '
                'You can still ping-scan for now — set up access to unlock full power.')
            self._paint_banner()
            self._banner.show()
            self._maybe_onboard()
        self._update_count()

    def _maybe_onboard(self) -> None:
        """First-run: in the packaged app, guide the user through Set Up Access
        once. Dev runs just show the banner button (no interruption)."""
        import sys
        if self._onboarded:
            return
        self._onboarded = True
        if getattr(sys, 'frozen', False):
            self._open_privilege()

    def _paint_banner(self) -> None:
        self._banner_icon.setPixmap(icons.pixmap('lock', THEME.warn, 18))

    # -- selection & action bar ---------------------------------------------

    def _build_selection_shortcuts(self) -> None:
        QShortcut(QKeySequence('Ctrl+Z'), self, activated=self._undo_selection)
        QShortcut(QKeySequence('Ctrl+Shift+Z'), self, activated=self._redo_selection)
        QShortcut(QKeySequence('Ctrl+Y'), self, activated=self._redo_selection)

    def eventFilter(self, obj, event) -> bool:
        # Clicking anything in this window that isn't a device card (or inside
        # one — its Spoof/Cut buttons count) clears the selection, like a file
        # manager deselecting on an empty-area click. An unaccepted mouse press
        # gets redelivered up the parent chain (row -> ... -> this window), and
        # this filter sees every one of those hops — so resolve the actual
        # clicked widget once via widgetAt(), rather than re-deriving it from
        # whatever `obj` happens to be at each hop (the last hop is always this
        # window itself, which isn't inside a DeviceRow, and was wrongly
        # clearing a selection that an earlier, correct hop had just made).
        if event.type() == QEvent.Type.MouseButtonPress and (self._multi or self._selected is not None):
            target = QApplication.widgetAt(event.globalPosition().toPoint())
            if target is not None and target.window() is self:
                node, on_row = target, False
                while node is not None:
                    if isinstance(node, DeviceRow):
                        on_row = True
                        break
                    node = node.parentWidget()
                if not on_row:
                    self._clear_selection()
        return super().eventFilter(obj, event)

    def _select(self, mac: str, modifiers=Qt.NoModifier) -> None:
        """Plain click selects just this row; Ctrl+click toggles it in/out of
        the selection; Shift+click selects the contiguous range from the last
        clicked row to this one — standard list multi-select, no checkboxes."""
        visible_order = [m for m, row in self._rows.items() if not row.isHidden()]
        if modifiers & Qt.ShiftModifier and self._selected in visible_order and mac in visible_order:
            i, j = visible_order.index(self._selected), visible_order.index(mac)
            lo, hi = min(i, j), max(i, j)
            multi = set(visible_order[lo:hi + 1])
            selected = self._selected
        elif modifiers & Qt.ControlModifier:
            multi = set(self._multi)
            multi.symmetric_difference_update({mac})
            selected = mac
        else:
            multi, selected = {mac}, mac
        self._set_selection(multi, selected)

    def _activate_device(self, mac: str) -> None:
        """Double-click: select just this device and open its detail dialog."""
        self._set_selection({mac}, mac)
        self._open_device()

    def _clear_selection(self) -> None:
        if self._multi or self._selected is not None:
            self._set_selection(set(), None)

    def _set_selection(self, multi: set, selected: str | None, record: bool = True) -> None:
        """The single place selection actually changes — everything else (click,
        shift/ctrl-click, right-click, background-click, double-click, undo/redo)
        routes through here so undo/redo history stays complete and consistent."""
        if multi == self._multi and selected == self._selected:
            return
        if record:
            self._sel_undo.append((frozenset(self._multi), self._selected))
            self._sel_redo.clear()
        self._multi, self._selected = multi, selected
        self._refresh_selection_visuals()

    def _undo_selection(self) -> None:
        if not self._sel_undo:
            return
        self._sel_redo.append((frozenset(self._multi), self._selected))
        multi, selected = self._sel_undo.pop()
        self._multi, self._selected = set(multi), selected
        self._refresh_selection_visuals()

    def _redo_selection(self) -> None:
        if not self._sel_redo:
            return
        self._sel_undo.append((frozenset(self._multi), self._selected))
        multi, selected = self._sel_redo.pop()
        self._multi, self._selected = set(multi), selected
        self._refresh_selection_visuals()

    def _refresh_selection_visuals(self) -> None:
        for m, row in self._rows.items():
            row.set_selected(m in self._multi)
        self._update_count()

    def _selected_device(self):
        """The single device for single-target dialogs (Blocker/Traffic/Info) —
        only defined when exactly one device is selected."""
        mac = next(iter(self._multi)) if len(self._multi) == 1 else None
        return self.ctrl.device_by_mac(mac) if mac else None

    def _targets(self) -> list[str]:
        """Devices a bulk action (Cut/One-way/Lag) applies to."""
        return sorted(self._multi)

    def _on_selected(self, fn) -> None:
        for mac in self._targets():
            fn(mac)

    def _build_device_menu(self):
        """Build (but don't show) the right-click menu for the current
        selection — the bulk/device actions that used to live in a bottom
        action bar now live here, same as patchwork's context menus. Returns
        None when nothing actionable is selected."""
        devices = [d for m in self._targets()
                  if (d := self.ctrl.device_by_mac(m)) and not d['admin']]
        if not devices:
            return None
        multi = len(devices) > 1
        states = [self.ctrl.state_of(d) for d in devices]
        all_cut = all(s['cut'] for s in states)
        all_oneway = all(s['one_way'] for s in states)
        all_lag = all(s['lag'] for s in states)

        menu = QMenu(self)
        menu.addAction(icons.icon('restore' if all_cut else 'cut', THEME.text, 16),
                       'Restore' if all_cut else 'Cut',
                       lambda: self._on_selected(self.ctrl.toggle_cut))
        menu.addAction(icons.icon('oneway', THEME.text, 16),
                       'Stop one-way block' if all_oneway else 'One-way block',
                       lambda: self._on_selected(self.ctrl.toggle_one_way))
        menu.addAction(icons.icon('lag', THEME.text, 16),
                       'Stop lag switch' if all_lag else 'Lag switch', self._open_lag)
        if not multi:
            menu.addSeparator()
            menu.addAction(icons.icon('port', THEME.text, 16), 'Blocker', self._open_blocker)
            menu.addAction(icons.icon('traffic', THEME.text, 16), 'Traffic monitor', self._open_traffic)
            menu.addAction(icons.icon('info', THEME.text, 16), 'Device details', self._open_device)
        return menu

    def _show_device_menu(self, mac: str, global_pos) -> None:
        if mac not in self._multi:
            self._set_selection({mac}, mac)
        menu = self._build_device_menu()
        if menu is not None:
            menu.exec(global_pos)

    def _update_count(self) -> None:
        n = max(0, len(self._rows) - 2)
        cut = len(self.ctrl.full_kills)
        iface = self.ctrl.iface_name()
        lock = '' if self._is_admin else '  ·  no admin'
        selected = f'  ·  {len(self._multi)} selected' if len(self._multi) > 1 else ''
        self._count.setText(f'{n} devices · {cut} cut · {iface}{lock}{selected}')

    def _apply_filter(self, text: str) -> None:
        text = text.strip().lower()
        for mac, row in self._rows.items():
            device = self.ctrl.device_by_mac(mac) or row.device
            hay = f'{display_name(device)} {device["ip"]} {device["mac"]} {device.get("vendor","")}'.lower()
            row.setVisible(text in hay)

    # -- dialogs -------------------------------------------------------------

    def _open(self, name: str) -> None:
        dlg = self._dialogs.get(name)
        if dlg is None:
            dlg = self._make_dialog(name)
            self._dialogs[name] = dlg
        dlg.show(); dlg.raise_(); dlg.activateWindow()

    def _make_dialog(self, name: str):
        if name == 'settings':
            from gui.dialogs.settings_dialog import SettingsDialog
            return SettingsDialog(self.ctrl, self)
        if name == 'privilege':
            from gui.dialogs.privilege_dialog import PrivilegeDialog
            return PrivilegeDialog(self.ctrl, self)
        if name == 'bandwidth':
            from gui.dialogs.bandwidth_dialog import BandwidthDialog
            return BandwidthDialog(self.ctrl, self)
        raise KeyError(name)

    def _open_privilege(self) -> None:
        self._open('privilege')

    def _open_blocker(self) -> None:
        from gui.dialogs.blocker_dialog import BlockerDialog
        dlg = self._dialogs.get('blocker')
        if dlg is None:
            dlg = BlockerDialog(self.ctrl, self)
            self._dialogs['blocker'] = dlg
        dlg.set_target(self._selected_device())
        dlg.show(); dlg.raise_(); dlg.activateWindow()

    def _open_traffic(self) -> None:
        device = self._selected_device()
        if not device:
            return
        from gui.dialogs.traffic_dialog import TrafficDialog
        dlg = self._dialogs.get('traffic')
        if dlg is None:
            dlg = TrafficDialog(self.ctrl, self)
            self._dialogs['traffic'] = dlg
        dlg.start(device)
        dlg.show(); dlg.raise_(); dlg.activateWindow()

    def _open_device(self) -> None:
        device = self._selected_device()
        if not device:
            return
        from gui.dialogs.device_dialog import DeviceDialog
        DeviceDialog(self.ctrl, device, self).exec()

    def _open_lag(self) -> None:
        targets = [m for m in self._targets()
                  if (d := self.ctrl.device_by_mac(m)) and not d['admin']]
        if not targets:
            return
        from gui.dialogs.lag_dialog import LagDialog
        if all(self.ctrl.lag_active_for(m) for m in targets):
            for mac in targets:
                self.ctrl.stop_lag_for(mac)
            return
        dlg = LagDialog(self, device_count=len(targets))
        if dlg.exec():
            block_ms, release_ms, direction = dlg.values()
            self.ctrl.start_lag(targets, block_ms, release_ms, direction)

    def _confirm_cut_all(self) -> None:
        if QMessageBox.question(self, 'Cut All',
                                'Cut every non-admin device off the network?') == QMessageBox.Yes:
            self.ctrl.kill_all()

    # -- theme ---------------------------------------------------------------

    def _toggle_theme(self) -> None:
        dark = THEME.name != 'dark'
        set_settings('dark', dark)
        retheme(QApplication.instance(), dark)

    def on_theme_changed(self) -> None:
        super().on_theme_changed()
        self._theme_btn.set_glyph('moon' if THEME.name == 'dark' else 'sun')
        self._paint_banner()

    # -- window lifecycle ----------------------------------------------------

    def _restore_window(self) -> None:
        self.showNormal(); self.raise_(); self.activateWindow()

    def _real_quit(self) -> None:
        self._quitting = True
        self.close()

    def closeEvent(self, event) -> None:
        minimized = bool(get_settings('minimized'))
        if minimized and not self._quitting:
            event.ignore()
            self.hide()
            self._tray.showMessage('cutter', 'Still running in the menu bar.',
                                   QSystemTrayIcon.Information, 2000)
            return
        self.ctrl.shutdown()
        self._tray.hide()
        QApplication.instance().removeEventFilter(self)
        event.accept()
        QApplication.instance().quit()
