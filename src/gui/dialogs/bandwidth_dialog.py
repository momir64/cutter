"""Bandwidth ranking — which of your devices use the most/least traffic.

Samples every non-admin device for a short fixed window, one at a time (only
ever one device routed through this PC for the scan), and ranks the totals.
Read-only measurement: nothing is cut or blocked here.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem,
)

from gui.dialogs.base import Dialog
from gui.theme import THEME
from gui.widgets.device_row import display_name


def _human(n: float) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024
    return f'{n:.1f} TB'


class BandwidthDialog(Dialog):
    def __init__(self, controller, parent=None) -> None:
        super().__init__('Bandwidth Ranking', parent, width=620, height=440)
        self.ctrl = controller
        self._results: dict[str, dict] = {}   # mac -> {'bytes', 'packets'}

        self.content.addWidget(self.caption(
            'Samples each device for a few seconds in turn (routed through this '
            'PC, then restored) and ranks them by traffic seen during that window. '
            'A short sample is a snapshot, not a perfect average — re-run for a '
            'steadier read.'))

        row = QHBoxLayout()
        self._status = QLabel('Idle')
        self._status.setObjectName('StatusLine')
        row.addWidget(self._status, 1)
        self._start_btn = QPushButton('Start Scan')
        self._start_btn.setProperty('accent', 'primary')
        self._start_btn.clicked.connect(self._start)
        self._cancel_btn = QPushButton('Cancel')
        self._cancel_btn.clicked.connect(self._cancel)
        self._cancel_btn.hide()
        row.addWidget(self._start_btn)
        row.addWidget(self._cancel_btn)
        self.content.addLayout(row)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['Device', 'Traffic', 'Packets'])
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.horizontalHeader().setHighlightSections(False)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for c in (1, 2):
            self._table.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.content.addWidget(self._table, 1)

        c = controller
        c.bandwidth_progress.connect(self._on_progress)
        c.bandwidth_result.connect(self._on_result)
        c.bandwidth_finished.connect(self._on_finished)

    # -- lifecycle -------------------------------------------------------------

    def _start(self) -> None:
        self._results.clear()
        self._table.setRowCount(0)
        self._start_btn.hide()
        self._cancel_btn.show()
        self._set_status('Starting…', 'accent')
        self.ctrl.start_bandwidth_scan(sample_seconds=8)

    def _cancel(self) -> None:
        self.ctrl.cancel_bandwidth_scan()
        self._set_status('Cancelling…', 'warn')

    def _on_progress(self, index: int, total: int, label: str) -> None:
        self._set_status(f'Sampling {index}/{total}: {label}', 'accent')

    def _on_result(self, mac: str, total_bytes: int, total_packets: int) -> None:
        self._results[mac] = {'bytes': total_bytes, 'packets': total_packets}
        self._render()

    def _on_finished(self) -> None:
        self._start_btn.show()
        self._cancel_btn.hide()
        if self._results:
            self._set_status(f'Done — {len(self._results)} device'
                             f'{"s" * (len(self._results) != 1)} sampled.', 'good')
        else:
            self._set_status('Idle', 'muted')

    def _set_status(self, text: str, level: str) -> None:
        self._status.setText(text)
        self._status.setProperty('level', level if level in
                                 ('good', 'warn', 'danger', 'accent') else None)
        self._status.style().unpolish(self._status)
        self._status.style().polish(self._status)

    # -- rendering ---------------------------------------------------------

    def _render(self) -> None:
        rows = sorted(self._results.items(), key=lambda kv: kv[1]['bytes'], reverse=True)
        self._table.setRowCount(len(rows))
        for r, (mac, stats) in enumerate(rows):
            device = self.ctrl.device_by_mac(mac)
            name = display_name(device) if device else mac
            sub = f'  ·  {device["ip"]}' if device else ''
            self._set(r, 0, f'{name}{sub}', THEME.text)
            self._set(r, 1, _human(stats['bytes']), THEME.text_muted)
            self._set(r, 2, str(stats['packets']), THEME.text_muted)

    def _set(self, row: int, col: int, text: str, color: str) -> None:
        item = QTableWidgetItem(text)
        item.setForeground(THEME.qcolor(color))
        if col > 0:
            item.setTextAlignment(Qt.AlignCenter)
        self._table.setItem(row, col, item)

    def closeEvent(self, event):
        self.ctrl.cancel_bandwidth_scan()
        super().closeEvent(event)
