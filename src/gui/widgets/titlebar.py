"""Custom title bar — Windows-style controls (minimize / maximize / close on right).

Frameless windows lose the native title bar, so we draw our own: a draggable bar
with an optional app logo + title on the left and native-style window chrome
buttons (minus / square / close) on the right.
"""
from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QAbstractButton, QHBoxLayout, QLabel, QPushButton, QWidget

from gui import icons
from gui.theme import THEME


class _WinBtn(QPushButton):
    """Chrome button that spans the full title bar height (native Windows
    caption buttons are flush top-to-bottom and flush to the window edge —
    that's what makes the top-right corner's hover/hit-test feel right)."""

    def __init__(self, icon_name: str, tip: str, is_close: bool = False,
                 height: int = 32, parent: QWidget = None) -> None:
        super().__init__(parent)
        self._icon_name = icon_name
        self._is_close  = is_close
        self.setFixedSize(46, height)
        self.setToolTip(tip)
        self.setCursor(Qt.ArrowCursor)
        self.setFocusPolicy(Qt.NoFocus)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._apply(hovered=False)

    def set_icon_name(self, name: str) -> None:
        self._icon_name = name
        self._apply(hovered=self.underMouse())

    def _apply(self, hovered: bool) -> None:
        # Icon color never changes on hover (matches native chrome) — only
        # close swaps to white so the glyph stays readable against red.
        col = '#ffffff' if (hovered and self._is_close) else THEME.text_faint
        if hovered:
            bg = '#c42b1c' if self._is_close else THEME.surface_hover
        else:
            bg = 'transparent'
        # size=15, stroke=1.9: matches patchwork's window-button render exactly —
        # the global icon default (stroke 2.0 at 14px) reads a touch heavy here,
        # most visible on the full-diagonal close glyph.
        self.setIcon(icons.icon(self._icon_name, col, 15, stroke=1.9))
        self.setIconSize(QSize(15, 15))
        self.setStyleSheet(
            f'QPushButton {{ background: {bg}; border: none; border-radius: 0px; padding: 0; }}'
        )

    def enterEvent(self, e) -> None:
        self._apply(hovered=True)
        super().enterEvent(e)

    def leaveEvent(self, e) -> None:
        self._apply(hovered=False)
        super().leaveEvent(e)


class TitleBar(QWidget):
    """Draggable title bar.

    Left: optional logo + title.  Right: a slot for extra controls via
    ``add_right``, then [−] [□] [×] chrome buttons.
    """

    def __init__(self, win: QWidget, title: str = '', logo: bool = False,
                 minimize: bool = True, zoom: bool = True, height: int = 38) -> None:
        super().__init__(win)
        self._win = win
        self.setFixedHeight(height)
        win._titlebar_h = height   # so the window's hit-test knows the real bar height

        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 0, 0, 0)
        lay.setSpacing(8)

        if logo:
            mark = QLabel()
            mark.setPixmap(icons.app_logo(20).scaled(
                20, 20, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            mark.setAttribute(Qt.WA_TransparentForMouseEvents)
            lay.addWidget(mark)

        self._title = QLabel(title)
        self._title.setProperty('role', 'titlebar')
        self._title.setAttribute(Qt.WA_TransparentForMouseEvents)
        lay.addWidget(self._title)

        lay.addStretch(1)

        self._right = QHBoxLayout()
        self._right.setSpacing(4)
        self._right.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(self._right)

        self._btn_min = self._btn_max = None

        # Buttons span the full bar height, flush to the window's top-right
        # corner — that's what native Windows caption buttons do, and it's
        # what makes hover / Snap-Layouts hit-testing feel right at the edge.
        if minimize:
            self._btn_min = _WinBtn('minus', 'Minimize', height=height, parent=self)
            self._btn_min.clicked.connect(win.showMinimized)
            lay.addWidget(self._btn_min)

        if zoom:
            self._btn_max = _WinBtn('square', 'Maximize', height=height, parent=self)
            self._btn_max.clicked.connect(self._toggle_max)
            lay.addWidget(self._btn_max)

        self._btn_close = _WinBtn('close', 'Close', is_close=True, height=height, parent=self)
        self._btn_close.clicked.connect(win.close)
        lay.addWidget(self._btn_close)

    def _toggle_max(self) -> None:
        self._win.showNormal() if self._win.isMaximized() else self._win.showMaximized()

    def add_right(self, widget: QWidget) -> None:
        self._right.addWidget(widget)

    def set_title(self, text: str) -> None:
        self._title.setText(text)

    def sync_state(self) -> None:
        """Update maximize/restore icon after window state changes."""
        if self._btn_max is None:
            return
        maxed = self._win.isMaximized()
        self._btn_max.set_icon_name('restore-win' if maxed else 'square')
        self._btn_max.setToolTip('Restore' if maxed else 'Maximize')

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self._win.start_drag()
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:
        if self._btn_max is not None:   # only windows with a maximize button zoom
            self._win.showNormal() if self._win.isMaximized() else self._win.showMaximized()
        super().mouseDoubleClickEvent(event)
