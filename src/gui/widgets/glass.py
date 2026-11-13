"""Window chrome — the frameless, solid, edge-resizable shell.

``GlassRoot`` paints one opaque panel. ``_Frameless`` turns any top-level widget
into a borderless, draggable, edge-resizable window using Qt6's native
``startSystemMove`` / ``startSystemResize``. The window is fully opaque (no
layered/translucent surface, no Qt drop-shadow effect): on Windows the shadow,
rounded corners and hairline border come from DWM itself, and are switched off
when the window is maximized or snapped to a screen edge. ``GlassWindow`` and
``GlassDialog`` are the two concrete shells the app builds on.
"""
from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QDialog, QVBoxLayout, QWidget

from gui.theme import THEME

_WM_NCCALCSIZE   = 0x0083
_WM_NCHITTEST    = 0x0084
_WM_EXITSIZEMOVE = 0x0232   # fires once, exactly when a native drag/resize loop ends
_HTCLIENT, _HTCAPTION = 1, 2
_HTLEFT, _HTRIGHT = 10, 11
_HTTOP, _HTTOPLEFT, _HTTOPRIGHT = 12, 13, 14
_HTBOTTOM, _HTBOTTOMLEFT, _HTBOTTOMRIGHT = 15, 16, 17

RADIUS = 16          # kept for callers; corner rounding is DWM's job now
DIALOG_RADIUS = 14
_GRIP = 6            # px hot-zone just inside the window edge for resizing


class GlassRoot(QWidget):
    """The window's single opaque panel. Everything else sits inside it."""

    def __init__(self, radius: int = 0, parent: QWidget = None) -> None:
        super().__init__(parent)
        self.setObjectName('GlassRoot')
        self.setAttribute(Qt.WA_OpaquePaintEvent, True)

    def paintEvent(self, _event) -> None:
        r, g, b = THEME.window_rgba[:3]
        QPainter(self).fillRect(self.rect(), QColor(r, g, b))


class _Frameless:
    """Shared frameless behavior for QWidget / QDialog top-levels.

    Subclasses call ``_build_glass()`` and add content to ``self.body`` (a
    QVBoxLayout inside the root panel).
    """

    def _build_glass(self, radius: int = 0, margin: int = 0) -> None:
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        self.setMouseTracking(True)
        self._margin = 0          # no transparent margin any more
        self._base_radius = 0     # DWM rounds the corners, not us
        # Per-edge snap state (updated by _check_snap_state)
        self._snapped_left = self._snapped_right = False
        self._snapped_top = self._snapped_bottom = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.root = GlassRoot(0, self)
        self.root.setMouseTracking(True)
        outer.addWidget(self.root)

        self.body = QVBoxLayout(self.root)
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(0)

    # -- edge resizing via native system resize -----------------------------

    def _edges_at(self, pos):
        r = self.rect()
        x, y = pos.x(), pos.y()
        edges = Qt.Edge(0)
        if x < _GRIP and not self._snapped_left:                     edges |= Qt.LeftEdge
        if x >= r.width() - _GRIP and not self._snapped_right:       edges |= Qt.RightEdge
        if y < _GRIP and not self._snapped_top:                      edges |= Qt.TopEdge
        if y >= r.height() - _GRIP and not self._snapped_bottom:     edges |= Qt.BottomEdge
        return edges

    @staticmethod
    def _cursor_for(edges):
        horiz = edges & (Qt.LeftEdge | Qt.RightEdge)
        vert = edges & (Qt.TopEdge | Qt.BottomEdge)
        if horiz and vert:
            tl_br = (edges & Qt.LeftEdge and edges & Qt.TopEdge) or \
                    (edges & Qt.RightEdge and edges & Qt.BottomEdge)
            return Qt.SizeFDiagCursor if tl_br else Qt.SizeBDiagCursor
        if horiz:
            return Qt.SizeHorCursor
        if vert:
            return Qt.SizeVerCursor
        return Qt.ArrowCursor

    def mouseMoveEvent(self, event):
        if self.isMaximized():
            self.unsetCursor()
        else:
            self.setCursor(self._cursor_for(self._edges_at(event.position().toPoint())))
        super().mouseMoveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and not self.isMaximized():
            edges = self._edges_at(event.position().toPoint())
            if edges and (handle := self.windowHandle()):
                handle.startSystemResize(edges)
                return
        super().mousePressEvent(event)

    def leaveEvent(self, event):
        self.unsetCursor()
        super().leaveEvent(event)

    def start_drag(self) -> None:
        """Called by a title bar to move the whole window natively."""
        if handle := self.windowHandle():
            handle.startSystemMove()

    # -- Windows: Aero Snap + native shadow / rounding ------------------------

    def _enable_snap(self) -> None:
        """Add WS_THICKFRAME | WS_MAXIMIZEBOX | WS_MINIMIZEBOX so Aero Snap, Snap
        Layouts and the native DWM shadow work, then commit with SWP_FRAMECHANGED."""
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        get = user32.GetWindowLongPtrW
        put = user32.SetWindowLongPtrW
        get.restype, get.argtypes = ctypes.c_ssize_t, (wintypes.HWND, ctypes.c_int)
        put.restype, put.argtypes = ctypes.c_ssize_t, (wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t)
        hwnd = wintypes.HWND(int(self.winId()))
        style = get(hwnd, -16)   # GWL_STYLE
        want = style | 0x00040000 | 0x00010000 | 0x00020000  # WS_THICKFRAME | WS_MAXIMIZEBOX | WS_MINIMIZEBOX
        if want != style:
            put(hwnd, -16, want)
            # SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED
            user32.SetWindowPos(hwnd, None, 0, 0, 0, 0,
                                0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020)

    def _apply_dwm(self) -> None:
        """Windows 11: round the corners and keep the thin border — except when the
        window fills the screen or touches an edge (maximized / snapped), where
        both would show as a gap or an outline against the screen edge."""
        if sys.platform != 'win32':
            return
        try:
            import ctypes
            flush = (self.isMaximized() or self.isFullScreen() or self._snapped_left or
                     self._snapped_right or self._snapped_top or self._snapped_bottom)
            pref = ctypes.c_int(1 if flush else 2)             # DWMWCP_DONOTROUND / DWMWCP_ROUND
            if flush:
                border = ctypes.c_uint(0xFFFFFFFE)             # DWMWA_COLOR_NONE
            else:
                r, g, b = self._border_rgb()
                border = ctypes.c_uint(r | (g << 8) | (b << 16))   # COLORREF 0x00BBGGRR
            hwnd = int(self.winId())
            dwm = ctypes.windll.dwmapi
            dwm.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(pref), 4)     # WINDOW_CORNER_PREFERENCE
            dwm.DwmSetWindowAttribute(hwnd, 34, ctypes.byref(border), 4)   # BORDER_COLOR
        except Exception:
            pass

    @staticmethod
    def _border_rgb():
        """The theme's hairline colour flattened onto the (opaque) window colour."""
        base = THEME.window_rgba[:3]
        c = THEME.qcolor(THEME.border_strong)
        a = c.alphaF()
        return tuple(round(base[i] * (1 - a) + (c.red(), c.green(), c.blue())[i] * a) for i in range(3))

    _snappable = True   # GlassDialog turns this off — dialogs shouldn't snap/maximize

    def showEvent(self, event) -> None:
        if sys.platform == 'win32':
            if self._snappable:
                self._enable_snap()   # WS_THICKFRAME|MAXIMIZEBOX|MINIMIZEBOX: without
                                      # these styles Windows won't snap/maximize on drag
            self._apply_dwm()
        super().showEvent(event)

    def nativeEvent(self, event_type, message):
        if sys.platform == 'win32' and event_type == b'windows_generic_MSG':
            import ctypes, ctypes.wintypes
            msg = ctypes.wintypes.MSG.from_address(int(message))
            if msg.message == _WM_NCCALCSIZE and msg.wParam:
                # Client area = the whole HWND, so the native frame is invisible.
                # When maximized, clamp it to the monitor work area (the HWND may
                # overhang it by the frame size, or not at all).
                user32 = ctypes.windll.user32
                hwnd = ctypes.wintypes.HWND(msg.hWnd)
                if user32.IsZoomed(hwnd):
                    import struct
                    mi = ctypes.create_string_buffer(40)
                    ctypes.c_uint32.from_buffer(mi, 0).value = 40
                    mon = user32.MonitorFromWindow(hwnd, 2)  # MONITOR_DEFAULTTONEAREST
                    if user32.GetMonitorInfoW(mon, mi):
                        wl, wt, wr, wb = struct.unpack('<4i', mi.raw[20:36])
                        rect = ctypes.wintypes.RECT.from_address(msg.lParam)
                        rect.left = max(rect.left, wl)
                        rect.top = max(rect.top, wt)
                        rect.right = min(rect.right, wr)
                        rect.bottom = min(rect.bottom, wb)
                return True, 0
            if msg.message == _WM_NCHITTEST:
                return True, self._nchittest(int(msg.lParam))
            if msg.message == _WM_EXITSIZEMOVE:
                self._check_snap_state()   # a drag/resize just ended: settle the final state
        return super().nativeEvent(event_type, message)

    def _nchittest(self, lp: int) -> int:
        import ctypes
        from PySide6.QtCore import QPoint
        # Physical screen coords from lParam (GET_X/Y_LPARAM convention)
        px = ctypes.c_short(lp & 0xFFFF).value
        py = ctypes.c_short((lp >> 16) & 0xFFFF).value
        # Windows sends physical pixels; Qt geometry is in logical pixels.
        screen = self.screen()
        dpr = screen.devicePixelRatio() if screen else 1.0
        local = self.mapFromGlobal(QPoint(round(px / dpr), round(py / dpr)))
        x, y = local.x(), local.y()
        w, h = self.width(), self.height()

        if not self.isMaximized():
            can_l = x < _GRIP and not self._snapped_left
            can_r = x >= w - _GRIP and not self._snapped_right
            can_t = y < _GRIP and not self._snapped_top
            can_b = y >= h - _GRIP and not self._snapped_bottom
            if can_l and can_t: return _HTTOPLEFT
            if can_r and can_t: return _HTTOPRIGHT
            if can_l and can_b: return _HTBOTTOMLEFT
            if can_r and can_b: return _HTBOTTOMRIGHT
            if can_t: return _HTTOP
            if can_b: return _HTBOTTOM
            if can_l: return _HTLEFT
            if can_r: return _HTRIGHT

        # Titlebar area → HTCAPTION enables Aero Snap on drag-to-edge and the
        # Windows 11 Snap Layouts popup; skip buttons so they stay clickable.
        if y < getattr(self, '_titlebar_h', 38):
            from PySide6.QtWidgets import QAbstractButton, QApplication
            if not isinstance(QApplication.widgetAt(round(px / dpr), round(py / dpr)), QAbstractButton):
                return _HTCAPTION

        return _HTCLIENT

    # -- keeping resize zones + DWM look in step with the window's state ------

    def changeEvent(self, event) -> None:
        from PySide6.QtCore import QEvent
        if event.type() == QEvent.Type.WindowStateChange:
            self._check_snap_state()
            titlebar = getattr(self, 'titlebar', None)
            if titlebar is not None:
                titlebar.sync_state()   # maximize ↔ restore icon, for dialogs too
        super().changeEvent(event)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if sys.platform == 'win32':
            from PySide6.QtCore import QTimer
            self._check_snap_state()
            QTimer.singleShot(60, self._check_snap_state)    # once the HWND has settled
            QTimer.singleShot(220, self._check_snap_state)   # and again for slow transitions

    def _native_rects(self):
        """((window rect), (monitor work area)) in physical px, or None."""
        try:
            import ctypes, struct
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            hwnd = wintypes.HWND(int(self.winId()))
            wr = wintypes.RECT()
            if not user32.GetWindowRect(hwnd, ctypes.byref(wr)):
                return None
            mi = ctypes.create_string_buffer(40)
            ctypes.c_uint32.from_buffer(mi, 0).value = 40
            if not user32.GetMonitorInfoW(user32.MonitorFromWindow(hwnd, 2), mi):
                return None
            return (wr.left, wr.top, wr.right, wr.bottom), struct.unpack('<4i', mi.raw[20:36])
        except Exception:
            return None

    def _check_snap_state(self) -> None:
        """Record which edges touch the work area (they get no resize grip and no
        rounded corner / border), then refresh the DWM look."""
        if not self._snappable:
            return   # dialogs: never flush/snapped, regardless of where they sit
        if self.isMaximized() or self.isFullScreen():
            self._snapped_left = self._snapped_right = False
            self._snapped_top = self._snapped_bottom = False
        else:
            screen = self.screen()
            if not screen:
                return
            rects = self._native_rects() if sys.platform == 'win32' else None
            if rects:
                # The HWND's real rectangle (physical px). Qt's geometry() can
                # still be the old full-screen rect mid-transition.
                (wl, wt, wr, wb), (al, at, ar, ab) = rects
                tol = round(10 * screen.devicePixelRatio())
                self._snapped_left, self._snapped_right = abs(wl - al) <= tol, abs(wr - ar) <= tol
                self._snapped_top, self._snapped_bottom = abs(wt - at) <= tol, abs(wb - ab) <= tol
            else:
                wa, g, tol = screen.availableGeometry(), self.geometry(), 10
                self._snapped_left   = abs(g.left()   - wa.left())   <= tol
                self._snapped_right  = abs(g.right()  - wa.right())  <= tol
                self._snapped_top    = abs(g.top()    - wa.top())    <= tol
                self._snapped_bottom = abs(g.bottom() - wa.bottom()) <= tol
        self._apply_dwm()

    def on_theme_changed(self) -> None:
        """New theme → repaint the panel and recolour the DWM border."""
        self.root.update()
        self._apply_dwm()


class GlassWindow(_Frameless, QWidget):
    def __init__(self, parent: QWidget = None) -> None:
        super().__init__(parent)
        self._build_glass()


class GlassDialog(_Frameless, QDialog):
    _snappable = False   # dialogs: no drag-to-edge snap, no maximize

    def __init__(self, parent: QWidget = None) -> None:
        super().__init__(parent)
        self._build_glass()
        self.root.setObjectName('GlassDialogRoot')
