"""Identity-shield — hostname leak protection AND MAC-address spoofing (Windows).

Covers three distinct attack surfaces that expose this PC's real identity on
the local network:

  1. Hostname via NetBIOS / LLMNR / mDNS  (ping -a, mDNS PTR queries)
  2. MAC address carried in every Ethernet frame this PC sends
  3. IP address — implicitly rotated when the MAC changes and DHCP renews

``enable()`` applies all three; ``disable()`` reverses everything precisely.
Both are idempotent and safe across multiple app restarts: each sub-shield
stores its own backup in the settings JSON so it can be restored even if the
app is killed mid-way and restarted later.

Only Windows is affected: macOS/Linux have no NetBIOS/LLMNR/Windows-mDNS
responder to disable, and MAC spoofing on those platforms uses different tools
(ip-link / ifconfig) that are not implemented here.
"""
from __future__ import annotations

import random
import re
import subprocess
import sys
from time import sleep
from typing import Any, Optional

from tools.utils_gui import get_settings, set_settings

# ---------------------------------------------------------------------------
# Registry paths — hostname shield
# ---------------------------------------------------------------------------
_LLMNR_KEY = r'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
_LLMNR_VAL = 'EnableMulticast'
_MDNS_KEY = r'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
_MDNS_VAL = 'EnableMDNS'
_NETBT_IFACES = r'SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
_NETBT_VAL = 'NetbiosOptions'   # 0=default(DHCP), 1=enable, 2=disable

_BACKUP_KEY = 'hostname_shield_backup'

# ---------------------------------------------------------------------------
# Registry path — MAC spoof
# ---------------------------------------------------------------------------
_NET_CLASS_KEY = (r'SYSTEM\CurrentControlSet\Control\Class'
                  r'\{4D36E972-E325-11CE-BFC1-08002BE10318}')
_MAC_BACKUP_KEY = 'mac_spoof_backup'

_GUID_RE = re.compile(
    r'([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}'
    r'-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})')


def available() -> bool:
    """True only on Windows — the only OS with these three responders."""
    return sys.platform.startswith('win')


def _winreg():
    import winreg
    return winreg


# ===========================================================================
# Registry helpers — hostname shield
# ===========================================================================

def _read_dword(path: str, name: str) -> Optional[int]:
    winreg = _winreg()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            val, _ = winreg.QueryValueEx(k, name)
            return int(val)
    except OSError:
        return None


def _write_dword(path: str, name: str, value: int) -> bool:
    winreg = _winreg()
    try:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                 winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, value)
        return True
    except OSError:
        return False


def _delete_value(path: str, name: str) -> None:
    winreg = _winreg()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                             winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, name)
    except OSError:
        pass


def _restore_one(path: str, name: str, original: Optional[int]) -> None:
    if original is None:
        _delete_value(path, name)
    else:
        _write_dword(path, name, original)


def _netbt_interfaces() -> list[str]:
    """Subkey names under NetBT\\Parameters\\Interfaces — one per NIC."""
    winreg = _winreg()
    names: list[str] = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NETBT_IFACES) as k:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(k, i))
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    return names


def _bounce_dnscache() -> None:
    no_window = 0x08000000
    try:
        subprocess.run(['sc', 'stop', 'Dnscache'], capture_output=True,
                       check=False, timeout=10, creationflags=no_window)
        subprocess.run(['sc', 'start', 'Dnscache'], capture_output=True,
                       check=False, timeout=10, creationflags=no_window)
    except OSError:
        pass


def _has_backup_key() -> bool:
    try:
        get_settings(_BACKUP_KEY)
        return True
    except Exception:  # noqa: BLE001
        return False


# ===========================================================================
# Registry helpers — MAC spoof
# ===========================================================================

def _random_mac_hex() -> str:
    """Return a random locally-administered unicast MAC as 12 uppercase hex chars."""
    b = [random.randint(0, 255) for _ in range(6)]
    b[0] = (b[0] & 0xFE) | 0x02  # unicast + locally administered
    return ''.join(f'{x:02X}' for x in b)


def _norm_guid(g: str) -> str:
    return g.strip('{}').upper()


def _extract_win_guid(pcap_name: str) -> Optional[str]:
    """Extract GUID string (without braces) from a pcap adapter name."""
    m = _GUID_RE.search(pcap_name)
    return m.group(1).upper() if m else None


def _find_nic_key(win_guid: str) -> Optional[str]:
    """Find the HKLM registry path for the NIC with the given GUID."""
    winreg = _winreg()
    norm = _norm_guid(win_guid)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NET_CLASS_KEY) as cls:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(cls, i)
                    i += 1
                    path = f'{_NET_CLASS_KEY}\\{sub}'
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as sk:
                        try:
                            val, _ = winreg.QueryValueEx(sk, 'NetCfgInstanceId')
                            if _norm_guid(str(val)) == norm:
                                return path
                        except OSError:
                            pass
                except OSError:
                    break
    except OSError:
        pass
    return None


def _read_mac_override(key_path: str) -> Optional[str]:
    """Read current NetworkAddress override from the NIC's registry key."""
    winreg = _winreg()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
            val, _ = winreg.QueryValueEx(k, 'NetworkAddress')
            return str(val)
    except OSError:
        return None


def _write_mac_override(key_path: str, mac_hex: str) -> bool:
    """Write a NetworkAddress override (12 hex chars, no separators)."""
    winreg = _winreg()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                             winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, 'NetworkAddress', 0, winreg.REG_SZ,
                              mac_hex.upper())
        return True
    except OSError:
        return False


def _delete_mac_override(key_path: str) -> None:
    """Delete the NetworkAddress override (restores factory/burned-in MAC)."""
    winreg = _winreg()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                             winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, 'NetworkAddress')
    except OSError:
        pass


def _restart_adapter(friendly_name: str) -> bool:
    """Disable then re-enable an adapter by friendly name (brief disconnect)."""
    no_window = 0x08000000
    base = ['netsh', 'interface', 'set', 'interface', friendly_name]
    try:
        subprocess.run(base + ['admin=disable'], capture_output=True,
                       check=False, timeout=15, creationflags=no_window)
        sleep(1.5)
        subprocess.run(base + ['admin=enable'], capture_output=True,
                       check=False, timeout=15, creationflags=no_window)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


# ===========================================================================
# Internal sub-shield state helpers
# ===========================================================================

def _is_hostname_active() -> bool:
    try:
        return bool(get_settings(_BACKUP_KEY))
    except Exception:  # noqa: BLE001
        return False


def _is_mac_active() -> bool:
    try:
        return bool(get_settings(_MAC_BACKUP_KEY))
    except Exception:  # noqa: BLE001
        return False


def _apply_mac_spoof() -> tuple[bool, str]:
    """Apply MAC spoof: pick a random MAC, write to registry, restart adapter."""
    try:
        from tools.utils import get_default_iface, get_iface_by_name
    except ImportError:
        return False, 'Could not import interface utilities.'

    try:
        iface_name = get_settings('iface')
        iface = (get_iface_by_name(iface_name)
                 if iface_name else get_default_iface())
    except Exception:  # noqa: BLE001
        iface = get_default_iface()

    if iface is None or iface.name == 'NULL':
        return False, 'No active network interface found.'

    win_guid = _extract_win_guid(iface.guid)
    if not win_guid:
        return False, f'Could not determine adapter GUID for "{iface.name}".'

    key_path = _find_nic_key(win_guid)
    if key_path is None:
        return False, f'Registry key not found for adapter "{iface.name}".'

    original = _read_mac_override(key_path)
    new_hex = _random_mac_hex()

    if not _write_mac_override(key_path, new_hex):
        return False, 'Failed to write MAC override to registry.'

    set_settings(_MAC_BACKUP_KEY, {
        'key_path': key_path,
        'adapter_name': iface.name,
        'had_override': original is not None,
        'original_value': original,
    })

    _restart_adapter(iface.name)
    formatted = ':'.join(new_hex[i:i + 2] for i in range(0, 12, 2))
    return True, (f'MAC address randomised to {formatted}. '
                  'A brief reconnect occurred; DHCP will assign a new IP.')


def _restore_mac_spoof() -> tuple[bool, str]:
    """Restore original MAC from backup and restart the adapter."""
    try:
        backup = get_settings(_MAC_BACKUP_KEY)
    except Exception:  # noqa: BLE001
        backup = {}
    if not backup:
        return True, ''

    key_path = backup.get('key_path', '')
    adapter_name = backup.get('adapter_name', '')
    had_override = backup.get('had_override', False)
    original_value = backup.get('original_value')

    if key_path:
        if had_override and original_value:
            _write_mac_override(key_path, original_value)
        else:
            _delete_mac_override(key_path)

    set_settings(_MAC_BACKUP_KEY, {})

    if adapter_name:
        _restart_adapter(adapter_name)
    return True, 'Original MAC address restored. A brief reconnect occurred.'


# ===========================================================================
# Public API
# ===========================================================================

def is_active() -> bool:
    """True if any stealth shield (hostname or MAC) is currently active."""
    return _is_hostname_active() or _is_mac_active()


def status() -> dict:
    """Best-effort read of all shield states, for the Settings UI. Never raises."""
    if not available():
        return {'available': False, 'active': False,
                'llmnr_on': False, 'mdns_on': False, 'netbios_on': False,
                'mac_spoofed': False}
    netbios_on = True
    for iface in _netbt_interfaces():
        if _read_dword(f'{_NETBT_IFACES}\\{iface}', _NETBT_VAL) == 2:
            netbios_on = False
            break
    return {
        'available': True,
        'active': is_active(),
        'llmnr_on': _read_dword(_LLMNR_KEY, _LLMNR_VAL) != 0,
        'mdns_on': _read_dword(_MDNS_KEY, _MDNS_VAL) != 0,
        'netbios_on': netbios_on,
        'mac_spoofed': _is_mac_active(),
    }


def enable() -> tuple[bool, str]:
    """Enable all stealth shields: hostname (NetBIOS/LLMNR/mDNS) + MAC spoof.

    Idempotent per sub-shield — if only one was enabled (e.g. partial prior
    run), re-calling applies the missing half without touching the other.
    Fully reversible; backups stored in the settings JSON survive restarts.
    """
    if not available():
        return False, 'The identity shield is Windows-only.'
    from tools.utils_gui import is_admin
    if not is_admin():
        return False, 'Administrator access is required to change this.'

    hostname_done = _is_hostname_active()
    mac_done = _is_mac_active()

    if hostname_done and mac_done:
        return True, 'Already enabled.'

    parts: list[str] = []
    all_ok = True

    # --- hostname shield ---
    if not hostname_done:
        backup: dict[str, Any] = {
            'llmnr': _read_dword(_LLMNR_KEY, _LLMNR_VAL),
            'mdns': _read_dword(_MDNS_KEY, _MDNS_VAL),
            'netbt': {iface: _read_dword(f'{_NETBT_IFACES}\\{iface}', _NETBT_VAL)
                      for iface in _netbt_interfaces()},
        }
        _write_dword(_LLMNR_KEY, _LLMNR_VAL, 0)
        _write_dword(_MDNS_KEY, _MDNS_VAL, 0)
        for iface in backup['netbt']:
            _write_dword(f'{_NETBT_IFACES}\\{iface}', _NETBT_VAL, 2)
        set_settings(_BACKUP_KEY, backup)
        _bounce_dnscache()
        parts.append('NetBIOS, LLMNR and mDNS name responses are now off.')

    # --- MAC spoof ---
    if not mac_done:
        ok, msg = _apply_mac_spoof()
        all_ok = all_ok and ok
        parts.append(msg)

    return all_ok, ' '.join(parts)


def disable() -> tuple[bool, str]:
    """Restore everything this module changed to its exact prior state."""
    if not available():
        return True, 'Nothing to restore (not Windows).'

    hostname_active = _is_hostname_active()
    mac_active = _is_mac_active()

    if not hostname_active and not mac_active:
        return True, 'Nothing to restore.'

    from tools.utils_gui import is_admin
    if not is_admin():
        return False, 'Administrator access is required to restore this.'

    parts: list[str] = []

    # --- hostname shield ---
    if hostname_active:
        backup = get_settings(_BACKUP_KEY) if _has_backup_key() else {}
        if backup:
            _restore_one(_LLMNR_KEY, _LLMNR_VAL, backup.get('llmnr'))
            _restore_one(_MDNS_KEY, _MDNS_VAL, backup.get('mdns'))
            for iface, original in (backup.get('netbt') or {}).items():
                _restore_one(f'{_NETBT_IFACES}\\{iface}', _NETBT_VAL, original)
            set_settings(_BACKUP_KEY, {})
            _bounce_dnscache()
            parts.append('NetBIOS, LLMNR and mDNS have been restored.')

    # --- MAC spoof ---
    if mac_active:
        ok, msg = _restore_mac_spoof()
        if msg:
            parts.append(msg)

    return True, ' '.join(parts)


def restore_if_active() -> None:
    """Fire-and-forget revert for the uninstaller / --flush-firewall path."""
    try:
        if is_active():
            disable()
    except Exception:  # noqa: BLE001
        pass
