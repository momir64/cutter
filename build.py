#!/usr/bin/env python3
"""
Build script for cutter.
Run: python build.py                 # build for current platform
     python build.py --version       # print version and exit
     python build.py --bump          # bump patch version (0.3.0 -> 0.3.1)
     python build.py --bump minor    # bump minor version (0.3.0 -> 0.4.0)

0-versioning: major always stays 0, so there's no --bump major.
"""

import subprocess
import sys
import platform
from pathlib import Path
from typing import NoReturn

# Read version from the canonical source
CONSTANTS_PATH: Path = Path(__file__).parent / 'src' / 'constants.py'


def _read_version() -> str:
    """Parse __version__ from constants.py without importing it."""
    for line in CONSTANTS_PATH.read_text().splitlines():
        if line.startswith('__version__'):
            return line.split('=', 1)[1].strip().strip("'\"")
    return '0.0.0'


def bump_version(level: str = 'patch') -> str:
    """Bump __version__ in constants.py (0.minor.patch — 0-versioning, major never
    moves), write it back, and return the new version string. Does not commit or
    tag — see --bump."""
    current = _read_version()
    try:
        major, minor, patch = (int(p) for p in current.split('.'))
    except ValueError:
        print(f"Can't parse current version {current!r} as major.minor.patch")
        sys.exit(1)
    if level == 'minor':
        minor, patch = minor + 1, 0
    elif level == 'patch':
        patch += 1
    else:
        print(f"Unknown bump level {level!r} (use patch or minor)")
        sys.exit(1)
    new_version = f'{major}.{minor}.{patch}'

    text = CONSTANTS_PATH.read_text()
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.startswith('__version__'):
            lines[i] = f"__version__: str = '{new_version}'\n"
            break
    CONSTANTS_PATH.write_text(''.join(lines))
    return new_version


VERSION: str = _read_version()

# All the imports PyInstaller is too dumb to find on its own
HIDDEN_IMPORTS: list[str] = [
    'PySide6',
    'PySide6.QtWidgets',
    'PySide6.QtCore',
    'PySide6.QtGui',
    'PySide6.QtSvg',
    'scapy',
    'scapy.all',
    'scapy.layers.all',
    'manuf',
    # lazily-imported engine/helper modules — bundle them so `--helper` works
    'privilege.helper',
    'privilege.remote',
    'privilege.install',
    'networking.dnsblock',
    'networking.scanner',
    'networking.killer',
    'networking.sniffer',
]

COLLECT_ALL: list[str] = [
    'manuf',
    'scapy',
    # PySide6 intentionally omitted: PyInstaller's built-in PySide6 hook collects
    # only the Qt plugins/DLLs the app actually uses; --collect-all PySide6 would
    # add QtQuick, QtWebEngine, Qt Designer and other unused modules (~100 MB extra).
]


def build() -> None:
    """Build ArpCut binary for the current platform."""
    system: str = platform.system()

    # Base command — invoke PyInstaller via the current interpreter so it works
    # whether or not the console script is on PATH (venv / CI parity).
    cmd: list[str] = [sys.executable, '-m', 'PyInstaller', '--name', 'cutter', '--noconfirm']

    # Per-platform hidden imports / data collection (copied so we can extend
    # them for Windows without mutating the module-level lists).
    hidden_imports = list(HIDDEN_IMPORTS)
    collect_all = list(COLLECT_ALL)

    # Platform-specific options
    if system == 'Windows':
        cmd.extend(['--onefile', '--windowed'])
        cmd.extend(['--add-data', 'exe/manuf;manuf'])
        cmd.extend(['--icon', 'exe/icon.ico'])
        cmd.extend(['--uac-admin'])  # Force admin elevation prompt
        # Bundle WinDivert (kernel forwarder). --collect-all pulls in the
        # WinDivert64.dll/.sys driver files that pydivert ships.
        hidden_imports.append('pydivert')
        collect_all.append('pydivert')
    elif system == 'Darwin':  # macOS
        cmd.extend(['--onedir', '--windowed'])
        cmd.extend(['--add-data', 'exe/manuf:manuf'])
        cmd.extend(['--icon', 'exe/icon.icns'])  # macOS requires .icns
    else:  # Linux
        cmd.extend(['--onefile'])
        cmd.extend(['--add-data', 'exe/manuf:manuf'])

    # Add hidden imports
    for imp in hidden_imports:
        cmd.extend(['--hidden-import', imp])

    # Collect all data for these packages
    for pkg in collect_all:
        cmd.extend(['--collect-all', pkg])

    # Entry point
    cmd.append('src/elmocut.py')

    print(f"Building for {system}...")
    print(f"Command: {' '.join(cmd)}")
    print()

    result: subprocess.CompletedProcess[bytes] = subprocess.run(cmd)

    if result.returncode == 0:
        print()
        print("Build complete!")
        if system == 'Windows':
            print(f"Output: dist/cutter/cutter.exe")
            _build_installer()
        elif system == 'Darwin':
            print(f"Output: dist/ArpCut-{VERSION}.app")
            print("Installer: python build.py --dmg   (or packaging/macos/create_dmg.sh)")
        else:
            print(f"Output: dist/ArpCut-{VERSION}")
    else:
        print("Build failed!")
        sys.exit(1)


def _build_installer() -> None:
    """Build the Inno Setup installer wizard (Windows only). Skipped silently if
    iscc is not on PATH — the .iss file can always be run manually later."""
    iss = Path(__file__).parent / 'packaging' / 'windows' / 'cutter.iss'

    # Locate iscc — check PATH first, then the two default Inno Setup install dirs.
    import shutil
    iscc = shutil.which('iscc')
    if not iscc:
        for candidate in [
            r'C:\Program Files (x86)\Inno Setup 6\iscc.exe',
            r'C:\Program Files\Inno Setup 6\iscc.exe',
            r'C:\Program Files (x86)\Inno Setup 7\iscc.exe',
            r'C:\Program Files\Inno Setup 7\iscc.exe',
        ]:
            if Path(candidate).exists():
                iscc = candidate
                break

    if not iscc:
        print()
        print("Inno Setup not found — skipping installer build.")
        print(f"Install Inno Setup 6 or run manually:  iscc {iss}")
        return

    print()
    print("Building installer wizard...")
    result = subprocess.run([iscc, str(iss)])
    if result.returncode == 0:
        print("Installer: dist/cutter-setup.exe")
    else:
        print("Installer build failed — check Inno Setup output above.")
        sys.exit(1)


def package_dmg() -> None:
    """Wrap the built .app into a drag-to-Applications .dmg (macOS only)."""
    if platform.system() != 'Darwin':
        print("--dmg is macOS-only.")
        return
    app = Path('dist') / f'ArpCut-{VERSION}.app'
    script = Path(__file__).parent / 'packaging' / 'macos' / 'create_dmg.sh'
    print(f"Packaging {app} → dmg ...")
    result = subprocess.run(['bash', str(script), str(app)])
    if result.returncode != 0:
        print("DMG packaging failed!")
        sys.exit(1)


if __name__ == '__main__':
    if '--bump' in sys.argv:
        i = sys.argv.index('--bump')
        level = sys.argv[i + 1] if i + 1 < len(sys.argv) and sys.argv[i + 1] in \
            ('patch', 'minor') else 'patch'
        new_version = bump_version(level)
        print(f'Bumped version: {VERSION} -> {new_version}')
        print(f"Commit it, then tag and push to release:\n"
              f"  git commit -am 'Bump version to {new_version}'\n"
              f"  git tag v{new_version} && git push origin v{new_version}")
    elif '--version' in sys.argv:
        print(f'cutter {VERSION}')
    elif '--dmg' in sys.argv:
        package_dmg()
    else:
        build()
