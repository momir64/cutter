# cutter

A modern, hardened network-control tool for **macOS, Windows, and Linux**. Discover
the devices on your local network and cut, throttle, redirect, or watch their
traffic — from a clean, device-centric interface.

**cutter** is my fork of [ArpCut](https://github.com/Mvgnu/ArpCut) by Mvgnus (Magnus
Ohle), which itself forked [elmoCut](https://github.com/elmoiv/elmocut) by Khaled
El-Morshedy (elmoiv). I rebuilt it Windows-focused: native frameless window chrome with
real Aero Snap, a multi-select device list with undo/redo, an async-started engine, and
a round of UI/UX fixes not present upstream.

GPL-3.0

> ⚠️ For education and **authorized** network administration only. Use it only on
> networks you own or have explicit permission to test.

<p align="center">
  <img src="assets/screenshots/main-dark.png" alt="cutter main window" width="840">
</p>

*(addresses in the screenshots are redacted)*

---

## What it does

**Discover** — ARP scan (fast) or a thorough ping sweep. Devices show as cards with
vendor, IP/MAC, nickname, and live state.

**Per-device actions** (click a card to select it — Shift/Ctrl-click for a multi-device
selection — then right-click for the action menu):

| Action | What it does |
|--------|--------------|
| **Cut / Restore** | Takes the device off the internet for real — ARP redirect **+** firewall drop, so it's a true cut even while kernel forwarding is on. |
| **One-way** | Blocks only the device's *outbound* traffic. |
| **Lag switch** | Intermittent lag — configurable on/off intervals and direction. With several devices selected, each gets the same interval length but a staggered start, so they don't all lag in lockstep. |
| **Traffic monitor** | Routes the device through this machine and shows its live flows (push-updated, not polled). It stays online while you watch. |
| **Cut All / Restore All** | The same, network-wide. |

Multi-select applies Cut, One-way, and Lag to every selected device at once; Blocker,
Traffic monitor, and device details stay single-device actions. Ctrl+Z / Ctrl+Shift+Z /
Ctrl+Y undo and redo the selection itself.

**Blocker** (per device + network-wide):

- **DNS name** — intercepts the device's DNS lookup of a name and answers `NXDOMAIN`.
  Works even for names with **no IP** (this is how the **PSN** preset forces host
  migration; the on-host equivalent of a router RPZ).
- **Port** — drops a TCP/UDP port for the device.
- **Destination IP / domain** — firewall-drops a destination (domains resolve, with a
  public-DNS fallback).
- **Curated presets** — PSN party/host-migration (DNS) and GTA-Online save block
  (verified Rockstar IP).

<p align="center">
  <img src="assets/screenshots/blocker.png" alt="Blocker" width="380">
  &nbsp;
  <img src="assets/screenshots/traffic.png" alt="Traffic monitor" width="420">
</p>

**Quality-of-life** — light/dark theme, menu-bar tray, device nicknames,
remember-cut-devices, a persistent status line, and (Windows) native Aero Snap /
maximize with a proper rounded-corner, DWM-shadowed frameless window.

---

## Privileges — and "Set Up Access"

Raw network control (BPF/raw sockets, `pf`/`nft`/`netsh`, IP-forwarding) **requires
administrator/root on every OS** — there is no sandbox-safe path. cutter handles this
without a terminal:

- Launch it; if it isn't privileged, a banner offers **Set Up Access**.
- **Grant Administrator Access** relaunches cutter elevated (native password prompt).
- **Install Background Helper** installs a small root daemon (`com.arpcut.helper`), the
  same model as Wireshark / Little Snitch — the unprivileged GUI then drives it over a
  local socket while holding no privilege itself.
- **Nothing is left blocked when you quit or crash.** The GUI holds a session to the
  helper; when it drops, the helper restores every device and clears every rule.

<p align="center">
  <img src="assets/screenshots/setup-access.png" alt="Set Up Access" width="420">
</p>

---

## Install

**Download** a build from [Releases](https://github.com/momir64/cutter/releases):

| Platform | Artifact | Notes |
|----------|----------|-------|
| macOS | `cutter-<ver>.dmg` | Drag to Applications. Unsigned builds: right-click → **Open** the first time. |
| Windows | `cutter-setup.exe` | Inno Setup installer; bundles the **Npcap** driver. |
| Linux | AppImage / `.deb` | `setcap`/polkit for privileges. |

On first launch, use **Set Up Access** (above).

### Run from source

```bash
git clone https://github.com/momir64/cutter.git && cd cutter
python3 -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt                       # PySide6, scapy, manuf
python src/elmocut.py                                 # add sudo / run as admin for full power
```

Windows also needs [Npcap](https://npcap.com/) ("WinPcap API-compatible Mode").

---

## Build installers

```bash
pip install pyinstaller
python build.py            # Windows → dist/cutter/cutter.exe; macOS/Linux → dist/ArpCut-<ver>
python build.py --dmg      # macOS → dist/ArpCut-<ver>.dmg  (drag-to-Applications)
```

- **Windows:** drop `packaging/windows/vendor/npcap.exe`, then run `build.py` — it also
  builds the installer (`dist/cutter-setup.exe`) via `packaging/windows/cutter.iss` if
  Inno Setup (`iscc`) is on `PATH`.
- **Signing / notarization** (macOS Developer ID) is optional but removes the
  Gatekeeper prompt — see `packaging/README.md`. The app binary doubles as the root
  helper daemon (`--helper`), so no separate helper binary is shipped.

---

## Architecture

```
PySide6 GUI ──intent──▶ Controller ──▶ ops backend ──▶ engine
 (window/dialogs)          │              ├─ LocalEngine  (in-process, when root)
   presentation only       │              └─ RemoteEngine (IPC to the root helper)
                     Qt signals ◀── results / pushed events (flows, cleanup)
```

- **GUI** renders state and emits intent — it never opens a socket or shells a firewall.
- **Controller** owns app state and orchestration (cut = ARP + firewall, one-way, lag,
  monitor, DNS interception), off the UI thread.
- **Engine** does the privileged work — used **in-process** with root, or reached over a
  Unix socket via the **root helper daemon** (`privilege/`) when unprivileged. One
  engine, two transports.

The `specs/` directory documents each domain (overview, platform, privilege, networking,
firewall, gui, build). The engine has zero Qt imports and is covered by 170+ unit tests
(`tests/`), including a real client↔helper socket loopback.

---

## Credits & License

- **cutter** — my fork.
- [ArpCut](https://github.com/Mvgnu/ArpCut) by Mvgnus (Magnus Ohle) — the repo I forked
  from.
- [elmoCut](https://github.com/elmoiv/elmocut) by elmoiv (Khaled El-Morshedy) — the
  original project, two forks back.

GNU General Public License v3.0 — see [LICENSE](LICENSE).
