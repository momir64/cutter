; cutter — Windows installer (Inno Setup 6)
;
; Installs cutter to Program Files, silently installs the Npcap capture driver
; if it is missing, creates Start Menu and optional desktop shortcuts, and
; requests administrator rights (raw network access requires them).
; On uninstall it flushes any leftover firewall rules and restores every system
; setting the app changed (stealth / MAC spoof backup).
;
; Build:  &"C:\Program Files\Inno Setup 7\iscc.exe" packaging\windows\cutter.iss
; Expects: dist\cutter\           (from `python build.py` on Windows)
;          packaging\windows\vendor\npcap.exe  (optional — download from https://npcap.com)

#define MyAppName    "cutter"
#define MyAppExe     "cutter.exe"
#define MyAppPublisher "cutter"
#define MyAppURL     "https://github.com/Mvgnu/ArpCut"
#define MyAppSrc     SourcePath + "..\..\dist"
#define MyAppVersion "2.0.1"

; Bundling Npcap is optional: if packaging\windows\vendor\npcap.exe is present
; it is embedded and silently installed when the driver is missing; otherwise
; the installer still builds and the app nudges users on first run.
#define NpcapVendor "vendor\npcap.exe"
#if FileExists(AddBackslash(SourcePath) + NpcapVendor)
  #define HaveNpcap
#endif

[Setup]
AppId={{7C3A2F10-CUTT-4C0T-9A11-CUTTER000001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExe}
OutputDir={#SourcePath}..\..\dist
OutputBaseFilename=cutter-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; cutter needs admin for raw sockets / firewall / MAC registry changes.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
; Single-file executable produced by PyInstaller --onefile.
Source: "{#MyAppSrc}\cutter.exe"; DestDir: "{app}"; Flags: ignoreversion

#ifdef HaveNpcap
; Bundle the Npcap driver so users never have to hunt for it separately.
Source: "{#NpcapVendor}"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: NpcapMissing
#endif

[Icons]
Name: "{group}\{#MyAppName}";           Filename: "{app}\{#MyAppExe}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";     Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Run]
#ifdef HaveNpcap
; Silently install Npcap in WinPcap-compatible mode if the driver is absent.
Filename: "{tmp}\npcap.exe"; Parameters: "/S /winpcap_mode=yes"; \
          StatusMsg: "Installing the Npcap capture driver..."; \
          Check: NpcapMissing; Flags: waituntilterminated
#endif
; Offer to launch after install finishes.
Filename: "{app}\{#MyAppExe}"; Description: "Launch {#MyAppName}"; \
          Flags: nowait postinstall skipifsilent

[UninstallRun]
; Flush firewall rules and restore any system changes (stealth/MAC) before
; files are removed so the helper binary is still present when this runs.
Filename: "{app}\{#MyAppExe}"; Parameters: "--flush-firewall"; \
          Flags: runhidden; RunOnceId: "FlushCutterRules"

[Code]
function NpcapMissing: Boolean;
begin
  { Npcap registers its kernel service under this key. }
  Result := not RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\npcap');
end;
