; Inno Setup script for LAN Signal Sniffer (Windows installer)
;
; Build prerequisites:
;   1. PyInstaller has produced  dist\LAN Signal Sniffer\  (the folder holding
;      the .exe and its dependencies).
;   2. Inno Setup 6+ installed, or ISCC.exe on PATH.
; Usage:
;   iscc /DAppVersion=0.1.0 windows_installer.iss
; The CI workflow (.github/workflows/build-release.yml) passes AppVersion from
; the pushed git tag.
;
; Everything Python-side — the interpreter, PyQt5, pyqtgraph, numpy, scapy — is
; already inside the PyInstaller folder, so the user installs none of it.
;
; Npcap is the exception and cannot be bundled: it is a kernel-mode driver with
; its own installer, and redistributing its binary requires a licence from its
; authors. So this installer detects it and, if missing, says so and offers to
; open the download page. Fetching a pinned installer URL was the alternative,
; and was rejected because the URL carries a version number that goes stale.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

#define AppName "LAN Signal Sniffer"
#define AppExe "LAN Signal Sniffer.exe"
#define RepoUrl "https://github.com/OmerVered1/lan-signal-sniffer"

[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Omer Vered
AppPublisherURL={#RepoUrl}
AppSupportURL={#RepoUrl}/issues
AppUpdatesURL={#RepoUrl}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=installer_out
OutputBaseFilename=LAN-Signal-Sniffer-Setup-{#AppVersion}
#if FileExists("assets\app_icon.ico")
SetupIconFile=assets\app_icon.ico
#endif
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequiredOverridesAllowed=dialog
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "dist\{#AppName}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Capture needs administrator rights, so the shortcuts request them. Without
; this the app starts but finds no capture interfaces, which looks like a bug
; rather than a permissions problem.
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "https://npcap.com/#download"; Description: "Open the Npcap download page (required for packet capture)"; Flags: shellexec nowait postinstall skipifsilent; Check: NpcapMissing
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
function NpcapInstalled(): Boolean;
var
  SysDir: String;
begin
  SysDir := ExpandConstant('{sys}');
  { Npcap puts wpcap.dll under System32\Npcap. Installing it in "WinPcap }
  { API-compatible mode" — which this app needs — also places a copy      }
  { directly in System32, so check both. The service key is the fallback  }
  { for layouts that differ between Npcap versions.                       }
  Result := FileExists(SysDir + '\Npcap\wpcap.dll')
         or FileExists(SysDir + '\wpcap.dll')
         or RegKeyExists(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\npcap')
         or RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Npcap')
         or RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\Npcap');
end;

function NpcapMissing(): Boolean;
begin
  Result := not NpcapInstalled();
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not NpcapInstalled() then
  begin
    { Warn before installing rather than after, so the user can deal with both }
    { in one sitting instead of discovering an empty interface list later.     }
    MsgBox(
      'Npcap was not found on this computer.' + #13#10 + #13#10 +
      '{#AppName} bundles everything else it needs, but packet capture relies '
      + 'on Npcap, a driver that has to be installed separately. Wireshark is '
      + 'not required — Npcap installs on its own.' + #13#10 + #13#10 +
      'Setup will continue. At the end you can open the Npcap download page; '
      + 'install it with "WinPcap API-compatible mode" ticked, then start '
      + '{#AppName}.',
      mbInformation, MB_OK);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if not NpcapInstalled() then
      MsgBox(
        'Reminder: install Npcap before using {#AppName}, and tick '
        + '"WinPcap API-compatible mode".' + #13#10 + #13#10 +
        'Also run {#AppName} as Administrator — capture needs it. Without '
        + 'either, the app opens but finds no capture interfaces.',
        mbInformation, MB_OK);
  end;
end;
