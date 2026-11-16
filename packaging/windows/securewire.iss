; SecureWire Windows installer (Inno Setup 6.3+).
; Build:  ISCC /DAppVersion=1.0.0 packaging\windows\securewire.iss
; Needs target\release\securewire.exe (cargo build --release -p securewire). Output: dist\.

#ifndef AppVersion
  #error Pass the version: ISCC /DAppVersion=x.y.z securewire.iss
#endif
#define Root "..\.."

[Setup]
AppId={{9D175744-8C9B-4A73-AF30-52A5305D9E49}
AppName=SecureWire
AppVersion={#AppVersion}
AppVerName=SecureWire {#AppVersion}
AppPublisher=SecureWire
AppPublisherURL=https://github.com/ismailian/SecureWire
AppSupportURL=https://github.com/ismailian/SecureWire/issues
AppUpdatesURL=https://github.com/ismailian/SecureWire/releases
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\SecureWire
DefaultGroupName=SecureWire
DisableProgramGroupPage=yes
; Per-user install without admin rights unless the user picks "all users".
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
SetupIconFile={#Root}\packaging\icons\securewire.ico
UninstallDisplayIcon={app}\securewire.exe
UninstallDisplayName=SecureWire
LicenseFile={#Root}\LICENSE-MIT
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
CloseApplications=yes
OutputDir={#Root}\dist
OutputBaseFilename=securewire-v{#AppVersion}-windows-x86_64-setup

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#Root}\target\release\securewire.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Root}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Root}\LICENSE-MIT"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "{#Root}\LICENSE-APACHE"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "{#Root}\crates\app\assets\fonts\OFL.txt"; DestDir: "{app}\licenses"; DestName: "JetBrainsMono-OFL.txt"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\SecureWire"; Filename: "{app}\securewire.exe"
Name: "{autodesktop}\SecureWire"; Filename: "{app}\securewire.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\securewire.exe"; Description: "{cm:LaunchProgram,SecureWire}"; Flags: nowait postinstall skipifsilent

; Saved hosts and known_hosts in %APPDATA%\SecureWire are kept on uninstall.
