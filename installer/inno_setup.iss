; ============================================================================
; WinnyTool Inno Setup Script
; Inno Setup 6.x
;
; Build with:   iscc inno_setup.iss
; Prerequisites: Place the PyInstaller output in ..\dist\ before compiling.
; ============================================================================

#define MyAppName      "WinnyTool"
#define MyAppVersion   "1.4.0"
#define MyAppPublisher "AES256Afro"
#define MyAppURL       "https://github.com/AES256Afro/WinnyTool"
#define MyAppExeName   "WinnyTool.exe"

[Setup]
; Unique AppId for upgrade detection -- do not change between versions
AppId={{7A3F2E8B-4C1D-4F6A-9B2E-1D8C5A7F3E9B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=..\LICENSE
; Output settings
OutputDir=..\dist
OutputBaseFilename=WinnyTool_Setup_v{#MyAppVersion}
; Icon
SetupIconFile=..\assets\winnytool.ico
UninstallDisplayIcon={app}\assets\winnytool.ico
; Compression
Compression=lzma2
SolidCompression=yes
; Modern wizard style
WizardStyle=modern
WizardSizePercent=110
; Privileges
PrivilegesRequired=admin
; Versioning
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Installer
VersionInfoCopyright=Copyright (c) {#MyAppPublisher}
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Main executable
Source: "..\dist\WinnyTool.exe"; DestDir: "{app}"; Flags: ignoreversion

; Data files
Source: "..\data\*"; DestDir: "{app}\data"; Flags: ignoreversion recursesubdirs createallsubdirs

; Asset files
Source: "..\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs

; Documentation
Source: "..\LICENSE";    DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";  DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start Menu
Name: "{group}\{#MyAppName}";            Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\winnytool.ico"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
; Desktop (optional task)
Name: "{autodesktop}\{#MyAppName}";       Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\winnytool.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
