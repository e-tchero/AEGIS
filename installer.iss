; Project AEGIS — Inno Setup Installer Script
; Lead Architect: ETCHERO / Abdul-Hameed
; Version: 1.0.0
;
; Produces AEGIS_Setup_v1.0.0.exe — a production-grade Windows installer.
;
; Requirements:
;   - Inno Setup 6+ (https://jrsoftware.org/isinfo.php)
;   - AEGIS.exe already built via `pyinstaller AEGIS.spec`
;
; Build:
;   ISCC installer.iss

#define MyAppName "Project AEGIS"
#define MyAppShortName "AEGIS"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "ETCHERO"
#define MyAppURL "https://github.com/ETCHERO/aegis"
#define MyAppExeName "AEGIS.exe"
#define MyAppAssocName MyAppShortName + " Files"

[Setup]
; NOTE: The value of AppId uniquely identifies this application. Do not use the same
; AppId value in installers for other applications.
AppId={{AEGIS-8A2B-4C1D-9E3F-6A7B8C9D0E1F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppShortName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
; License file (see LICENSE in app directory)
LicenseFile=LICENSE
InfoBeforeFile=README.md
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=release
OutputBaseFilename=AEGIS_Setup_v{#MyAppVersion}
SetupIconFile=image.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=no
CloseApplications=no
ExtraDiskSpaceRequired=104857600
ArchitecturesInstallIn64BitMode=x64compatible

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nAEGIS is an autonomous security operations agent that monitors processes, network traffic, file integrity, logins, memory, and DNS for threats.

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Main executable
; Note: PyInstaller spec produces a single-file EXE at dist\AEGIS.exe
Source: "dist\AEGIS.exe"; DestDir: "{app}"; Flags: ignoreversion

; Configuration
Source: "config\file_baseline.json"; DestDir: "{app}\config"; Flags: ignoreversion

; Documentation
Source: "AEGIS_Documentation.html"; DestDir: "{app}"; Flags: ignoreversion
Source: "investor_one_pager.html"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

; Icon
Source: "image.ico"; DestDir: "{app}"; Flags: ignoreversion

; Validation reports
Source: "validation\reports\*.html"; DestDir: "{app}\validation\reports"; Flags: ignoreversion recursesubdirs createallsubdirs

; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Dirs]
Name: "{app}\logs"; Permissions: users-modify
Name: "{app}\config"; Permissions: users-modify
Name: "{app}\validation\reports"
Name: "{app}\evidence"

[Icons]
Name: "{group}\{#MyAppShortName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\image.ico"; Comment: "Launch AEGIS Security Operations Agent"
Name: "{group}\{cm:UninstallProgram,{#MyAppShortName}}"; Filename: "{uninstallexe}"
Name: "{group}\AEGIS Documentation"; Filename: "{app}\AEGIS_Documentation.html"
Name: "{commondesktop}\{#MyAppShortName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\image.ico"; Tasks: desktopicon; Comment: "Launch AEGIS Security Operations Agent"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppShortName}}"; Flags: nowait postinstall skipifsilent unchecked; Parameters: "--help"

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--uninstall-cleanup"; Flags: runhidden; RunOnceId: "AEGISCleanup"

[Registry]
; Register .aegis file association (optional)
Root: HKA; Subkey: "Software\Classes\.aegis\OpenWithProgids"; ValueType: string; ValueName: "{#MyAppAssocName}"; ValueData: ""; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocName}"; ValueType: string; ValueName: ""; ValueData: "{#MyAppAssocName}"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocName}\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\image.ico,0"
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocName}\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""

[Code]
function InitializeSetup: Boolean;
begin
  Result := True;
end;

function GetUninstallString: string;
var
  sUnInstPath: string;
  sUnInstallString: String;
begin
  sUnInstPath := ExpandConstant('Software\Microsoft\Windows\CurrentVersion\Uninstall\{#emit SetupSetting("AppId")}_is1');
  sUnInstallString := '';
  if not RegQueryStringValue(HKLM, sUnInstPath, 'UninstallString', sUnInstallString) then
    RegQueryStringValue(HKCU, sUnInstPath, 'UninstallString', sUnInstallString);
  Result := sUnInstallString;
end;

function IsUpgrade: Boolean;
begin
  Result := (GetUninstallString <> '');
end;

function InitializeUninstall: Boolean;
begin
  Result := True;
end;

function GetCustomSetupExitCode: Integer;
begin
  Result := 0;
end;
