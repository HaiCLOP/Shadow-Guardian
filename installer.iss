; Shadow Guardian - Inno Setup Installer Script
;
; Creates a professional Windows installer with:
;   - Start Menu shortcuts
;   - Desktop shortcut (optional)
;   - Startup registry entry (optional)
;   - Uninstaller

#define MyAppName "Shadow Guardian"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "HaiCLOP Labs"
#define MyAppURL "https://github.com/shadowguardian"
#define MyAppExeName "ShadowGuardian.exe"

[Setup]
AppId={{A7F3E2B1-9C4D-4E5F-8A6B-1C2D3E4F5A6B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=dist
OutputBaseFilename=ShadowGuardianSetup
WizardStyle=modern
WizardSizePercent=120
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#MyAppExeName}
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupentry"; Description: "Start Shadow Guardian on Windows startup"; GroupDescription: "System Integration:"

[Files]
; Main application directory (everything from PyInstaller output)
Source: "dist\ShadowGuardian\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Writable config (don't overwrite user config on upgrade)
Source: "config.json"; DestDir: "{app}"; Flags: onlyifdoesntexist

[Icons]
; Start Menu
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Comment: "Launch Shadow Guardian"
Name: "{group}\Shadow Guardian Dashboard"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--mode watchdog"; Comment: "Open Shadow Guardian Dashboard"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

; Desktop shortcut (optional task)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; Comment: "Launch Shadow Guardian"

[Registry]
; (Auto-start is handled via Scheduled Task, not registry — see [Run] section)

[Run]
; Launch after install (this will run elevated and trigger register_autostart() to create the Scheduled Task properly via XML)
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Shadow Guardian"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Remove the scheduled task
Filename: "schtasks"; Parameters: "/Delete /TN ""ShadowGuardian"" /F"; Flags: runhidden; RunOnceId: "RemoveTask"
; Clean shutdown before uninstall
Filename: "taskkill"; Parameters: "/F /IM ShadowGuardian.exe"; Flags: runhidden; RunOnceId: "KillSG"

[UninstallDelete]
; Clean up generated app data files
Type: filesandordirs; Name: "{localappdata}\ShadowGuardian"

[Code]
function InitializeSetup: Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  if Exec('tasklist', '/FI "IMAGENAME eq ShadowGuardian.exe" /NH', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if MsgBox('Shadow Guardian may be running. Setup will attempt to close it. Continue?',
              mbConfirmation, MB_YESNO) = IDNO then
    begin
      Result := False;
      Exit;
    end;
    Exec('taskkill', '/F /IM ShadowGuardian.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1000);
  end;
end;
