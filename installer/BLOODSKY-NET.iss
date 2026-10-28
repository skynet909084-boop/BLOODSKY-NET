#define MyAppName "BLOODSKY NET"
#define MyAppVersion "0.15.0-dev"
#define MyAppExeName "BLOODSKY-NET.exe"

[Setup]
AppId={{C6459D56-B4F9-4E2E-B4F2-8F8D04725061}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=BLOODSKY
DefaultDirName={localappdata}\Programs\BLOODSKY NET
DefaultGroupName=BLOODSKY NET
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
DisableWelcomePage=no
WizardStyle=modern
OutputDir=output
OutputBaseFilename=BLOODSKY-NET-Setup-0.15.0-dev
Compression=lzma
SolidCompression=yes
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать значок на рабочем столе"; Flags: unchecked

[Files]
Source: "..\dist\BLOODSKY-NET.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\BLOODSKY NET"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\BLOODSKY NET"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Запустить BLOODSKY NET"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Command: String;
  ExePath: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    ExePath := Lowercase(ExpandConstant('{app}\{#MyAppExeName}'));
    if RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'BLOODSKY NET', Command) then
      if Pos(ExePath, Lowercase(Command)) > 0 then
        RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'BLOODSKY NET');
  end;
end;
