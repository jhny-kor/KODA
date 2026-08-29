#ifndef MyAppVersion
#define MyAppVersion "0.1.0"
#endif

#define MyAppName "KODA"
#define MyAppPublisher "jhny-kor"
#define MyAppExeName "KODA.exe"
#define SourceDir "..\..\..\dist\KODA"
#define MyAppIcon "..\assets\KODA.ico"

[Setup]
AppId={{2A235674-97E5-4B71-A57C-32BE33DC960C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://gitlab.aigov.go.kr/y2kthr/koda
AppSupportURL=https://gitlab.aigov.go.kr/y2kthr/koda
AppUpdatesURL=https://gitlab.aigov.go.kr/y2kthr/koda
DefaultDirName={localappdata}\KODA
DefaultGroupName=KODA
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ChangesEnvironment=yes
OutputDir=..\..\..\dist\Windows
OutputBaseFilename=KODASetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile={#MyAppIcon}
UninstallDisplayIcon={app}\{#MyAppExeName}

[Tasks]
Name: "desktopicon"; Description: "바탕 화면에 KODA 바로가기 만들기"; GroupDescription: "추가 바로가기:"; Flags: unchecked

[InstallDelete]
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\.venv"
Type: files; Name: "{app}\SecChk.bat"
Type: files; Name: "{app}\SecChk-CLI.bat"
Type: files; Name: "{app}\Uninstall-SecChk.ps1"
Type: filesandordirs; Name: "{app}\KODA-CLI"
Type: files; Name: "{app}\KODA-CLI.cmd"
Type: files; Name: "{app}\koda.cmd"
Type: files; Name: "{app}\KODA-CLI-Shell.cmd"
Type: filesandordirs; Name: "{app}\tools"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Registry]
; Add the per-user install directory to PATH so a new Command Prompt can run
; `koda` directly. Existing PATH entries are preserved by {olddata}.
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Flags: preservestringtype

[Icons]
Name: "{group}\KODA"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{userdocs}"; Comment: "KODA local security dashboard"
Name: "{group}\KODA (Browser Mode)"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--browser"; WorkingDir: "{userdocs}"; Comment: "Open KODA in the default browser if WebView2 is unavailable"
Name: "{group}\KODA CLI"; Filename: "{app}\KODA-CLI-Shell.cmd"; WorkingDir: "{userdocs}"; Comment: "KODA command-line interface"
Name: "{userdesktop}\KODA"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{userdocs}"; Comment: "KODA local security dashboard"; Tasks: desktopicon
Name: "{group}\KODA 제거"; Filename: "{uninstallexe}"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "KODA 지금 실행"; Flags: nowait postinstall skipifsilent
