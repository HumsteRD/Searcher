; Установщик Threat Scanner.
;
; Собирается скриптом tools/package.ps1: он кладёт готовые файлы в
; dist\ThreatScanner и передаёт версию ключом /DAppVersion=x.y.z.
;
; Ставится в Program Files с правами администратора, а не в профиль:
; рядом лежат помощник, который Windows запускает с полными правами, и
; служба. Такие файлы должны лежать там, куда обычный пользователь
; писать не может.

#ifndef AppVersion
  #define AppVersion "2.0.0"
#endif
#define AppName "Threat Scanner"
#define AppExe "ThreatScanner.exe"
#define AppPublisher "HumsteRD"
#define AppUrl "https://github.com/HumsteRD/Searcher"

[Setup]
AppId={{6B3E2F4A-9C1D-4E7B-8A52-3D0F7C91B6E4}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}/issues
AppUpdatesURL={#AppUrl}/releases
VersionInfoVersion={#AppVersion}
VersionInfoDescription={#AppName} Setup
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=..\release
OutputBaseFilename=ThreatScanner-Setup-{#AppVersion}
SetupIconFile=..\res\icons\app.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
WizardStyle=modern
Compression=lzma2/ultra64
SolidCompression=yes
; Запущенную программу закрывает штатный механизм Windows (Restart
; Manager). При автообновлении программа завершается сама до запуска
; установщика и после установки запускается снова (раздел [Run]).
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
russian.ContextMenu=Добавить «Проверить в Threat Scanner» в меню проводника
english.ContextMenu=Add "Scan with Threat Scanner" to the Explorer menu
russian.CheckWith=Проверить в Threat Scanner
english.CheckWith=Scan with Threat Scanner
russian.StartWithWindows=Запускать вместе с Windows (мониторинг загрузок в фоне)
english.StartWithWindows=Start with Windows (download monitoring in the background)

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "contextmenu"; Description: "{cm:ContextMenu}"
Name: "autostart"; Description: "{cm:StartWithWindows}"; Flags: unchecked

[Dirs]
; Обновления баз скачивает окно программы, которое работает от обычного
; пользователя, — ему нужна запись в папку баз.
Name: "{commonappdata}\ThreatScanner\signatures"; Permissions: users-modify

[Files]
Source: "..\dist\ThreatScanner\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\THIRD-PARTY.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; Пункт контекстного меню для файлов и папок.
Root: HKLM; Subkey: "Software\Classes\*\shell\ThreatScanner"; ValueType: string; ValueData: "{cm:CheckWith}"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\*\shell\ThreatScanner"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#AppExe}"",0"; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\*\shell\ThreatScanner\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" --check ""%1"""; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\Directory\shell\ThreatScanner"; ValueType: string; ValueData: "{cm:CheckWith}"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\Directory\shell\ThreatScanner"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#AppExe}"",0"; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\Directory\shell\ThreatScanner\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" --check ""%1"""; Tasks: contextmenu
; Автозапуск — у текущего пользователя, свёрнутым в трей.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "ThreatScanner"; ValueData: """{app}\{#AppExe}"" --minimized"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
; Обычная установка — галочка «Запустить» в конце мастера.
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser
; Тихое обновление из самой программы — запустить её снова, с правами
; пользователя, а не администратора.
Filename: "{app}\{#AppExe}"; Flags: nowait runasoriginaluser; Check: WizardSilent

[UninstallRun]
; Фоновая служба, если пользователь её включал, снимается штатной командой.
Filename: "{app}\ThreatService.exe"; Parameters: "--uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\ThreatScanner\signatures"
