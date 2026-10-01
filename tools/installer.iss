; EverbloomSecurity Windows installer (Inno Setup 6)
;
; Build with:
;   "D:\Inno Setup 6\ISCC.exe" /DAppVersion=0.1.0 /DSourceDir=artifacts\package\install /DOutputDir=artifacts\package\output tools\installer.iss
;
; The script bundles every file under {SourceDir} into a single Windows
; installer that copies the payload to {pf}\EverbloomSecurity\ by default. The layout
; mirrors the existing ZIP package (bin\, doc\, share\) so operators can
; upgrade from a ZIP install by re-running the installer (it installs on top
; of the existing tree without breaking rules / data).

#define AppName "EverbloomSecurity"
#define AppPublisher "EverbloomSecurity Project"
#define AppURL "https://www.everbloom.local/"
#define AppVersion GetEnv("AppVersion")
#if AppVersion == ""
  #define AppVersion "0.1.0"
#endif
#define SourceDir GetEnv("SourceDir")
#if SourceDir == ""
  #define SourceDir "..\artifacts\package\install"
#endif
#define OutputDir GetEnv("OutputDir")
#if OutputDir == ""
  #define OutputDir "..\artifacts\package\output"
#endif
#define OutputBaseFilename "EverbloomSecurity-" + AppVersion + "-Windows-Setup"

[Setup]
AppId={{B9C9C8A1-3F2D-4E7B-8F18-7E1A3B5C9D6E}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\EverbloomSecurity
DisableProgramGroupPage=yes
LicenseFile=LICENSE.txt
InfoBeforeFile=README-preinstall.txt
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
Uninstallable=yes
UninstallDisplayIcon={app}\bin\everbloom_gui.exe
UninstallDisplayName={#AppName}
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseFilename}
SetupIconFile={#SourceDir}\share\everbloom\assets\everbloom_icon.ico
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimp"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
Name: "chinetrad"; MessagesFile: "compiler:Languages\ChineseTraditional.isl"
Name: "japanese"; MessagesFile: "compiler:Languages\Japanese.isl"
Name: "korean"; MessagesFile: "compiler:Languages\Korean.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "portuguese"; MessagesFile: "compiler:Languages\Portuguese.isl"

[Messages]
BeveledLabel=EverbloomSecurity antivirus installer v{#AppVersion} (build LZMA2-64)

[CustomMessages]
english.CreateDesktopIcon=Create a desktop shortcut
english.RunAfterInstall=Launch EverbloomSecurity when the installer finishes
english.ContextMenuTask=Install the Explorer right-click scan menu
english.InstallDriverTask=Install the EverbloomSecurity kernel driver (requires signed CAT)
english.RequiresReboot=This installation requires a reboot to finish installing the kernel driver. The setup will exit after you click Continue.
english.TasksGroupAdditional=Additional icons
english.TasksGroupOptional=Optional tasks
english.WelcomeLabel=This wizard will install [name/ver] on your computer.%n%nEverbloomSecurity is a research-grade antivirus prototype. Please review the pre-install notes before continuing.
english.InfoBeforeLabel=Please read the pre-install notes before continuing.
english.WelcomeTitle=Welcome to the [name/ver] Setup Wizard
english.ReadyTitle=Ready to install
english.ReadyLabel=Setup is ready to install [name/ver] on your computer.
english.FinishedTitle=Installation complete
english.FinishedLabel=[name/ver] has been installed on your computer.%n%nYou can launch EverbloomSecurity from the Start menu or the desktop shortcut that this installer created (if selected).
english.MismatchWarning=Setup has detected an existing [name] installation at the target directory. The installer will upgrade the previous files but it is strongly recommended that you close all running EverbloomSecurity processes (engine, GUI, console) before continuing.
chinesesimp.CreateDesktopIcon=创建桌面快捷方式(&D)
chinesesimp.RunAfterInstall=安装完成后启动 EverbloomSecurity(&L)
chinesesimp.ContextMenuTask=安装资源管理器右键扫描菜单(&C)
chinesesimp.InstallDriverTask=安装 EverbloomSecurity 内核驱动（需要已签名的 CAT）
chinesesimp.RequiresReboot=本次安装需要重启以完成内核驱动的安装。点击"继续"后安装程序将退出。
chinesesimp.TasksGroupAdditional=附加快捷方式
chinesesimp.TasksGroupOptional=可选任务
chinesesimp.WelcomeLabel=本向导将在您的电脑上安装 [name/ver]。%n%nEverbloomSecurity 是一个研究/演示级别的杀毒软件原型，请先阅读"安装前必读"再继续。
chinesesimp.InfoBeforeLabel=请先阅读"安装前必读"再继续。
chinesesimp.WelcomeTitle=欢迎使用 [name/ver] 安装向导
chinesesimp.ReadyTitle=准备安装
chinesesimp.ReadyLabel=安装程序已准备就绪，将把 [name/ver] 安装到您的电脑。
chinesesimp.FinishedTitle=安装完成
chinesesimp.FinishedLabel=已成功安装 [name/ver]。%n%n您可以从开始菜单或本安装程序创建的桌面快捷方式（如果已勾选）启动 EverbloomSecurity。
chinesesimp.MismatchWarning=检测到目标目录已存在旧版 [name] 安装。安装程序将升级既有文件，但强烈建议您先关闭所有正在运行的 EverbloomSecurity 进程（引擎、GUI、控制台）再继续。
chinetrad.CreateDesktopIcon=建立桌面捷徑(&D)
chinetrad.RunAfterInstall=安裝完成後啟動 EverbloomSecurity(&L)
chinetrad.ContextMenuTask=安裝檔案總管右鍵掃描選單(&C)
chinetrad.TasksGroupAdditional=附加捷徑
chinetrad.TasksGroupOptional=可選任務
chinetrad.WelcomeLabel=本精靈將在您的電腦上安裝 [name/ver]。%n%nEverbloomSecurity 是一個研究/示範等級的防毒軟體原型，請先閱讀「安裝前必讀」再繼續。
chinetrad.WelcomeTitle=歡迎使用 [name/ver] 安裝精靈
japanese.CreateDesktopIcon=デスクトップにショートカットを作成する(&D)
japanese.RunAfterInstall=インストール完了後に EverbloomSecurity を起動する(&L)
japanese.ContextMenuTask=エクスプローラーの右クリック スキャン メニューをインストールする(&C)
japanese.TasksGroupAdditional=追加のアイコン
japanese.TasksGroupOptional=任意のタスク
japanese.WelcomeLabel=このウィザードは [name/ver] をコンピューターにインストールします。%n%nEverbloomSecurity は研究/デモ段階のアンチウイルス プロトタイプです。続行する前にインストール前の注意をご確認ください。
japanese.WelcomeTitle=[name/ver] セットアップ ウィザードへようこそ
korean.CreateDesktopIcon=바탕 화면 바로 가기 만들기(&D)
korean.RunAfterInstall=설치가 끝나면 EverbloomSecurity 실행(&L)
korean.ContextMenuTask=탐색기 마우스 오른쪽 버튼 스캔 메뉴 설치(&C)
korean.TasksGroupAdditional=추가 아이콘
korean.TasksGroupOptional=선택적 작업
korean.WelcomeLabel=이 마법사는 컴퓨터에 [name/ver]을(를) 설치합니다.%n%nEverbloomSecurity는 연구/데모 수준의 안티바이러스 프로토타입입니다. 계속하기 전에 설치 전 주의 사항을 확인하세요.
korean.WelcomeTitle=[name/ver] 설치 마법사에 오신 것을 환영합니다
french.CreateDesktopIcon=Créer un raccourci sur le bureau(&D)
french.RunAfterInstall=Lancer EverbloomSecurity à la fin de l'installation(&L)
french.ContextMenuTask=Installer le menu d'analyse du clic droit de l'Explorateur(&C)
french.TasksGroupAdditional=Icônes supplémentaires
french.TasksGroupOptional=Tâches facultatives
french.WelcomeLabel=Cet assistant va installer [name/ver] sur votre ordinateur.%n%nEverbloomSecurity est un prototype d'antivirus destiné à la recherche et à la démonstration. Veuillez consulter les notes préalables avant de continuer.
french.WelcomeTitle=Assistant d'installation de [name/ver]
german.CreateDesktopIcon=Desktop-Verknüpfung erstellen(&D)
german.RunAfterInstall=EverbloomSecurity nach der Installation starten(&L)
german.ContextMenuTask=Explorer-Kontextmenü für Scan installieren(&C)
german.TasksGroupAdditional=Zusätzliche Symbole
german.TasksGroupOptional=Optionale Aufgaben
german.WelcomeLabel=Dieser Assistent installiert [name/ver] auf Ihrem Computer.%n%nEverbloomSecurity ist ein Antivirus-Prototyp für Forschung und Demonstration. Bitte lesen Sie die Vorbemerkungen, bevor Sie fortfahren.
german.WelcomeTitle=Willkommen beim Setup-Assistenten für [name/ver]
spanish.CreateDesktopIcon=Crear un acceso directo en el escritorio(&D)
spanish.RunAfterInstall=Ejecutar EverbloomSecurity al finalizar la instalación(&L)
spanish.ContextMenuTask=Instalar el menú de análisis con el botón derecho del Explorador(&C)
spanish.TasksGroupAdditional=Iconos adicionales
spanish.TasksGroupOptional=Tareas opcionales
spanish.WelcomeLabel=Este asistente instalará [name/ver] en su ordenador.%n%nEverbloomSecurity es un prototipo de antivirus en fase de investigación y demostración. Revise las notas previas a la instalación antes de continuar.
spanish.WelcomeTitle=Asistente de instalación de [name/ver]
italian.CreateDesktopIcon=Crea un collegamento sul desktop(&D)
italian.RunAfterInstall=Avvia EverbloomSecurity al termine dell'installazione(&L)
italian.ContextMenuTask=Installa il menu di analisi con clic destro di Esplora risorse(&C)
italian.TasksGroupAdditional=Icone aggiuntive
italian.TasksGroupOptional=Attività facoltative
italian.WelcomeLabel=Questa procedura guidata installerà [name/ver] sul computer.%n%nEverbloomSecurity è un prototipo di antivirus in fase di ricerca e dimostrazione. Leggere le note preliminari prima di continuare.
italian.WelcomeTitle=Installazione guidata di [name/ver]
russian.CreateDesktopIcon=Создать ярлык на рабочем столе(&D)
russian.RunAfterInstall=Запустить EverbloomSecurity после установки(&L)
russian.ContextMenuTask=Установить контекстное меню сканирования в Проводнике(&C)
russian.TasksGroupAdditional=Дополнительные значки
russian.TasksGroupOptional=Дополнительные задачи
russian.WelcomeLabel=Эта программа установит [name/ver] на ваш компьютер.%n%nEverbloomSecurity — это исследовательский прототип антивируса. Перед продолжением ознакомьтесь с предварительными замечаниями.
russian.WelcomeTitle=Мастер установки [name/ver]
brazilianportuguese.CreateDesktopIcon=Criar um atalho na área de trabalho(&D)
brazilianportuguese.RunAfterInstall=Executar EverbloomSecurity ao concluir a instalação(&L)
brazilianportuguese.ContextMenuTask=Instalar o menu de análise do clique direito no Explorer(&C)
brazilianportuguese.TasksGroupAdditional=Ícones adicionais
brazilianportuguese.TasksGroupOptional=Tarefas opcionais
brazilianportuguese.WelcomeLabel=Este assistente instalará o [name/ver] no seu computador.%n%nO EverbloomSecurity é um protótipo de antivírus em fase de pesquisa/demonstração. Revise as notas de pré-instalação antes de continuar.
brazilianportuguese.WelcomeTitle=Assistente de instalação do [name/ver]
portuguese.CreateDesktopIcon=Criar um atalho no ambiente de trabalho(&D)
portuguese.RunAfterInstall=Executar EverbloomSecurity no final da instalação(&L)
portuguese.ContextMenuTask=Instalar o menu de análise com botão direito do Explorer(&C)
portuguese.TasksGroupAdditional=Ícones adicionais
portuguese.TasksGroupOptional=Tarefas opcionais
portuguese.WelcomeLabel=Este assistente irá instalar o [name/ver] no seu computador.%n%nO EverbloomSecurity é um protótipo de antivírus em fase de investigação e demonstração. Reveja as notas prévias antes de continuar.
portuguese.WelcomeTitle=Assistente de instalação do [name/ver]

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:TasksGroupAdditional}"; Flags: unchecked
Name: "contextmenu"; Description: "{cm:ContextMenuTask}"; GroupDescription: "{cm:TasksGroupOptional}"; Flags: unchecked
Name: "install_driver"; Description: "{cm:InstallDriverTask}"; GroupDescription: "{cm:TasksGroupOptional}"; Flags: unchecked
Name: "autorunquarantine"; Description: "{cm:RunAfterInstall}"; GroupDescription: "{cm:TasksGroupOptional}"; Flags: checkedonce

[Files]
; Mirror the install/ staging tree verbatim under {app}\.
Source: "{#SourceDir}\bin\*"; DestDir: "{app}\bin"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\doc\*"; DestDir: "{app}\doc"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\share\*"; DestDir: "{app}\share"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\driver\*"; DestDir: "{app}\driver"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
; Make sure engine data directories exist so the first launch has somewhere
; to write its allowlist, quarantine index, and dynamic YARA state.
Name: "{app}\bin\data\rules"
Name: "{app}\bin\data\quarantine\objects"
Name: "{app}\bin\data\quarantine\metadata"

[Icons]
Name: "{commondesktop}\{#AppName}"; Filename: "{app}\bin\everbloom_gui.exe"; Tasks: desktopicon
Name: "{commonstartmenu}\{#AppName}"; Filename: "{app}\bin\everbloom_gui.exe"
Name: "{commonstartmenu}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"

[Run]
; Optional post-install actions: launch the GUI, register the right-click
; context menu, and install the kernel driver. Failures are non-fatal (we
; don't roll back the install if a runtime helper exits non-zero).
Filename: "{app}\bin\register_context_menu.cmd"; Parameters: ""; Flags: runhidden; Tasks: contextmenu; Check: WizardNotSilent
Filename: "{app}\bin\install_driver.cmd"; Parameters: ""; Flags: runhidden; Tasks: install_driver; Check: WizardNotSilent
Filename: "{app}\bin\launch_gui.cmd"; Description: "{cm:RunAfterInstall}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Drop engine caches and quarantine index on uninstall. Users who want to
; keep quarantine state can copy {app}\bin\data\quarantine aside first.
Type: filesandordirs; Name: "{app}\bin\data\quarantine"
Type: filesandordirs; Name: "{app}\bin\data\logs"
Type: filesandordirs; Name: "{app}\bin\data\cache"

[UninstallRun]
; Best-effort: remove the right-click shell extension and unload the kernel
; driver before files disappear. Driver removal is skipped if the service
; is missing.
Filename: "{app}\bin\unregister_context_menu.cmd"; Flags: runhidden
Filename: "{app}\bin\uninstall_driver.cmd"; Flags: runhidden runascurrentuser

[Code]
function WizardNotSilent: Boolean;
begin
  Result := not WizardSilent();
end;

