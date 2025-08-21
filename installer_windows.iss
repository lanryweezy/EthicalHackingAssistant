[Setup]
AppName=Ethical Hacking Assistant
AppVersion=1.0
DefaultDirName={pf}\Ethical Hacking Assistant
DefaultGroupName=Ethical Hacking Assistant
UninstallDisplayIcon={app}\EthicalHackingAssistant.exe
Compression=lzma2
SolidCompression=yes
OutputDir=dist\windows
OutputBaseFilename=EthicalHackingAssistant-Setup
SetupIconFile=assets\icon.ico
LicenseFile=LICENSE
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "dist\EthicalHackingAssistant.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "TERMINAL_SETUP.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Ethical Hacking Assistant"; Filename: "{app}\EthicalHackingAssistant.exe"
Name: "{group}\Uninstall Ethical Hacking Assistant"; Filename: "{uninstallexe}"
Name: "{commondesktop}\Ethical Hacking Assistant"; Filename: "{app}\EthicalHackingAssistant.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{app}\EthicalHackingAssistant.exe"; Description: "Launch Ethical Hacking Assistant"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
