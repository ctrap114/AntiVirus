// EverbloomSecurity extended YARA rule pack - curated strings-only detections covering
// prevalent 2024-2026 stealer, ransomware, loader, RAT, LOLBin, persistence,
// defense-evasion, credential-theft, and C2-pattern families. All rules use
// pure string matching (no YARA modules) so they compile under the vendored
// 4.5.5 build used by the engine.

rule EverbloomSecurity_LummaC2_Stealer
{
    meta:
        author = "EverbloomSecurity"
        description = "LummaC2 stealer campaign markers (loader config strings)"
        severity = "high"
    strings:
        $campaign_a = "lumma" nocase
        $campaign_b = "LummaC2" fullword
        $c2_marker = "/c2socket/" nocase
    condition:
        any of ($campaign_*) or $c2_marker
}

rule EverbloomSecurity_Stealc_Config_Artifact
{
    meta:
        author = "EverbloomSecurity"
        description = "Stealc stealer configuration artifact strings"
        severity = "high"
    strings:
        $a = "stealc" fullword nocase
        $b = "Stealer Stealer" fullword
        $c = "StealerBuildID=" fullword
    condition:
        any of them
}

rule EverbloomSecurity_RedLine_Stealer_Token
{
    meta:
        author = "EverbloomSecurity"
        description = "RedLine stealer token/api markers"
        severity = "high"
    strings:
        $a = "RedLine" fullword nocase
        $b = "redline" fullword
        $c = "RedLine_Stealer_Main" fullword
    condition:
        any of them
}

rule EverbloomSecurity_RaccoonV2_Stealer_Marker
{
    meta:
        author = "EverbloomSecurity"
        description = "Raccoon/RaccoonV2 stealer config string artifacts"
        severity = "high"
    strings:
        $a = "raccoonv2" nocase
        $b = "raccoon_panel" nocase
        $c = "Raccoon Stealer v2" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Vidar_Stealer_Artifact
{
    meta:
        author = "EverbloomSecurity"
        description = "Vidar stealer binary artifacts (loader string + dll name)"
        severity = "high"
    strings:
        $a = "Vidar" fullword
        $b = "vidar.dll" nocase
        $c = "VidarsCampaign=" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Meta_Stealer_Discord
{
    meta:
        author = "EverbloomSecurity"
        description = "Meta stealer Discord exfiltration indicators"
        severity = "high"
    strings:
        $a = "MetaStealer" fullword
        $b = "MetaGrabber" fullword
        $c = "discord.com/api/webhooks" nocase
        $d = "webhook_token" fullword
    condition:
        ($a or $b) and ($c or $d)
}

rule EverbloomSecurity_Amadey_Loader_Artifacts
{
    meta:
        author = "EverbloomSecurity"
        description = "Amadey loader configuration string artifacts"
        severity = "high"
    strings:
        $a = "Amadey" fullword
        $b = "amadey_bot" fullword
        $c = "AmadeyClient" fullword
    condition:
        any of them
}

rule EverbloomSecurity_SmokeLoader_Downloader
{
    meta:
        author = "EverbloomSecurity"
        description = "SmokeLoader downloader string artifacts"
        severity = "high"
    strings:
        $a = "SmokeLoader" fullword
        $b = "smoke_bot" fullword
        $c = "smoke_loader.dll" nocase
    condition:
        any of them
}

rule EverbloomSecurity_PrivateLoader_Panel
{
    meta:
        author = "EverbloomSecurity"
        description = "PrivateLoader panel/build strings"
        severity = "high"
    strings:
        $a = "PrivateLoader" fullword
        $b = "privateloader" fullword
        $c = "PL_BuildID=" fullword
    condition:
        any of them
}

rule EverbloomSecurity_BatLoader_Stage_Marker
{
    meta:
        author = "EverbloomSecurity"
        description = "BatLoader (DBatLoader) stage marker strings"
        severity = "high"
    strings:
        $a = "DBatLoader" fullword
        $b = "BatLoader" fullword
        $c = "bat_loader" fullword
    condition:
        any of them
}

rule EverbloomSecurity_AsyncRAT_Config_Block
{
    meta:
        author = "EverbloomSecurity"
        description = "AsyncRAT configuration block markers"
        severity = "high"
    strings:
        $a = "AsyncClient" fullword
        $b = "AsyncRAT" fullword
        $c = "AsyncRAT_Settings" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Remcos_RAT_Artifacts
{
    meta:
        author = "EverbloomSecurity"
        description = "Remcos RAT configuration strings"
        severity = "high"
    strings:
        $a = "Remcos" fullword
        $b = "remcos_mutex" fullword
        $c = "RemcosBehavior" fullword
    condition:
        any of them
}

rule EverbloomSecurity_NjRAT_Config_Block
{
    meta:
        author = "EverbloomSecurity"
        description = "NjRAT configuration artifacts"
        severity = "high"
    strings:
        $a = "njRAT" fullword
        $b = "NJRAT" fullword
        $c = "'ds'='Microsoft Upd" nocase
    condition:
        any of them
}

rule EverbloomSecurity_Quasar_RAT_Strings
{
    meta:
        author = "EverbloomSecurity"
        description = "Quasar RAT client/build strings"
        severity = "high"
    strings:
        $a = "Quasar Server" fullword
        $b = "Quasar Client" fullword
        $c = "QNCore" fullword
    condition:
        any of them
}

rule EverbloomSecurity_DCRat_Config_Markers
{
    meta:
        author = "EverbloomSecurity"
        description = "DCRat (DarkCrystal RAT) configuration artifacts"
        severity = "high"
    strings:
        $a = "DCRat" fullword
        $b = "DarkCrystal RAT" fullword
        $c = "DCRatMutex" fullword
    condition:
        any of them
}

rule EverbloomSecurity_XWorm_Artifacts
{
    meta:
        author = "EverbloomSecurity"
        description = "XWorm RAT client build strings"
        severity = "high"
    strings:
        $a = "XWorm" fullword
        $b = "XWormClient" fullword
        $c = "XWorm-Mut" fullword
    condition:
        any of them
}

rule EverbloomSecurity_AgentTesla_SMTP
{
    meta:
        author = "EverbloomSecurity"
        description = "AgentTesla SMTP/FTP exfiltration panel artifacts"
        severity = "high"
    strings:
        $a = "AgentTesla" fullword
        $b = "Agent Tesla" fullword
        $c = "TeslaKeylogger" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Akira_Ransomware_Marker
{
    meta:
        author = "EverbloomSecurity"
        description = "Akira ransomware notes and extension markers"
        severity = "high"
    strings:
        $a = "akira" fullword nocase
        $b = ".akira" nocase
        $c = "Akiraransom" fullword
    condition:
        any of them
}

rule EverbloomSecurity_LockBit_Black_Artifacts
{
    meta:
        author = "EverbloomSecurity"
        description = "LockBit Black/3.0 ransomware note and extension strings"
        severity = "high"
    strings:
        $a = "LockBit" fullword
        $b = ".lockbit" nocase
        $c = "Restore-My-Files.txt" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Play_Ransomware_Marker
{
    meta:
        author = "EverbloomSecurity"
        description = "Play ransomware note file markers"
        severity = "high"
    strings:
        $a = "PLAY_README" fullword
        $b = "PLAY ransom" fullword
        $c = ".play" nocase
    condition:
        any of them
}

rule EverbloomSecurity_BlackCat_ALPHV_Marker
{
    meta:
        author = "EverbloomSecurity"
        description = "BlackCat/ALPHV ransomware note strings"
        severity = "high"
    strings:
        $a = "BlackCat" fullword
        $b = "ALPHV" fullword
        $c = "RECOVER-README.txt" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Babuk_Esxi_Artifacts
{
    meta:
        author = "EverbloomSecurity"
        description = "Babuk ESXi variant ransom note strings"
        severity = "high"
    strings:
        $a = "Babuk" fullword
        $b = "How To Restore Your Files.txt" fullword
        $c = ".babyk" nocase
    condition:
        any of them
}

rule EverbloomSecurity_Conti_Ransomware_Artifact
{
    meta:
        author = "EverbloomSecurity"
        description = "Conti ransomware note + extension markers"
        severity = "high"
    strings:
        $a = "CONTI" fullword
        $b = ".conti" nocase
        $c = "CONTI_README.txt" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Stop_Djvu_Artifacts
{
    meta:
        author = "EverbloomSecurity"
        description = "Stop/Djvu ransomware family note strings"
        severity = "high"
    strings:
        $a = "_readme.txt" fullword
        $b = "STOP Djvu" fullword
        $c = "stop ransomware" fullword nocase
    condition:
        any of them
}

rule EverbloomSecurity_Mimic_Ransomware_Marker
{
    meta:
        author = "EverbloomSecurity"
        description = "Mimic ransomware (Conti-based) note string"
        severity = "high"
    strings:
        $a = "Mimic" fullword
        $b = "MIMIC_README.hta" fullword
        $c = ".mimic" nocase
    condition:
        any of them
}

rule EverbloomSecurity_Phobos_Artifacts
{
    meta:
        author = "EverbloomSecurity"
        description = "Phobos ransomware extension + note markers"
        severity = "high"
    strings:
        $a = "phobos" fullword nocase
        $b = ".phobos" nocase
        $c = "info.hta" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Backup_Delete_Shadowcopy
{
    meta:
        author = "EverbloomSecurity"
        description = "Ransomware-style shadow copy deletion commands"
        severity = "high"
    strings:
        $a = "vssadmin delete shadows /all" nocase
        $b = "wbadmin delete catalog -quiet" nocase
        $c = "wbadmin delete systemstatebackup" nocase
    condition:
        any of them
}

rule EverbloomSecurity_Mimikatz_Strings
{
    meta:
        author = "EverbloomSecurity"
        description = "Mimikatz credential dumper string indicators"
        severity = "high"
    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa::logonpasswords" nocase
        $c = "lsadump::sam" nocase
    condition:
        any of them
}

rule EverbloomSecurity_LaZagne_Credentials
{
    meta:
        author = "EverbloomSecurity"
        description = "LaZagne credential recovery tool string"
        severity = "high"
    strings:
        $a = "LaZagne" fullword
        $b = "lazagne" fullword
        $c = "lazagne_project" fullword
    condition:
        any of them
}

rule EverbloomSecurity_WebBrowser_Credential_Loot
{
    meta:
        author = "EverbloomSecurity"
        description = "Browser credential database target strings"
        severity = "high"
    strings:
        $a = "Login Data" fullword
        $b = "Cookies" fullword
        $c = "\\Mozilla\\Firefox\\Profiles" nocase
        $d = "\\Google\\Chrome\\User Data" nocase
    condition:
        2 of them
}

rule EverbloomSecurity_Discord_Token_Grab
{
    meta:
        author = "EverbloomSecurity"
        description = "Discord token capture paths + tokens in process memory"
        severity = "high"
    strings:
        $a = "discordcanary" nocase
        $b = "discord_desktop_core" nocase
        $c = "dQw4w9WgXcQ" fullword
        $d = "tokens.json" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Telegram_Session_Steal
{
    meta:
        author = "EverbloomSecurity"
        description = "Telegram session file loot indicators"
        severity = "high"
    strings:
        $a = "Telegram Desktop" fullword
        $b = "tdata" fullword
        $c = "telgram_session" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Crypto_Wallet_Steal_Paths
{
    meta:
        author = "EverbloomSecurity"
        description = "Browser crypto wallet extension target paths"
        severity = "high"
    strings:
        $a = "\\Extensions\\nkbihfbeogaeaoehlefnkodbefgpgknn" nocase
        $b = "\\Extensions\\ibnejdfjinnkfbnlampopmepkmelmiibl" nocase
        $c = "\\Local Extension Settings" nocase
    condition:
        any of them
}

rule EverbloomSecurity_AMSI_Bypass_Reflection
{
    meta:
        author = "EverbloomSecurity"
        description = "AMSI bypass via .NET reflection string artifacts"
        severity = "high"
    strings:
        $a = "amsiInitFailed" nocase
        $b = "AmsiUtils" fullword
        $c = "System.Management.Automation.AmsiUtils" fullword
    condition:
        any of them
}

rule EverbloomSecurity_ETW_Bypass_DisableTrace
{
    meta:
        author = "EverbloomSecurity"
        description = "ETW bypass / PInvoke etwEventWrite patching strings"
        severity = "high"
    strings:
        $a = "EtwEventWrite" fullword
        $b = "EtwEventWriteFull" fullword
        $c = "ntdll!EtwEventWrite" nocase
    condition:
        any of them
}

rule EverbloomSecurity_Defender_Tamper_Disable
{
    meta:
        author = "EverbloomSecurity"
        description = "Defender real-time protection disable command patterns"
        severity = "high"
    strings:
        $a = "Set-MpPreference" nocase
        $b = "DisableRealtimeMonitoring" nocase
        $c = "Add-MpPreference -ExclusionPath" nocase
    condition:
        any of them
}

rule EverbloomSecurity_Defender_Tamper_Registry
{
    meta:
        author = "EverbloomSecurity"
        description = "Defender DisableAntiSpyware/DisableRealtimeMonitoring registry tampering"
        severity = "high"
    strings:
        $a = "DisableAntiSpyware" nocase
        $b = "DisableRealtimeMonitoring" nocase
        $c = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" nocase
    condition:
        any of them
}

rule EverbloomSecurity_UAC_Bypass_Fodhelper
{
    meta:
        author = "EverbloomSecurity"
        description = "UAC bypass via fodhelper/ComputerDefaults/EventVwr registry hijack"
        severity = "high"
    strings:
        $a = "ms-settings\\shell\\open\\command" nocase
        $b = "mscfile\\shell\\open\\command" nocase
        $c = "Software\\Classes\\ms-settings" nocase
    condition:
        any of them
}

rule EverbloomSecurity_Persistence_Run_Key
{
    meta:
        author = "EverbloomSecurity"
        description = "Run/RunOnce persistence registry value writes"
        severity = "high"
    strings:
        $a = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $b = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $c = "CurrentVersion\\Explorer\\Shell Folders" nocase
    condition:
        any of them
}

rule EverbloomSecurity_Persistence_ScheduledTask_HighPriv
{
    meta:
        author = "EverbloomSecurity"
        description = "Schtasks /IT and at.exe style persistence"
        severity = "high"
    strings:
        $a = "schtasks /create" nocase
        $b = "/rl highest" nocase
        $c = "New-ScheduledTask" nocase
    condition:
        any of them
}

rule EverbloomSecurity_Persistence_Service_Install
{
    meta:
        author = "EverbloomSecurity"
        description = "Service install via sc.exe or CreateService with suspicious binary path"
        severity = "high"
    strings:
        $a = "sc create" nocase
        $b = "sc.exe create" nocase
        $c = "CreateService" nocase
        $d = "StartService" nocase
    condition:
        2 of them
}

rule EverbloomSecurity_Persistence_WMI_Event
{
    meta:
        author = "EverbloomSecurity"
        description = "WMI event subscription persistence via PowerShell"
        severity = "high"
    strings:
        $a = "__EventFilter" fullword
        $b = "CommandLineEventConsumer" fullword
        $c = "Register-WmiEvent" nocase
    condition:
        any of them
}

rule EverbloomSecurity_LSASS_Handle_Open
{
    meta:
        author = "EverbloomSecurity"
        description = "Process access rights patterns targeting LSASS (MiniDumpWriteDump chains)"
        severity = "high"
    strings:
        $a = "MiniDumpWriteDump" fullword
        $b = "lsass.exe" nocase
    condition:
        $a and $b
}

rule EverbloomSecurity_PowerShell_Network_ReverseShell
{
    meta:
        author = "EverbloomSecurity"
        description = "PowerShell reverse shell / download cradle command patterns"
        severity = "high"
    strings:
        $a = "$client = New-Object System.Net.Sockets.TCPClient" nocase
        $b = "Net.Sockets.TCPClient" nocase
        $c = "System.Net.WebClient).DownloadString" nocase
    condition:
        any of them
}

rule EverbloomSecurity_Encoded_PowerShell_Command
{
    meta:
        author = "EverbloomSecurity"
        description = "PowerShell -EncodedCommand usage with -WindowStyle Hidden (suspicious chain)"
        severity = "medium"
    strings:
        $a = "-EncodedCommand" nocase
        $b = "-WindowStyle Hidden" nocase
        $c = "powershell.exe" nocase
    condition:
        2 of them
}

rule EverbloomSecurity_MShta_Remote_Execution
{
    meta:
        author = "EverbloomSecurity"
        description = "mshta.exe executing remote HTML/JS payloads"
        severity = "high"
    strings:
        $a = "mshta http" nocase
        $b = "mshta.exe" nocase
        $c = "about:<script" nocase
    condition:
        $a or ($b and $c)
}

rule EverbloomSecurity_Rundll32_Unsigned
{
    meta:
        author = "EverbloomSecurity"
        description = "rundll32.exe with no args + suspicious DLL (proxy for unsigned script)"
        severity = "high"
    strings:
        $a = "rundll32.exe" nocase
        $b = "javascript:" nocase
        $c = "shell32.dll" nocase
    condition:
        $a and $b and not $c
}

rule EverbloomSecurity_Regsvr32_Squiblydoo
{
    meta:
        author = "EverbloomSecurity"
        description = "regsvr32 squiblydoo/AppLocker bypass command"
        severity = "high"
    strings:
        $a = "regsvr32 /s /n /u /i:" nocase
        $b = "scrobj.dll" nocase
        $c = "regsvr32.exe" nocase
    condition:
        $a and $b and $c
}

rule EverbloomSecurity_Certutil_Encoder_Abuse
{
    meta:
        author = "EverbloomSecurity"
        description = "certutil used for download/encoding (LOLBin abuse)"
        severity = "high"
    strings:
        $a = "certutil.exe -urlcache" nocase
        $b = "certutil -decode" nocase
        $c = "certutil.exe" nocase
        $d = "split" nocase
    condition:
        $a or $b or ($c and $d)
}

rule EverbloomSecurity_Bitsadmin_Download
{
    meta:
        author = "EverbloomSecurity"
        description = "bitsadmin transfer /download LOLBin abuse"
        severity = "high"
    strings:
        $a = "bitsadmin /transfer" nocase
        $b = "bitsadmin.exe" nocase
        $c = "/download" nocase
    condition:
        $a or ($b and $c)
}

rule EverbloomSecurity_Powershell_Bypass_ExecutionPolicy
{
    meta:
        author = "EverbloomSecurity"
        description = "PowerShell ExecutionPolicy bypass markers"
        severity = "high"
    strings:
        $a = "-ExecutionPolicy Bypass" nocase
        $b = "-ExecutionPolicy Unrestricted" nocase
        $c = "Set-ExecutionPolicy" nocase
    condition:
        any of them
}

rule EverbloomSecurity_ScheduledTask_Template_Suspicious
{
    meta:
        author = "EverbloomSecurity"
        description = "Schtasks /create /xml + suspicious command tail"
        severity = "high"
    strings:
        $a = "/create /xml" nocase
        $b = "schtasks" nocase
        $c = "powershell" nocase
    condition:
        all of them
}

rule EverbloomSecurity_Netsh_Firewall_Tamper
{
    meta:
        author = "EverbloomSecurity"
        description = "netsh advfirewall / firewall tampering"
        severity = "high"
    strings:
        $a = "netsh advfirewall set" nocase
        $b = "netsh firewall set" nocase
        $c = "netsh.exe" nocase
        $d = "firewall" nocase
    condition:
        $a or $b or ($c and $d)
}

rule EverbloomSecurity_Process_Hollowing_Artifacts
{
    meta:
        author = "EverbloomSecurity"
        description = "Process hollowing API set (NtUnmapViewOfSection + WriteProcessMemory + ResumeThread)"
        severity = "high"
    strings:
        $a = "NtUnmapViewOfSection" fullword
        $b = "WriteProcessMemory" fullword
        $c = "ResumeThread" fullword
        $d = "ZwMapViewOfSection" fullword
    condition:
        $a and $b and $c and $d
}

rule EverbloomSecurity_Reflective_Loader_Markers
{
    meta:
        author = "EverbloomSecurity"
        description = "Reflective DLL loading via VirtualAlloc + custom PE parsing"
        severity = "medium"
    strings:
        $a = "VirtualAlloc" fullword
        $b = "IMAGE_NT_HEADERS" fullword
        $c = "IMAGE_DOS_SIGNATURE" fullword
        $d = "LoadLibraryA" fullword
    condition:
        2 of them
}

rule EverbloomSecurity_Cobalt_Strike_Beacon_Config
{
    meta:
        author = "EverbloomSecurity"
        description = "Cobalt Strike beacon config artifact indicators"
        severity = "high"
    strings:
        $a = "%s as %s\\%s: %d" fullword
        $b = "beacon.dll" nocase
        $c = "Malleable C2" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Cobalt_Strike_Default_Port
{
    meta:
        author = "EverbloomSecurity"
        description = "Cobalt Strike default port strings / HTTPS fields"
        severity = "high"
    strings:
        $a = "cobaltstrike" nocase
        $b = "CS-" fullword
        $c = "beacon_config" fullword
    condition:
        any of them
}

rule EverbloomSecurity_AsyncRAT_RemoteShell_Command
{
    meta:
        author = "EverbloomSecurity"
        description = "AsyncRAT shell.do command indicators"
        severity = "high"
    strings:
        $a = "shell.do" fullword
        $b = "AsyncRAT" fullword
        $c = "dossh" fullword
    condition:
        any of them
}

rule EverbloomSecurity_PlugX_RAT_Artifacts
{
    meta:
        author = "EverbloomSecurity"
        description = "PlugX RAT campaign string artifacts"
        severity = "high"
    strings:
        $a = "PlugX" fullword
        $b = "plugx_dll" fullword
        $c = "KORPLUG" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Cobalt_Strike_Malleable
{
    meta:
        author = "EverbloomSecurity"
        description = "Cobalt Strike malleable profile header indicator"
        severity = "high"
    strings:
        $a = "http-get" fullword
        $b = "http-post" fullword
        $c = "client {" fullword
    condition:
        2 of them
}

rule EverbloomSecurity_Pupy_RAT_Artifacts
{
    meta:
        author = "EverbloomSecurity"
        description = "Pupy RAT client config artifacts"
        severity = "high"
    strings:
        $a = "Pupy" fullword
        $b = "pupy_" fullword
        $c = "PUPYC" fullword
    condition:
        any of them
}

rule EverbloomSecurity_BruteRatel_C4_Config
{
    meta:
        author = "EverbloomSecurity"
        description = "Brute Ratel C4 default config artifacts"
        severity = "high"
    strings:
        $a = "Brute Ratel" fullword
        $b = "BruteRatel" fullword
        $c = "C4_Profile" fullword
    condition:
        any of them
}

rule EverbloomSecurity_APT_Loader_Macro_Office
{
    meta:
        author = "EverbloomSecurity"
        description = "APT-style Office macro download+execute chain"
        severity = "high"
    strings:
        $a = "AutoOpen" fullword
        $b = "Document_Open" fullword
        $c = "powershell" nocase
        $d = "mshta" nocase
    condition:
        ($a or $b) and ($c or $d)
}

rule EverbloomSecurity_Powershell_Cred_Dump_Pattern
{
    meta:
        author = "EverbloomSecurity"
        description = "PowerShell credential dump / system.management pattern"
        severity = "high"
    strings:
        $a = "Get-CachedRdpConnection" nocase
        $b = "Get-VaultCredential" nocase
        $c = "Windows.Security.Credentials" nocase
    condition:
        any of them
}

rule EverbloomSecurity_NetworkBeacon_Beacon_Interval
{
    meta:
        author = "EverbloomSecurity"
        description = "C2-style beacon interval artifacts in code"
        severity = "medium"
    strings:
        $a = "beacon_interval" fullword
        $b = "jitter=" fullword
        $c = "callback_url" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Base64_PowerShell_Payload
{
    meta:
        author = "EverbloomSecurity"
        description = "Large base64-decoded PowerShell payload markers (decoder shape)"
        severity = "medium"
    strings:
        $a = "FromBase64String" nocase
        $b = "Invoke-Expression" nocase
        $c = "IEX(" nocase
    condition:
        2 of them
}

rule EverbloomSecurity_CobaltStrike_Beacon_Imports
{
    meta:
        author = "EverbloomSecurity"
        description = "Cobalt Strike beacon-style network API imports (winexec + wininet)"
        severity = "high"
    strings:
        $a = "InternetOpenA" fullword
        $b = "InternetConnectA" fullword
        $c = "HttpSendRequestA" fullword
    condition:
        all of them
}

rule EverbloomSecurity_Credential_Access_Browser_History
{
    meta:
        author = "EverbloomSecurity"
        description = "Browser history exfil strings (History + login_data SQLite)"
        severity = "high"
    strings:
        $a = "places.sqlite" fullword
        $b = "logins.json" fullword
        $c = "Login Data" fullword
        $d = "Cookies" fullword
    condition:
        2 of them
}

rule EverbloomSecurity_Persistence_Startup_Folder
{
    meta:
        author = "EverbloomSecurity"
        description = "Startup folder persistence path indicators"
        severity = "high"
    strings:
        $a = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase
        $b = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu" nocase
        $c = "\\Start Menu\\Programs\\Startup" nocase
    condition:
        any of them
}

rule EverbloomSecurity_WMI_Persistence_Template
{
    meta:
        author = "EverbloomSecurity"
        description = "WMI event subscription persistence template strings"
        severity = "high"
    strings:
        $a = "SELECT * FROM __InstanceModificationEvent" nocase
        $b = "ActiveScriptEventConsumer" fullword
        $c = "CommandLineEventConsumer" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Netsh_Helper_DLL
{
    meta:
        author = "EverbloomSecurity"
        description = "Netsh helper DLL persistence via add helper"
        severity = "high"
    strings:
        $a = "netsh add helper" nocase
        $b = "RegisterHelper" fullword
        $c = "HelperLoadStatus" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Lateral_Movement_PSExec
{
    meta:
        author = "EverbloomSecurity"
        description = "PsExec / WMI lateral movement command patterns"
        severity = "high"
    strings:
        $a = "psexec.exe" nocase
        $b = "PsExec64.exe" nocase
        $c = "wmic /node:" nocase
    condition:
        any of them
}

rule EverbloomSecurity_AntiDebug_Sleep_Acceleration
{
    meta:
        author = "EverbloomSecurity"
        description = "Anti-debug / sleep acceleration artifacts"
        severity = "medium"
    strings:
        $a = "IsDebuggerPresent" fullword
        $b = "CheckRemoteDebuggerPresent" fullword
        $c = "NtQueryInformationProcess" fullword
    condition:
        any of them
}

rule EverbloomSecurity_AntiVM_Sandbox_Artifacts
{
    meta:
        author = "EverbloomSecurity"
        description = "Anti-VM / anti-sandbox artifact strings (vmware/qemu/vbox)"
        severity = "medium"
    strings:
        $a = "vmware" fullword nocase
        $b = "VirtualBox" fullword
        $c = "QEMU" fullword
        $d = "SbieDll.dll" nocase
    condition:
        any of them
}

rule EverbloomSecurity_Ransomware_Note_Generator
{
    meta:
        author = "EverbloomSecurity"
        description = "Generic ransom note generator scripts with .onion instructions"
        severity = "high"
    strings:
        $a = "Your files have been encrypted" fullword
        $b = "bitcoin address" nocase
        $c = ".onion" fullword
    condition:
        2 of them
}

rule EverbloomSecurity_Exfil_Cloud_Upload
{
    meta:
        author = "EverbloomSecurity"
        description = "Suspicious cloud upload exfil via legitimate file share hostnames"
        severity = "high"
    strings:
        $a = "transfer.sh" nocase
        $b = "anonfiles.com" nocase
        $c = "mega.nz" nocase
        $d = "gofile.io" nocase
    condition:
        any of them
}

rule EverbloomSecurity_Keylogger_Api_Chain
{
    meta:
        author = "EverbloomSecurity"
        description = "Keylogger-style API chain (GetAsyncKeyState + GetForegroundWindow)"
        severity = "high"
    strings:
        $a = "GetAsyncKeyState" fullword
        $b = "GetForegroundWindow" fullword
        $c = "GetWindowText" fullword
    condition:
        $a and ($b or $c)
}

rule EverbloomSecurity_Screenshot_Exfil
{
    meta:
        author = "EverbloomSecurity"
        description = "Screenshot capture and exfiltration chain (BitBlt + encoding)"
        severity = "high"
    strings:
        $a = "BitBlt" fullword
        $b = "GetDesktopWindow" fullword
        $c = "FromBase64String" fullword
    condition:
        ($a or $b) and $c
}

rule EverbloomSecurity_Phishing_Html_Form
{
    meta:
        author = "EverbloomSecurity"
        description = "HTML phishing form targeting Office 365 / Outlook credentials"
        severity = "medium"
    strings:
        $a = "login.microsoftonline.com" nocase
        $b = "outlook.office.com" nocase
        $c = "form action=\"https://" nocase
    condition:
        ($a or $b) and $c
}

rule EverbloomSecurity_Stealer_Browser_Extension_Target
{
    meta:
        author = "EverbloomSecurity"
        description = "Browser extension targeted by crypto/credential stealers"
        severity = "high"
    strings:
        $a = "nkbihfbeogaeaoehlefnkodbefgpgknn" fullword
        $b = "ibnejdfjinnkfbnlampopmepkmelmiibl" fullword
        $c = "fhbohimaelbohpjbbldcngcnapdodjpdl" fullword
        $d = "afbcbjpbpfadlkmhmclhkeezdmkkdcmf" fullword
    condition:
        any of them
}

rule EverbloomSecurity_PE_Header_Tamper
{
    meta:
        author = "EverbloomSecurity"
        description = "PE header tampering indicators (SizeOfImage manipulation)"
        severity = "medium"
    strings:
        $a = "SizeOfImage" fullword
        $b = "NtCreateSection" fullword
        $c = "NtMapViewOfSection" fullword
    condition:
        2 of them
}

rule EverbloomSecurity_LockBit_4_Artifacts
{
    meta:
        author = "EverbloomSecurity"
        description = "LockBit 4.0 ransomware note + icon artifact strings"
        severity = "high"
    strings:
        $a = "LockBit 4.0" fullword
        $b = "Lock.ico" fullword
        $c = "Restore-Files.txt" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Ransomware_RC4_KeyStub
{
    meta:
        author = "EverbloomSecurity"
        description = "Ransomware RC4 setup stub (keyinit + transform indicator)"
        severity = "medium"
    strings:
        $a = "RC4Init" fullword
        $b = "rc4_key" fullword
        $c = "keyinit" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Chacha20_Key_Stub
{
    meta:
        author = "EverbloomSecurity"
        description = "ChaCha20 key setup indicator (ransomware/stealer families)"
        severity = "medium"
    strings:
        $a = "chacha20_keysetup" fullword
        $b = "chacha20_block" fullword
        $c = "ChaCha20_Key" fullword
    condition:
        any of them
}

rule EverbloomSecurity_Stealer_Discord_Webhook
{
    meta:
        author = "EverbloomSecurity"
        description = "Discord webhook exfil string + token capture in same file"
        severity = "high"
    strings:
        $a = "discord.com/api/webhooks" nocase
        $b = "Webhook" fullword
        $c = "auth.token" fullword
    condition:
        $a and $b and $c
}

rule EverbloomSecurity_Generic_Malformed_PE_Name
{
    meta:
        author = "EverbloomSecurity"
        description = "PE file masquerading as a document but with high-entropy section names"
        severity = "medium"
    strings:
        $fake_pdf = "%%PDF" fullword
        $fake_doc = "PK" fullword
        $a = ".text" fullword
    condition:
        ($fake_pdf or $fake_doc) and $a
}
