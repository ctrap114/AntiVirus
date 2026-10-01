rule EverbloomSecurity_EICAR_Test_File
{
    meta:
        author = "EverbloomSecurity"
        description = "Standard EICAR antivirus test file"
        severity = "test"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}

rule EverbloomSecurity_PowerShell_Download_Execute
{
    meta:
        author = "EverbloomSecurity"
        description = "High-confidence PowerShell download followed by dynamic execution indicators"
        severity = "high"

    strings:
        $powershell = "powershell" nocase
        $download_webclient = "Net.WebClient" nocase
        $download_request = "Invoke-WebRequest" nocase
        $download_string = "DownloadString" nocase
        $download_bits = "Start-BitsTransfer" nocase
        $execute_iex = "Invoke-Expression" nocase
        $execute_short = "IEX(" nocase
        $execute_start = "Start-Process" nocase
        $execute_encoded = "-EncodedCommand" nocase
        $execute_decode = "FromBase64String" nocase

    condition:
        $powershell and 1 of ($download_*) and 1 of ($execute_*)
}

rule EverbloomSecurity_Process_Injection_Imports
{
    meta:
        author = "EverbloomSecurity"
        description = "Common remote-process injection API set present together"
        severity = "high"

    strings:
        $open = "OpenProcess" ascii wide nocase
        $allocate = "VirtualAllocEx" ascii wide nocase
        $write = "WriteProcessMemory" ascii wide nocase
        $thread = "CreateRemoteThread" ascii wide nocase
        $protect = "VirtualProtectEx" ascii wide nocase

    condition:
        all of them
}

rule EverbloomSecurity_SilverFox_ValleyRAT_BYOVD_Chain
{
    meta:
        author = "EverbloomSecurity"
        description = "Silver Fox/ValleyRAT-style loader with a vulnerable security driver and process termination capability"
        severity = "high"
        family = "ValleyRAT/Winos"
        reference = "https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/"

    strings:
        $driver_amsdk = "amsdk.sys" ascii wide nocase
        $driver_zam = "ZAM.exe" ascii wide nocase
        $driver_watchdog = "WatchDog Antimalware" ascii wide nocase
        $terminate_1 = "TerminateProcess" ascii wide nocase
        $terminate_2 = "NtTerminateProcess" ascii wide nocase
        $terminate_3 = "ZwTerminateProcess" ascii wide nocase
        $security_1 = "MsMpEng.exe" ascii wide nocase
        $security_2 = "WinDefend" ascii wide nocase
        $security_3 = "CSFalconService.exe" ascii wide nocase
        $security_4 = "ekrn.exe" ascii wide nocase
        $security_5 = "avp.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($driver_*) and
        1 of ($terminate_*) and
        1 of ($security_*)
}

rule EverbloomSecurity_SilverFox_ValleyRAT_Reflective_Loader
{
    meta:
        author = "EverbloomSecurity"
        description = "Reflective ValleyRAT/Winos loader artifacts associated with Silver Fox campaigns"
        severity = "medium"
        family = "ValleyRAT/Winos"
        reference = "https://research.checkpoint.com/2025/cracking-valleyrat-from-builder-secrets-to-kernel-rootkits/"

    strings:
        $family_1 = "ValleyRAT" ascii wide nocase
        $family_2 = "Winos" ascii wide nocase
        $module_1 = "LoginModule.dll" ascii wide nocase
        $module_2 = "\xE4\xB8\x8A\xE7\xBA\xBF\xE6\xA8\xA1\xE5\x9D\x97.dll" ascii
        $callback_1 = "EnumWindows" ascii wide nocase
        $callback_2 = "EnumChildWindows" ascii wide nocase
        $memory_1 = "VirtualProtect" ascii wide nocase
        $memory_2 = "NtProtectVirtualMemory" ascii wide nocase
        $memory_3 = "RtlMoveMemory" ascii wide nocase
        $memory_4 = "NtFlushInstructionCache" ascii wide nocase
        $resolve_1 = "GetProcAddress" ascii wide nocase
        $resolve_2 = "LoadLibrary" ascii wide nocase
        $export_run = "run" ascii wide

    condition:
        uint16(0) == 0x5a4d and
        (
            (
                1 of ($family_*) and
                1 of ($callback_*) and
                2 of ($memory_*) and
                $export_run
            ) or
            (
                1 of ($module_*) and
                1 of ($callback_*) and
                ($memory_3 or $memory_4) and
                ($resolve_1 or $resolve_2) and
                $export_run
            )
        )
}

rule EverbloomSecurity_WhiteBlack_Proxy_Sideload_Injection
{
    meta:
        author = "EverbloomSecurity"
        description = "Proxy-DLL side-loading artifacts combined with in-memory execution or remote-process injection"
        severity = "medium"
        technique = "DLL side-loading and process injection correlation"
        false_positive_control = "Requires a proxy library, loader marker, and memory/injection API evidence"

    strings:
        $proxy_1 = "version.dll" ascii wide nocase
        $proxy_2 = "winmm.dll" ascii wide nocase
        $proxy_3 = "dbghelp.dll" ascii wide nocase
        $proxy_4 = "wininet.dll" ascii wide nocase
        $proxy_5 = "cryptbase.dll" ascii wide nocase
        $resolve_1 = "LoadLibrary" ascii wide nocase
        $resolve_2 = "GetProcAddress" ascii wide nocase
        $loader_1 = "DllMain" ascii wide nocase
        $loader_2 = "EnumWindows" ascii wide nocase
        $loader_3 = "EnumChildWindows" ascii wide nocase
        $memory_1 = "VirtualAlloc" ascii wide nocase
        $memory_2 = "VirtualProtect" ascii wide nocase
        $memory_3 = "WriteProcessMemory" ascii wide nocase
        $memory_4 = "CreateRemoteThread" ascii wide nocase
        $path_1 = "\\AppData\\" ascii wide nocase
        $path_2 = "\\Local\\Temp\\" ascii wide nocase
        $path_3 = "\\Downloads\\" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($proxy_*) and
        2 of ($resolve_*, $loader_*) and
        1 of ($path_*) and
        (
            ($memory_3 or $memory_4) or
            ($memory_1 and $memory_2)
        )
}

rule EverbloomSecurity_APC_Reflective_Injection_Chain
{
    meta:
        author = "EverbloomSecurity"
        description = "APC queueing correlated with remote allocation, memory write, and execution resumption"
        severity = "high"
        technique = "APC or PoolParty-style process injection"
        false_positive_control = "Requires four independent remote-injection capabilities"

    strings:
        $queue_1 = "QueueUserAPC" ascii wide nocase
        $queue_2 = "NtQueueApcThread" ascii wide nocase
        $queue_3 = "ZwQueueApcThread" ascii wide nocase
        $alloc_1 = "VirtualAllocEx" ascii wide nocase
        $alloc_2 = "NtAllocateVirtualMemory" ascii wide nocase
        $write_1 = "WriteProcessMemory" ascii wide nocase
        $write_2 = "NtWriteVirtualMemory" ascii wide nocase
        $resume_1 = "ResumeThread" ascii wide nocase
        $resume_2 = "NtTestAlert" ascii wide nocase
        $resume_3 = "NtCreateThreadEx" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($queue_*) and
        1 of ($alloc_*) and
        1 of ($write_*) and
        1 of ($resume_*)
}

rule EverbloomSecurity_ThreadPool_Reflective_Obfuscation
{
    meta:
        author = "EverbloomSecurity"
        description = "Thread-pool work/timer scheduling used with memory protection or dynamic API resolution"
        severity = "medium"
        rationale = "The combination is more specific than any individual thread-pool API and is intended to reduce false positives."

    strings:
        $pool_1 = "CreateThreadpoolWork" ascii wide nocase
        $pool_2 = "TpAllocWork" ascii wide nocase
        $pool_3 = "TpPostWork" ascii wide nocase
        $pool_4 = "TrySubmitThreadpoolCallback" ascii wide nocase
        $pool_5 = "SetThreadpoolTimer" ascii wide nocase
        $pool_6 = "CreateThreadpoolTimer" ascii wide nocase
        $pool_7 = "SubmitThreadpoolWork" ascii wide nocase
        $pool_8 = "CloseThreadpoolWork" ascii wide nocase
        $memory_1 = "VirtualAlloc" ascii wide nocase
        $memory_2 = "VirtualProtect" ascii wide nocase
        $memory_3 = "NtProtectVirtualMemory" ascii wide nocase
        $memory_4 = "RtlMoveMemory" ascii wide nocase
        $resolve_1 = "GetProcAddress" ascii wide nocase
        $resolve_2 = "LoadLibrary" ascii wide nocase
        $execution_1 = "QueueUserWorkItem" ascii wide nocase
        $execution_2 = "NtCreateThreadEx" ascii wide nocase
        $execution_3 = "WriteProcessMemory" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        2 of ($pool_*) and
        ($memory_1 or $memory_2 or $memory_3 or $memory_4) and
        1 of ($resolve_*) and
        1 of ($execution_*)
}

rule EverbloomSecurity_Defender_AMSI_ETW_Tampering_Chain
{
    meta:
        author = "EverbloomSecurity"
        description = "Security telemetry or Defender configuration tampering combined with memory modification"
        severity = "high"

    strings:
        $telemetry_1 = "AmsiScanBuffer" ascii wide nocase
        $telemetry_2 = "EtwEventWrite" ascii wide nocase
        $defender_1 = "DisableRealtimeMonitoring" ascii wide nocase
        $defender_2 = "ExclusionPath" ascii wide nocase
        $defender_3 = "Set-MpPreference" ascii wide nocase
        $memory_1 = "VirtualProtect" ascii wide nocase
        $memory_2 = "WriteProcessMemory" ascii wide nocase
        $memory_3 = "NtProtectVirtualMemory" ascii wide nocase
        $module_1 = "amsi.dll" ascii wide nocase
        $module_2 = "ntdll.dll" ascii wide nocase
        $shell_1 = "powershell" ascii wide nocase
        $shell_2 = "pwsh" ascii wide nocase
        $shell_3 = "cmd.exe" ascii wide nocase
        $patch_1 = { B8 57 00 07 80 C3 }
        $patch_2 = { B8 00 00 00 00 C3 }

    condition:
        uint16(0) == 0x5a4d and
        (
            (
                $telemetry_1 and
                $telemetry_2 and
                1 of ($module_*) and
                1 of ($patch_*)
            ) or
            (
                1 of ($defender_*) and
                1 of ($memory_*) and
                1 of ($shell_*)
            )
        )
}

rule EverbloomSecurity_Suspicious_UAC_Bypass_Persistence_Chain
{
    meta:
        author = "EverbloomSecurity"
        description = "Known UAC-bypass target combined with its registry hijack key, execution, and override value"
        severity = "medium"

    strings:
        $uac_1 = "fodhelper.exe" ascii wide nocase
        $uac_2 = "eventvwr.exe" ascii wide nocase
        $uac_3 = "computerdefaults.exe" ascii wide nocase
        $uac_4 = "sdclt.exe" ascii wide nocase
        $uac_key_1 = "ms-settings\\shell\\open\\command" ascii wide nocase
        $uac_key_2 = "mscfile\\shell\\open\\command" ascii wide nocase
        $uac_key_3 = "ms-settings\\shell\\open\\command" ascii wide nocase
        $uac_key_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths" ascii wide nocase
        $uac_value_1 = "DelegateExecute" ascii wide nocase
        $uac_value_2 = "IsolatedCommand" ascii wide nocase
        $exec_1 = "CreateProcess" ascii wide nocase
        $exec_2 = "ShellExecute" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($exec_*) and
        (
            ($uac_1 and $uac_key_1 and $uac_value_1) or
            ($uac_2 and $uac_key_2 and $uac_value_2) or
            ($uac_3 and $uac_key_3 and $uac_value_1) or
            ($uac_4 and $uac_key_4 and $uac_value_2)
        )
}

rule EverbloomSecurity_Emotet_Macro_Dropper_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "Emotet/Heodo-style document or script dropper using an auto-run macro, script host, download and execution chain"
        severity = "high"
        family = "Emotet/Heodo/Geodo"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-280a"

    strings:
        $macro_1 = "AutoOpen" ascii wide nocase
        $macro_2 = "Document_Open" ascii wide nocase
        $macro_3 = "Workbook_Open" ascii wide nocase
        $script_1 = "WScript.Shell" ascii wide nocase
        $script_2 = "powershell" ascii wide nocase
        $script_3 = "cmd.exe" ascii wide nocase
        $download_1 = "URLDownloadToFile" ascii wide nocase
        $download_2 = "WinHttpRequest" ascii wide nocase
        $download_3 = "ADODB.Stream" ascii wide nocase
        $execute_1 = "regsvr32" ascii wide nocase
        $execute_2 = "rundll32" ascii wide nocase
        $execute_3 = "ShellExecute" ascii wide nocase

    condition:
        1 of ($macro_*) and
        1 of ($script_*) and
        1 of ($download_*) and
        1 of ($execute_*)
}

rule EverbloomSecurity_QakBot_QBot_Modular_Loader_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "QakBot/QBot/Pinkslipbot modular loader with persistence and network or lateral-movement artifacts"
        severity = "high"
        family = "QakBot/QBot/Pinkslipbot"
        reference = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan%3AWin64%2FQakbot"

    strings:
        $family_1 = "QakBot" ascii wide nocase
        $family_2 = "QBot" ascii wide nocase
        $family_3 = "Pinkslipbot" ascii wide nocase
        $persist_1 = "CurrentVersion\\Run" ascii wide nocase
        $persist_2 = "CurrentControlSet\\services" ascii wide nocase
        $network_1 = "WinHttpOpen" ascii wide nocase
        $network_2 = "InternetOpen" ascii wide nocase
        $network_3 = "URLDownloadToFile" ascii wide nocase
        $lateral_1 = "C$" ascii wide
        $lateral_2 = "Admin$" ascii wide
        $lateral_3 = "esentutl.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($family_*) and
        1 of ($persist_*) and
        (1 of ($network_*) or 1 of ($lateral_*))
}

rule EverbloomSecurity_AgentTesla_CredentialStealer_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "Agent Tesla and related credential-stealer variants accessing browser, mail and FTP credential stores"
        severity = "high"
        family = "Agent Tesla"

    strings:
        $family_1 = "Agent Tesla" ascii wide nocase
        $family_2 = "AgentTesla" ascii wide nocase
        $browser_1 = "Login Data" ascii wide nocase
        $browser_2 = "Web Data" ascii wide nocase
        $browser_3 = "Cookies" ascii wide nocase
        $browser_4 = "key3.db" ascii wide nocase
        $ftp_1 = "FileZilla" ascii wide nocase
        $ftp_2 = "WinSCP" ascii wide nocase
        $mail_1 = "Thunderbird" ascii wide nocase
        $mail_2 = "Outlook" ascii wide nocase
        $exfil_1 = "SmtpClient" ascii wide nocase
        $exfil_2 = "FtpWebRequest" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($family_*) and
        1 of ($browser_*, $ftp_*, $mail_*) and
        1 of ($exfil_*)
}

rule EverbloomSecurity_AsyncRAT_AsyncRat_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "AsyncRAT-style .NET remote-access client with configuration, host fingerprint and surveillance capability markers"
        severity = "high"
        family = "AsyncRAT"

    strings:
        $family_1 = "AsyncRAT" ascii wide nocase
        $family_2 = "Async Rat" ascii wide nocase
        $config_1 = "ClientSettings" ascii wide nocase
        $config_2 = "HWID" ascii wide nocase
        $config_3 = "C2Server" ascii wide nocase
        $evasion_1 = "AntiAnalysis" ascii wide nocase
        $evasion_2 = "IsDebuggerPresent" ascii wide nocase
        $capability_1 = "GetAsyncKeyState" ascii wide nocase
        $capability_2 = "ScreenCapture" ascii wide nocase
        $capability_3 = "AesManaged" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($family_*) and
        2 of ($config_*, $evasion_*, $capability_*)
}

rule EverbloomSecurity_Remcos_RAT_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "Remcos remote-access trojan variants with persistence and surveillance capability markers"
        severity = "high"
        family = "Remcos"

    strings:
        $family_1 = "Remcos" ascii wide nocase
        $family_2 = "Remcos RAT" ascii wide nocase
        $config_1 = "Remcos\\" ascii wide nocase
        $config_2 = "api.telegram.org" ascii wide nocase
        $capability_1 = "Keylogger" ascii wide nocase
        $capability_2 = "Screenshot" ascii wide nocase
        $capability_3 = "WebCam" ascii wide nocase
        $persist_1 = "CurrentVersion\\Run" ascii wide nocase
        $persist_2 = "Startup" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($family_*) and
        2 of ($config_*, $capability_*, $persist_*)
}

rule EverbloomSecurity_njRAT_Bladabindi_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "njRAT/Bladabindi remote-access variants with keyboard, desktop or removable-media monitoring"
        severity = "high"
        family = "njRAT/Bladabindi"

    strings:
        $family_1 = "njRAT" ascii wide nocase
        $family_2 = "Bladabindi" ascii wide nocase
        $capability_1 = "keylog" ascii wide nocase
        $capability_2 = "GetDesktopWindow" ascii wide nocase
        $capability_3 = "GetForegroundWindow" ascii wide nocase
        $capability_4 = "GetDriveType" ascii wide nocase
        $capability_5 = "Win32_DiskDrive" ascii wide nocase
        $network_1 = "TcpClient" ascii wide nocase
        $network_2 = "NetworkStream" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($family_*) and
        1 of ($capability_*) and
        1 of ($network_*)
}

rule EverbloomSecurity_RedLine_Stealer_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "RedLine-style browser and cryptocurrency credential stealer variants"
        severity = "high"
        family = "RedLine Stealer"

    strings:
        $family_1 = "RedLine" ascii wide nocase
        $family_2 = "RedLine Stealer" ascii wide nocase
        $browser_1 = "Local State" ascii wide nocase
        $browser_2 = "Login Data" ascii wide nocase
        $browser_3 = "Web Data" ascii wide nocase
        $browser_4 = "Cookies" ascii wide nocase
        $wallet_2 = "Telegram Desktop" ascii wide nocase
        $wallet_3 = "CCleaner" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($family_*) and
        (
            2 of ($browser_*) or
            (1 of ($browser_*) and ($wallet_2 or $wallet_3))
        )
}

rule EverbloomSecurity_SmokeLoader_Staged_Loader_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "SmokeLoader-style staged loader with anti-analysis and dynamic payload resolution"
        severity = "high"
        family = "SmokeLoader/Smoke Loader"

    strings:
        $family_1 = "SmokeLoader" ascii wide nocase
        $family_2 = "Smoke Loader" ascii wide nocase
        $stage_2 = "VirtualAlloc" ascii wide nocase
        $stage_3 = "VirtualProtect" ascii wide nocase
        $stage_4 = "GetProcAddress" ascii wide nocase
        $stage_5 = "LoadLibraryA" ascii wide nocase
        $evasion_1 = "IsDebuggerPresent" ascii wide nocase
        $evasion_2 = "CheckRemoteDebuggerPresent" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($family_*) and
        (
            (
                ($stage_2 or $stage_3) and
                ($stage_4 or $stage_5)
            ) or
            2 of ($evasion_*)
        )
}

rule EverbloomSecurity_PlugX_Korplug_Sideload_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "PlugX/Korplug side-loaded payload with dynamic resolution and host-process camouflage markers"
        severity = "high"
        family = "PlugX/Korplug"

    strings:
        $family_1 = "PlugX" ascii wide nocase
        $family_2 = "Korplug" ascii wide nocase
        $loader_1 = "LoadLibrary" ascii wide nocase
        $loader_2 = "GetProcAddress" ascii wide nocase
        $loader_3 = "CreateThread" ascii wide nocase
        $host_1 = "svchost.exe" ascii wide nocase
        $host_2 = "rundll32.exe" ascii wide nocase
        $host_3 = "winlogon.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($family_*) and
        1 of ($loader_*) and
        1 of ($host_*)
}

rule EverbloomSecurity_Gh0stRAT_Remote_Access_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "Gh0st RAT family markers combined with remote-control and process-execution capabilities"
        severity = "high"
        family = "Gh0st RAT"

    strings:
        $family_1 = "Gh0st" ascii wide nocase
        $family_2 = "Gh0st RAT" ascii wide nocase
        $capability_1 = "ShellExecute" ascii wide nocase
        $capability_2 = "CreateProcess" ascii wide nocase
        $capability_3 = "GetDesktopWindow" ascii wide nocase
        $capability_4 = "SetWindowsHookEx" ascii wide nocase
        $network_1 = "InternetOpen" ascii wide nocase
        $network_2 = "WinHttpOpen" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($family_*) and
        1 of ($network_*) and
        1 of ($capability_*)
}

rule EverbloomSecurity_IcedID_BokBot_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "IcedID/BokBot loader variants with staged execution and encrypted or dynamic payload handling"
        severity = "high"
        family = "IcedID/BokBot"

    strings:
        $family_1 = "IcedID" ascii wide nocase
        $family_2 = "BokBot" ascii wide nocase
        $family_3 = "Bokbot" ascii wide nocase
        $stage_1 = "WinHttpOpen" ascii wide nocase
        $stage_2 = "InternetOpen" ascii wide nocase
        $stage_3 = "VirtualAlloc" ascii wide nocase
        $stage_4 = "VirtualProtect" ascii wide nocase
        $stage_5 = "GetProcAddress" ascii wide nocase
        $crypto_1 = "CryptDecrypt" ascii wide nocase
        $crypto_2 = "BCryptDecrypt" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($family_*) and
        ($stage_1 or $stage_2) and
        (
            ($stage_3 or $stage_4 or $stage_5) or
            1 of ($crypto_*)
        )
}

rule EverbloomSecurity_Ursnif_Gozi_ISFB_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "Ursnif/Gozi/ISFB banking-trojan variants with network collection and dynamic payload handling"
        severity = "high"
        family = "Ursnif/Gozi/ISFB"

    strings:
        $family_1 = "Ursnif" ascii wide nocase
        $family_2 = "Gozi" ascii wide nocase
        $family_3 = "ISFB" ascii wide nocase
        $network_1 = "InternetOpen" ascii wide nocase
        $network_2 = "HttpSendRequest" ascii wide nocase
        $network_3 = "WinHttpOpen" ascii wide nocase
        $loader_1 = "VirtualAlloc" ascii wide nocase
        $loader_2 = "GetProcAddress" ascii wide nocase
        $loader_3 = "LoadLibrary" ascii wide nocase
        $crypto_1 = "CryptAcquireContext" ascii wide nocase
        $crypto_2 = "CryptEncrypt" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($family_*) and
        1 of ($network_*) and
        (1 of ($loader_*) or 1 of ($crypto_*))
}

rule EverbloomSecurity_Lumma_Stealer_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "Lumma/LummaC2-style browser and wallet stealer variants"
        severity = "high"
        family = "Lumma Stealer"

    strings:
        $family_1 = "Lumma" ascii wide nocase
        $family_2 = "LummaC2" ascii wide nocase
        $browser_1 = "Login Data" ascii wide nocase
        $browser_2 = "Local State" ascii wide nocase
        $browser_3 = "Cookies" ascii wide nocase
        $wallet_1 = "MetaMask" ascii wide nocase
        $wallet_2 = "Exodus" ascii wide nocase
        $wallet_3 = "Electrum" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($family_*) and
        (
            2 of ($browser_*) or
            (1 of ($browser_*) and
             ($wallet_1 or $wallet_2 or $wallet_3))
        )
}

// These behavior rules intentionally require a PE header and independent
// evidence from collection, execution, or persistence groups.  YARA matches
// are treated as hard malicious results by the scanner, so a single API name
// is never sufficient here.
rule EverbloomSecurity_Browser_Credential_Collection_Chain
{
    meta:
        author = "EverbloomSecurity"
        description = "Browser credential-store access combined with DPAPI or secret extraction and collection/exfiltration support"
        severity = "high"
        technique = "browser credential and cookie theft"
        false_positive_control = "Requires two browser stores, a decryption indicator, and a collection or network indicator"

    strings:
        $store_1 = "Login Data" ascii wide nocase
        $store_2 = "Local State" ascii wide nocase
        $store_3 = "Cookies" ascii wide nocase
        $store_4 = "Web Data" ascii wide nocase
        $decrypt_1 = "CryptUnprotectData" ascii wide nocase
        $decrypt_2 = "NCryptUnprotectSecret" ascii wide nocase
        $decrypt_3 = "CryptStringToBinary" ascii wide nocase
        $collect_1 = "sqlite3_open" ascii wide nocase
        $collect_2 = "CopyFile" ascii wide nocase
        $collect_3 = "FtpWebRequest" ascii wide nocase
        $collect_4 = "HttpSendRequest" ascii wide nocase
        $collect_5 = "WinHttpOpen" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        2 of ($store_*) and
        1 of ($decrypt_*) and
        1 of ($collect_*)
}

rule EverbloomSecurity_Ransomware_Recovery_Disruption_Chain
{
    meta:
        author = "EverbloomSecurity"
        description = "Recovery-destruction command combined with file enumeration and encryption capability"
        severity = "high"
        technique = "ransomware early-warning chain"
        false_positive_control = "Requires one recovery-disruption command plus independent enumeration and encryption evidence"

    strings:
        $recovery_1 = "vssadmin delete shadows" ascii wide nocase
        $recovery_2 = "wmic shadowcopy delete" ascii wide nocase
        $recovery_3 = "wbadmin delete catalog" ascii wide nocase
        $recovery_4 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $recovery_5 = "wevtutil cl" ascii wide nocase
        $crypto_1 = "BCryptEncrypt" ascii wide nocase
        $crypto_2 = "CryptEncrypt" ascii wide nocase
        $crypto_3 = "EncryptFile" ascii wide nocase
        $crypto_4 = "SetFileInformationByHandle" ascii wide nocase
        $walk_1 = "FindFirstFile" ascii wide nocase
        $walk_2 = "FindNextFile" ascii wide nocase
        $walk_3 = "GetFileInformationByHandle" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($recovery_*) and
        1 of ($crypto_*) and
        1 of ($walk_*)
}

rule EverbloomSecurity_BYOVD_Vulnerable_Driver_Release_Chain
{
    meta:
        author = "EverbloomSecurity"
        description = "Known vulnerable-driver artifact combined with service loading and device control"
        severity = "high"
        technique = "bring your own vulnerable driver"
        false_positive_control = "Requires an explicit vulnerable driver name, a driver/service-loading API, and device interaction"

    strings:
        $driver_1 = "amsdk.sys" ascii wide nocase
        $driver_2 = "BdApiUtil64.sys" ascii wide nocase
        $driver_3 = "zam64.sys" ascii wide nocase
        $driver_4 = "RTCore64.sys" ascii wide nocase
        $driver_5 = "iqvw64e.sys" ascii wide nocase
        $driver_6 = "gdrv.sys" ascii wide nocase
        $driver_7 = "WinRing0x64.sys" ascii wide nocase
        $load_1 = "CreateService" ascii wide nocase
        $load_2 = "OpenSCManager" ascii wide nocase
        $load_3 = "NtLoadDriver" ascii wide nocase
        $load_4 = "ZwLoadDriver" ascii wide nocase
        $device_1 = "DeviceIoControl" ascii wide nocase
        $device_2 = "\\\\.\\" ascii wide nocase
        $device_3 = "\\Device\\" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        1 of ($driver_*) and
        1 of ($load_*) and
        1 of ($device_*)
}

rule EverbloomSecurity_CTF_TypeLib_Hijack_Loader_Chain
{
    meta:
        author = "EverbloomSecurity"
        description = "CTF or TypeLib registry hijack indicators combined with DLL loading from a writable location"
        severity = "high"
        technique = "registry hijacking and DLL side-loading"
        false_positive_control = "Requires a hijack key, registry write, loader context, target process, and writable-path evidence"

    strings:
        $ctf_key = "Software\\Microsoft\\CTF" ascii wide nocase
        $ctf_value = "CtfLp" ascii wide nocase
        $typelib_key = "TypeLib\\{" ascii wide nocase
        $registry_1 = "RegSetValue" ascii wide nocase
        $registry_2 = "RegCreateKey" ascii wide nocase
        $registry_3 = "NtSetValueKey" ascii wide nocase
        $loader_1 = "LoadLibrary" ascii wide nocase
        $loader_2 = "LdrLoadDll" ascii wide nocase
        $loader_3 = "DllMain" ascii wide nocase
        $target_1 = "ctfmon.exe" ascii wide nocase
        $target_2 = "explorer.exe" ascii wide nocase
        $writable_1 = "\\AppData\\" ascii wide nocase
        $writable_2 = "\\Local\\Temp\\" ascii wide nocase
        $writable_3 = "\\Users\\Public\\" ascii wide nocase
        $writable_4 = "\\ProgramData\\" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        (($ctf_key and $ctf_value) or $typelib_key) and
        1 of ($registry_*) and
        1 of ($loader_*) and
        1 of ($target_*) and
        1 of ($writable_*)
}

rule EverbloomSecurity_LockBit_Ransomware_Note_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "LockBit-family ransom-note and encrypted-file extension markers"
        severity = "high"
        family = "LockBit"

    strings:
        $family_1 = "LockBit" ascii wide nocase
        $family_2 = ".lockbit" ascii wide nocase
        $family_3 = "LockBit 3.0" ascii wide nocase
        $note_1 = "Restore-My-Files" ascii wide nocase
        $note_2 = "decrypt" ascii wide nocase
        $note_3 = "ransom" ascii wide nocase
        $note_4 = "Tor Browser" ascii wide nocase

    condition:
        1 of ($family_*) and
        (
            ($family_2 or $family_3) or
            2 of ($note_*)
        )
}

rule EverbloomSecurity_BlackCat_ALPHV_Ransomware_Variants
{
    meta:
        author = "EverbloomSecurity"
        description = "BlackCat/ALPHV ransomware markers with recovery or encrypted-file instructions"
        severity = "high"
        family = "BlackCat/ALPHV"

    strings:
        $family_1 = "BlackCat" ascii wide nocase
        $family_2 = "ALPHV" ascii wide nocase
        $family_3 = ".alphv" ascii wide nocase
        $note_1 = "decrypt" ascii wide nocase
        $note_2 = "recover" ascii wide nocase
        $note_3 = "ransom" ascii wide nocase
        $note_4 = "onion" ascii wide nocase

    condition:
        1 of ($family_*) and
        (
            $family_3 or
            2 of ($note_*)
        )
}

rule EverbloomSecurity_PowerShell_Persistence_Chain
{
    meta:
        author = "EverbloomSecurity"
        description = "PowerShell remnant combined with scheduled-task persistence and hidden or encoded execution"
        severity = "high"
        technique = "scheduled-task persistence with obfuscated script execution"
        false_positive_control = "Requires a PowerShell remnant, two scheduled-task artifacts, and a hidden-window or encoded-execution marker"

    strings:
        $ps_1 = "powershell" ascii wide nocase
        $ps_2 = "pwsh" ascii wide nocase
        $ps_3 = "windows\\system32\\windowspowershell" ascii wide nocase
        $task_1 = "schtasks" ascii wide nocase
        $task_2 = "/create" ascii wide nocase
        $task_3 = "/sc onlogon" ascii wide nocase
        $task_4 = "/sc onstart" ascii wide nocase
        $task_5 = "/sc minute" ascii wide nocase
        $task_6 = "/ru system" ascii wide nocase
        $hidden_1 = "-w hidden" ascii wide nocase
        $hidden_2 = "-windowstyle hidden" ascii wide nocase
        $hidden_3 = "-window hidden" ascii wide nocase
        $encoded_1 = "-encodedcommand" ascii wide nocase
        $encoded_2 = "frombase64string" ascii wide nocase

    condition:
        1 of ($ps_*) and
        2 of ($task_*) and
        (1 of ($hidden_*) or $encoded_1 or $encoded_2)
}

rule EverbloomSecurity_Discord_Webhook_Exfil_Chain
{
    meta:
        author = "EverbloomSecurity"
        description = "Discord webhook endpoint combined with credential, surveillance, or upload capability artifacts"
        severity = "high"
        technique = "outside-console exfiltration via Discord webhook"
        false_positive_control = "Requires a genuine webhook endpoint plus an independent store and collection artifact"

    strings:
        $webhook_1 = "discord.com/api/webhooks" ascii wide nocase
        $webhook_2 = "discordapp.com/api/webhooks" ascii wide nocase
        $store_1 = "Login Data" ascii wide nocase
        $store_2 = "Local State" ascii wide nocase
        $store_3 = "Web Data" ascii wide nocase
        $store_4 = "Cookies" ascii wide nocase
        $store_5 = "wallet.dat" ascii wide nocase
        $store_6 = "logins.json" ascii wide nocase
        $capture_1 = "GetAsyncKeyState" ascii wide nocase
        $capture_2 = "GetClipboardData" ascii wide nocase
        $capture_3 = "BitBlt" ascii wide nocase
        $capture_4 = "CreateCompatibleBitmap" ascii wide nocase
        $exfil_1 = "WebClient" ascii wide nocase
        $exfil_2 = "SmtpClient" ascii wide nocase
        $exfil_3 = "FtpWebRequest" ascii wide nocase

    condition:
        1 of ($webhook_*) and
        1 of ($store_*) and
        1 of ($capture_*, $exfil_*)
}

rule EverbloomSecurity_Netsh_PortProxy_Tunnel_Relay_Chain
{
    meta:
        author = "EverbloomSecurity"
        description = "netsh portproxy tunnel combined with a relay tool name and command-shell execution context"
        severity = "high"
        technique = "network tunneling and proxy relay"
        false_positive_control = "Requires the distinctive portproxy command, a relay tool name, and a shell or batch execution artifact"

    strings:
        $portproxy_1 = "netsh interface portproxy add" ascii wide nocase
        $portproxy_2 = "portproxy add v4tov4" ascii wide nocase
        $portproxy_3 = "portproxy delete v4tov4" ascii wide nocase
        $relay_1 = "plink.exe" ascii wide nocase
        $relay_2 = "stunnel" ascii wide nocase
        $relay_3 = "htran" ascii wide nocase
        $relay_4 = "lcx.exe" ascii wide nocase
        $relay_5 = "socat" ascii wide nocase
        $shell_1 = "cmd.exe" ascii wide nocase
        $shell_2 = "powershell" ascii wide nocase
        $shell_3 = "reg add" ascii wide nocase
        $shell_4 = "sc create" ascii wide nocase

    condition:
        1 of ($portproxy_*) and
        1 of ($relay_*) and
        1 of ($shell_*)
}
