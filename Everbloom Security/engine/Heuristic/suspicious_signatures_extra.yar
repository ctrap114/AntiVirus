/* Additional YARA rules for EverbloomSecurity heuristic engine */

rule Suspicious_Packer_Stub
{
    meta:
        author = "everbloom"
        description = "Matches common packer/packer stub strings in PE files"
        severity = "medium"

    strings:
        $mz = { 4D 5A }
        $upx = "UPX!" ascii
        $packed = "Packed by" ascii nocase
        $rvas = "Rich" ascii

    condition:
        $mz and 1 of ($upx, $packed, $rvas)
}

rule Suspicious_API_Resolver
{
    meta:
        author = "everbloom"
        description = "Detects code that resolves APIs dynamically via LoadLibrary/GetProcAddress"
        severity = "medium"

    strings:
        $loadlib = "LoadLibraryA" ascii
        $getproc = "GetProcAddress" ascii
        $virtalloc = "VirtualAlloc" ascii
        $virtprot = "VirtualProtect" ascii
        $rmtthread = "CreateRemoteThread" ascii

    condition:
        2 of ($loadlib, $getproc, $virtalloc, $virtprot, $rmtthread)
}

rule Suspicious_Autorun_Service
{
    meta:
        author = "everbloom"
        description = "Matches autorun and service persistence strings in binaries"
        severity = "medium"

    strings:
        $runkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $create_service = "CreateServiceA" ascii
        $start_service = "StartServiceA" ascii
        $reg_set = "RegSetValueExA" ascii

    condition:
        1 of ($runkey, $create_service, $start_service, $reg_set)
}

rule Suspicious_Ransomware_Notice
{
    meta:
        author = "everbloom"
        description = "Detects common ransomware note and encrypted file markers"
        severity = "high"

    strings:
        $encrypt = "files are encrypted" ascii nocase
        $decrypt = "Decrypt instructions" ascii nocase
        $extension = ".encrypted" ascii nocase
        $ransomed = "Your files have been encrypted" ascii nocase

    condition:
        1 of ($encrypt, $decrypt, $extension, $ransomed)
}

rule Suspicious_Persistence_Installer
{
    meta:
        author = "everbloom"
        description = "Matches installer and persistence-related strings often used by malicious installers"
        severity = "low"

    strings:
        $msiexec = "msiexec.exe" ascii nocase
        $shell_exec = "ShellExecuteA" ascii
        $advapi = "Advapi32.dll" ascii
        $svcctrl = "OpenServiceA" ascii

    condition:
        2 of ($msiexec, $shell_exec, $advapi, $svcctrl)
}
