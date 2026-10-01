/* Example YARA rules for EverbloomSecurity - copied to Engine/Heuristic */

rule Suspicious_PE_Stub
{
    meta:
        author = "everbloom"
        description = "Matches simple PE stub strings used in some packers"
        severity = "medium"

    strings:
        $mz = { 4D 5A } /* MZ header */
        $stub = "This program cannot be run in DOS mode" ascii

    condition:
        $mz and $stub
}

rule Suspicious_HelloWorld
{
    meta:
        author = "everbloom"
        description = "Example: matches Hello, World string in binaries/text"
        severity = "low"

    strings:
        $hw = "Hello, World" ascii wide

    condition:
        any of them
}
