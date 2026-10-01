rule Kynx_Stealer {
    meta: 
        description = "Detects Kynx Stealer by static strings" 
        author = "SOCRadar Threat Research Unit (STRU)"
        date = "2026-07-17"
        yarahub_uuid = "3d11fc9c-5c94-48c1-b7db-a628991a9b6c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "810d854e82ce5b0b560af72ff9c88c57"

    strings: 
        // Network
        $net1   = "X-Kynx-Token:" ascii 
        $net2   = "?cat=files" ascii
        
        // Files
        $file1  = "kynx_vmcheck.txt" ascii 
        $file2  = "kynx_files.zip" ascii
        $file3  = "kynx_early.txt" ascii
        $file4  = "som_helper.exe" ascii 
        $file5  = "crdecrypt.exe" ascii
        $file6  = "debug.txt" ascii

        // Behavior
        $beh1   = "--- KYNX DEBUG LOG ---" ascii             
        $beh2   = "=== KYNX STARTED (OWNER_UID=" ascii       
        $beh3   = "KynxCR_" ascii                            
        $beh4   = "KynxSO_" ascii                              
        $beh5   = "DevGrabber" ascii 
        $beh6   = "Priority: MCE -> DBS -> ChromeElevator -> raw copy" ascii 
        $beh7   = "[=] FINAL SCORE: %d (Target: " ascii    
        $beh8   = "[!] Being Debugged (PEB): %s (+" ascii 
        $beh9   = "_IAS_ACCOUNTS_DO_NOT_SEND_TO_ANYONE" ascii 
        $beh10  = "MCE/DBS/CE all failed" ascii
        $beh11  = "WinSysHealth" ascii

    condition: 
        uint16(0) == 0x5A4D and 
        (
            1 of ($net*) and 2 of ($file*) and 3 of ($beh*)
        )
}