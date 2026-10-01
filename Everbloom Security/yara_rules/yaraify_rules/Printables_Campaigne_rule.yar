/*
3D Campaigne
*/

rule Printables_Campaigne_rule
{
    meta:
        meta:
        id = "TA001"
        version = "1.0"
        date = "2026-07-07"
        modified = "2026-07-08"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        author = "frexna"
        description = "Detects Python RAT, Pyramid, Fernet, zlib/base64 and pythonmemorymodule artifacts"
        category = "MALWARE"
        malware = "PYTHON_RAT"
        mitre_att = "T1027,T1059,T1105"
        yarahub_uuid = "4a4f4c2e-3a1c-4f21-9c61-7bb5f1d00a11"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "d41d8cd98f00b204e9800998ecf8427e"

    strings:
        $s1 = "194.76.217.84"                    //this is a string
        $s2 = "193.233.138.21"           //this is a hex string representing binary data
        $s3 = "albio" ascii
        $s4 = "JeffreyEpstein" ascii
        $s5 = "InternetV.1.0" ascii
        $s6 = "NORTH KOREA TANK GROUPING" ascii
        $s7 = "We are the cyber criminal group PINEAPPLE" ascii
        $com1 = "NORTH KOREA TANK GROUPING" ascii
        $com2 = "Call us Anus" ascii
		$com3 = "We are the syber criminal group PINEAPPLE" ascii

    condition:
        any of them
}