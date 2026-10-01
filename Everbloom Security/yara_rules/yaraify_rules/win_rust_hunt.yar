rule win_rust_hunt {
	meta:
		date = "2026-06-05"
		yarahub_uuid = "d7e7ac8b-b3d5-4fd9-9b20-9219fd911928"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "44d88612fea8a8f36de82e1278abb02f"

	strings:
		$s1 = "rustc version" ascii

	condition:
		uint32(0) == 0x464c457f
		and filesize >= 1MB
		and all of them
}
