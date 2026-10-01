rule nix_rust_hunt {
	meta:
		date = "2026-06-05"
		yarahub_uuid = "cbc5fbde-f0a2-4476-ae6b-9cc155e33c11"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "44d88612fea8a8f36de82e1278abb02f"

	strings:
		$s1 = "rustc version" ascii

	condition:
		uint16(0) == 0x5a4d
		and filesize >= 1MB
		and all of them
}
