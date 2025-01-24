rule MAL_GOLANG_STEALER_QBIT{
	meta:
		author = "Ryan Foote <intelcorgi>"
		description = "Rule designed to detect Qbit Stealer."
        version = "v1.0"
        Day = "20"
        Hash1 = "874ac477ea85e1a813ed167f326713c26018d9b2d649099148de7f9e7a163b23"
        Hash2 = "2787246491b1ef657737e217142ca216c876c7178febcfe05f0379b730aae0cc"
	strings:
        $branding0 = "qBit Stealer" ascii // Full string is qBit Stealer RaaS
        $branding1 = "TRIAL VERSION - 24 Hour Access" ascii
        
        $setup0 = "Stolen Folder Name:" ascii
		$setup1 = "Max File Size(MB):" ascii
        $setup2 = "Targeted File Extensions:" ascii
        $setup3 = "[+] Logged into Mega" ascii
        $setup4 = "[+] Loaded configJs" ascii

        $error0 = "Failed to load configJs" ascii
        $error1 = "Failed to archive files" ascii
        $error2 = "Failed to upload files" ascii
        $error3 = "Failed to get file info" ascii
	condition:
        filesize > 7MB and
        filesize < 9MB and
		5 of them
}

rule HUNT_QBIT_STEALER_DEV{
    meta:
		author = "Ryan Foote <intelcorgi>"
		description = "Rule designed to detect other possible software created by Qbit's author (n1k714i)."
		version = "v1.0"
		Day = "20"
	strings:
		$dev_email = "qbit@hitler.rocks"
		$dev_telegram = "n1k7l4i"
        $dev_pixeldrain = "N1k7" // may prove to be inefficient, given the dev telegram contains this name as well.
        $related_vimeo = "CrabCat"
	condition:
		any of them
}