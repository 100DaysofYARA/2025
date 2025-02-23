rule MAL_COYOTE_BANKING_TROJAN{
        meta:
                author = "Ryan Foote <intelcorgi>"
                description = "Rule for detecting b64 decoding routine seen in final stages of Coyote Banking Trojan."
                version = "v1.1"
                Day = "53"
                Hash = "1d06acf137ab1e23b21d777de1f023feac4ae9201d3e95141b9ebc6224640679"
                Ref1 = "https://www.fortinet.com/blog/threat-research/coyote-banking-trojan-a-stealthy-attack-via-lnk-files"
                Ref2 = "https://x.com/1ZRR4H/status/1885459907547111617"
	strings:
                /*
                0x0001135B 280300000A IL_0023: call      class [mscorlib]System.Text.Encoding [mscorlib]System.Text.Encoding::get_UTF8()
		0x00011360 280300000A IL_0028: call      class [mscorlib]System.Text.Encoding [mscorlib]System.Text.Encoding::get_UTF8()
		0x00011365 72B5CA0970 IL_002D: ldstr     "RzlXRUNaSndMRk5pNEc5V0VDWkp3TEZHOVdFQ1pKd0xGeExqRzlXRUNaSndMRkc5V0VDWkp3TEZBPUc5V0VDWkp3TEY="
		0x0001136A 280400000A IL_0032: call      uint8[] [mscorlib]System.Convert::FromBase64String(string)
		0x0001136F 6F0500000A IL_0037: callvirt  instance string [mscorlib]System.Text.Encoding::GetString(uint8[])
		0x00011374 7270CB0970 IL_003C: ldstr     "G9WECZJwLF"
		0x00011379 72D2000070 IL_0041: ldstr     ""
                */

                $b64_decoding = { 28 ?? 00 00 0A 28 ?? 00 00 0A 72 ?? ?? ?? ?? 28 ?? 00 00 0A 6F ?? 00 00 0A 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? }
	condition:
                $b64_decoding
}