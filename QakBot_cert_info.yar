import "pe"
rule QakBot_cert_info : QakBot{
	meta:
		description = "Detects QakBot from invalid signature"
		date = "2020-07-22"
		author = "Kostas Tsialemis - Twitter: @Kostastsale"
		hash = "bcbcfeec015ae846c03f1d3edb1b7a95"
	strings:
		$s = "EZIOLHHGQANMUKKAHE"
	condition:
		uint16(0) == 0x5a4d and filesize >= 706KB and filesize <= 900KB and
     	         $s and pe.version_info["CompanyName"] == "IObit" and
   		 pe.signatures[0].issuer contains "EZIOLHHGQANMUKKAHE"
}
