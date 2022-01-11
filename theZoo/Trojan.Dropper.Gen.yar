
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Dropper_Gen 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Dropper_Gen {
	meta: 
		 description= "Trojan_Dropper_Gen Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-30-39" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "f88e9b7446a6e57943728cce3cc70720"

	strings:

	
 		 $a1= "ExpandEnvironmentStringsA" fullword ascii
		 $a2= "#http://crl.thawte.com/ThawtePCA.crl0" fullword ascii
		 $a3= "/http://crl.thawte.com/ThawtePremiumServerCA.crl0" fullword ascii
		 $a4= ".http://crl.thawte.com/ThawteTimestampingCA.crl0" fullword ascii
		 $a5= "*http://cs-g2-crl.thawte.com/ThawteCSG2.crl0" fullword ascii
		 $a6= "http://nsis.sf.net/NSIS_Error" fullword ascii
		 $a7= "https://www.thawte.com/cps0" fullword ascii
		 $a8= "+http://ts-crl.ws.symantec.com/tss-ca-g2.crl0(" fullword ascii
		 $a9= "http://ts-ocsp.ws.symantec.com07" fullword ascii
		 $a10= "premium-server@thawte.com0" fullword ascii
		 $a11= "SHGetSpecialFolderLocation" fullword ascii
		 $a12= "SoftwareMicrosoftWindowsCurrentVersion" fullword ascii
		 $a13= "WritePrivateProfileStringA" fullword ascii

		 $hex1= {246131303d20227072}
		 $hex2= {246131313d20225348}
		 $hex3= {246131323d2022536f}
		 $hex4= {246131333d20225772}
		 $hex5= {2461313d2022457870}
		 $hex6= {2461323d2022236874}
		 $hex7= {2461333d20222f6874}
		 $hex8= {2461343d20222e6874}
		 $hex9= {2461353d20222a6874}
		 $hex10= {2461363d2022687474}
		 $hex11= {2461373d2022687474}
		 $hex12= {2461383d20222b6874}
		 $hex13= {2461393d2022687474}

	condition:
		1 of them
}
