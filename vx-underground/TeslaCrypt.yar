
/*
   YARA Rule Set
   Author: resteex
   Identifier: TeslaCrypt 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_TeslaCrypt {
	meta: 
		 description= "TeslaCrypt Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-19-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "209a288c68207d57e0ce6e60ebf60729"
		 hash2= "52012cf8810a507634e15ec5912e2527"
		 hash3= "db065f2506b3b56dedeb3035bd61d0ee"
		 hash4= "f3b12a197d732cda29d6d9e698ea58bf"

	strings:

	
 		 $s1= "HELP_TO_DECRYPT_YOUR_FILES.bmp" fullword wide
		 $s2= "HELP_TO_DECRYPT_YOUR_FILES.txt" fullword wide
		 $s3= "https://www.torproject.org/projects/torbrowser.html.en" fullword wide
		 $s4= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s5= "www.torproject.org/projects/torbrowser.html.en" fullword wide
		 $a1= "https://www.torproject.org/projects/torbrowser.html.en" fullword ascii

		 $hex1= {2461313d2022687474}
		 $hex2= {2473313d202248454c}
		 $hex3= {2473323d202248454c}
		 $hex4= {2473333d2022687474}
		 $hex5= {2473343d2022536f66}
		 $hex6= {2473353d2022777777}

	condition:
		4 of them
}
