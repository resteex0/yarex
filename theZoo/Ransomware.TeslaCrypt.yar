
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_TeslaCrypt 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_TeslaCrypt {
	meta: 
		 description= "Ransomware_TeslaCrypt Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-51-24" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "209a288c68207d57e0ce6e60ebf60729"
		 hash2= "6d3d62a4cff19b4f2cc7ce9027c33be8"
		 hash3= "6e080aa085293bb9fbdcc9015337d309"

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
