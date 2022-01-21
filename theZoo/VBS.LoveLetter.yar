
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_VBS_LoveLetter 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_VBS_LoveLetter {
	meta: 
		 description= "theZoo_VBS_LoveLetter Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-35-58" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "072b90a954bb9349a8871fa749165596"
		 hash2= "7812042921729e8f20dc3950ea52534a"
		 hash3= "836a5abd025d60a7aa8550679dd556c9"
		 hash4= "e8f103dc1620e8b310c244d38ad24dd7"

	strings:

	
 		 $a1= "HKLMSoftwareMicrosoftWindowsCurrentVersionRunMSKernel32" fullword ascii
		 $a2= "HKLMSoftwareMicrosoftWindowsCurrentVersionRunWIN-BUGSFIX" fullword ascii
		 $a3= "http://www.cert.org/tech_tips/malicious_code_FAQ.html#steps " fullword ascii

		 $hex1= {2461313d2022484b4c}
		 $hex2= {2461323d2022484b4c}
		 $hex3= {2461333d2022687474}

	condition:
		2 of them
}
