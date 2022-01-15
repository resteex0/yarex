
/*
   YARA Rule Set
   Author: resteex
   Identifier: ZeusGameover_Feb2014 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_ZeusGameover_Feb2014 {
	meta: 
		 description= "ZeusGameover_Feb2014 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-52-58" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "19c68862d3a53ea1746180b40bf32226"
		 hash2= "7bc463a32d6c0fb888cd76cc07ee69b5"
		 hash3= "7fe11cfcd7c66f7727cfc4613e755389"
		 hash4= "b227e7c0d9995715f331592750d6ebc2"

	strings:

	
 		 $s1= "AVarFileInfoTranslation" fullword wide
		 $s2= "SOFTWAREMicrosoftWindows NTCurrentVersionProfileList%s" fullword wide
		 $s3= "StringFileInfo%04x%04x%s" fullword wide
		 $a1= "SOFTWAREMicrosoftWindows NTCurrentVersionProfileList%s" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {2473313d2022415661}
		 $hex3= {2473323d2022534f46}
		 $hex4= {2473333d2022537472}

	condition:
		2 of them
}
