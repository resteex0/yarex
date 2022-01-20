
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_CodeRed_Worm_C 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_CodeRed_Worm_C {
	meta: 
		 description= "W32_CodeRed_Worm_C Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "5edc2375e7aca69f8c1a8d77c4ffff18"
		 hash2= "e99eadcc1bb3891fb513fb32b9ba2df1"

	strings:

	
 		 $a1= "SOFTWAREMicrosoftWindows NTCurrentVersionWinlogon" fullword ascii

		 $hex1= {2461313d2022534f46}

	condition:
		0 of them
}
