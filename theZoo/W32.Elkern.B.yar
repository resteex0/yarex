
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_Elkern_B 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_Elkern_B {
	meta: 
		 description= "W32_Elkern_B Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0a8a4950d9d71b448fde1f741608921e"
		 hash2= "15eb3a656f9e83138cdb4c3a16b6ab60"

	strings:

	
 		 $s1= "Scaling X-Scaling Y-Scaling" fullword wide

		 $hex1= {2473313d2022536361}

	condition:
		0 of them
}
