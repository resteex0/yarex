
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Reveton 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Reveton {
	meta: 
		 description= "Win32_Reveton Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-39-09" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2cdb29c8aa709cdb75f42248c84fe5d7"
		 hash2= "8334d2692aa97076a5bd95a9d9fdfcd5"

	strings:

	
 		 $s1= "65Gi9VWDrzZPCTw" fullword wide
		 $s2= "pec2tAK0tzEqLZkk" fullword wide
		 $s3= "xhbu0bF8Rk0YKSNe" fullword wide

		 $hex1= {2473313d2022363547}
		 $hex2= {2473323d2022706563}
		 $hex3= {2473333d2022786862}

	condition:
		1 of them
}
