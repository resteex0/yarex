
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Destover_SonySigned 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Destover_SonySigned {
	meta: 
		 description= "Trojan_Destover_SonySigned Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-43-48" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "e904bf93403c0fb08b9683a9e858c73e"

	strings:

	
 		 $a1= "1http://crl.usertrust.com/UTN-USERFirst-Object.crl05" fullword ascii

		 $hex1= {2461313d2022316874}

	condition:
		0 of them
}
