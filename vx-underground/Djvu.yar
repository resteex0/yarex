
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Djvu 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Djvu {
	meta: 
		 description= "vx_underground2_Djvu Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-54-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "02118409643dbdad9710c6571b02130e"
		 hash2= "690f34d0cc11112bab173c2c864f911f"

	strings:

	
 		 $s1= "gukemikekugoxopohisaluyapimow" fullword wide
		 $s2= "karizevodasayohihohecezulamas" fullword wide
		 $s3= "verosiwagasedavijozegulozakeawkutafojajocoxelufayifelif" fullword wide
		 $a1= "C:cecenyaxovaxakocit_wevefigomadathemapinewirasunef v.pdb" fullword ascii

		 $hex1= {2461313d2022433a63}
		 $hex2= {2473313d202267756b}
		 $hex3= {2473323d20226b6172}
		 $hex4= {2473333d2022766572}

	condition:
		2 of them
}
