
/*
   YARA Rule Set
   Author: resteex
   Identifier: Djvu 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Djvu {
	meta: 
		 description= "Djvu Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-02-26" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "02118409643dbdad9710c6571b02130e"
		 hash2= "690f34d0cc11112bab173c2c864f911f"

	strings:

	
 		 $s1= "gukemikekugoxopohisaluyapimow" fullword wide
		 $s2= "karizevodasayohihohecezulamas" fullword wide
		 $s3= "verosiwagasedavijozegulozakeawkutafojajocoxelufayifelif" fullword wide
		 $a1= "verosiwagasedavijozegulozakeawkutafojajocoxelufayifelif" fullword ascii

		 $hex1= {2461313d2022766572}
		 $hex2= {2473313d202267756b}
		 $hex3= {2473323d20226b6172}
		 $hex4= {2473333d2022766572}

	condition:
		2 of them
}
