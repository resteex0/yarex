
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_BitRAT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_BitRAT {
	meta: 
		 description= "vx_underground2_BitRAT Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-53-34" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1aa4ec7db318a524fdfb5aaff61a1031"

	strings:

	
 		 $s1= "Vkeagj.Fwiakvndmqwxftcyids.dll" fullword wide
		 $s2= "Vkeagj.Properties.Resources" fullword wide

		 $hex1= {2473313d2022566b65}
		 $hex2= {2473323d2022566b65}

	condition:
		1 of them
}
