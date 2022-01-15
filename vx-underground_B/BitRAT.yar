
/*
   YARA Rule Set
   Author: resteex
   Identifier: BitRAT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_BitRAT {
	meta: 
		 description= "BitRAT Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_23-03-31" 
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
