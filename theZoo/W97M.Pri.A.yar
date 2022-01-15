
/*
   YARA Rule Set
   Author: resteex
   Identifier: W97M_Pri_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W97M_Pri_A {
	meta: 
		 description= "W97M_Pri_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-52-05" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "20577952428b972fc5103d329b77f4b7"
		 hash2= "44d7ef71a0c02a415f6ddf11ea976de0"
		 hash3= "edbe88b73d582b38690570f032a3e249"

	strings:

	
 		 $s1= "{C2F40CF1-9808-11D2-8861-004033E0078E}" fullword wide
		 $s2= "DocumentSummaryInformation" fullword wide

		 $hex1= {2473313d20227b4332}
		 $hex2= {2473323d2022446f63}

	condition:
		1 of them
}
