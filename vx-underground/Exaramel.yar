
/*
   YARA Rule Set
   Author: resteex
   Identifier: Exaramel 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Exaramel {
	meta: 
		 description= "Exaramel Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-04-04" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8eff45383a7a0c6e3ea6d526a599610d"

	strings:

	
 		 $s1= "!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13" fullword wide
		 $a1= "!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13" fullword ascii

		 $hex1= {2461313d2022212325}
		 $hex2= {2473313d2022212325}

	condition:
		1 of them
}
