
/*
   YARA Rule Set
   Author: resteex
   Identifier: NvRendererMiner 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_NvRendererMiner {
	meta: 
		 description= "NvRendererMiner Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-16-12" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "13f73b7f5a8123b724f0fb5b36556100"

	strings:

	
 		 $s1= "!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13" fullword wide
		 $a1= "!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13" fullword ascii

		 $hex1= {2461313d2022212325}
		 $hex2= {2473313d2022212325}

	condition:
		1 of them
}
