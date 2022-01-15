
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_GROK 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_GROK {
	meta: 
		 description= "EquationGroup_GROK Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-51-03" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "24a6ec8ebf9c0867ed1c097f4a653b8d"

	strings:

	
 		 $s1= "registrymachinesoftwareMicrosoftWindows NTCurrentVersion" fullword wide
		 $a1= "registrymachinesoftwareMicrosoftWindows NTCurrentVersion" fullword ascii

		 $hex1= {2461313d2022726567}
		 $hex2= {2473313d2022726567}

	condition:
		1 of them
}
