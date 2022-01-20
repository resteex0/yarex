
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
		 date = "2022-01-20_04-42-24" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "24a6ec8ebf9c0867ed1c097f4a653b8d"

	strings:

	
 		 $s1= "registrymachinesoftwareMicrosoftWindows NTCurrentVersion" fullword wide

		 $hex1= {2473313d2022726567}

	condition:
		0 of them
}
