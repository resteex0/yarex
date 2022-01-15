
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
		 date = "2022-01-14_21-37-27" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "24a6ec8ebf9c0867ed1c097f4a653b8d"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "Microsoft Corporation" fullword wide
		 $s3= "OriginalFilename" fullword wide
		 $s4= "registrymachinesoftwareMicrosoftWindows NTCurrentVersion" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide
		 $a1= "registrymachinesoftwareMicrosoftWindows NTCurrentVersion" fullword ascii

		 $hex1= {2461313d2022726567}
		 $hex2= {2473313d202246696c}
		 $hex3= {2473323d20224d6963}
		 $hex4= {2473333d20224f7269}
		 $hex5= {2473343d2022726567}
		 $hex6= {2473353d202256535f}

	condition:
		2 of them
}
