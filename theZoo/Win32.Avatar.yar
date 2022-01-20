
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Avatar 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Avatar {
	meta: 
		 description= "Win32_Avatar Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-12" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "32d6644c5ea66e390070d3dc3401e54b"

	strings:

	
 		 $s1= "%suxtheme.dll;%scryptbase.dll" fullword wide

		 $hex1= {2473313d2022257375}

	condition:
		0 of them
}
