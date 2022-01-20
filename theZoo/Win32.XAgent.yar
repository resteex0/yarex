
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_XAgent 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_XAgent {
	meta: 
		 description= "Win32_XAgent Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-45-14" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2f6d1bed602a3ad749301e7aa3800139"

	strings:

	
 		 $s1= "RegisterServiceCtrlHandler" fullword wide
		 $s2= "StartServiceCtrlDispatcher" fullword wide

		 $hex1= {2473313d2022526567}
		 $hex2= {2473323d2022537461}

	condition:
		1 of them
}
