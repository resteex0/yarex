
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Invicea_Tunnel 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Invicea_Tunnel {
	meta: 
		 description= "Win32_Invicea_Tunnel Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-31" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ad44a7c5e18e9958dda66ccfc406cd44"

	strings:

	
 		 $s1= "@MSG_ERROR_DIALOG_CAPTION@" fullword wide

		 $hex1= {2473313d2022404d53}

	condition:
		0 of them
}
