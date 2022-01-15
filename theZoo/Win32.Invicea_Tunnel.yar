
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
		 date = "2022-01-14_21-38-56" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ad44a7c5e18e9958dda66ccfc406cd44"

	strings:

	
 		 $s1= "-create-e4j-log" fullword wide
		 $s2= "/create-e4j-log" fullword wide
		 $s3= "&-create-i4j-log" fullword wide
		 $s4= "/create-i4j-log" fullword wide
		 $s5= "@MSG_ERROR_DIALOG_CAPTION@" fullword wide
		 $s6= "@MSG_ERROR_DIALOG_OK@" fullword wide
		 $s7= "@MSG_ERROR_DIALOG_TEXT@" fullword wide

		 $hex1= {2473313d20222d6372}
		 $hex2= {2473323d20222f6372}
		 $hex3= {2473333d2022262d63}
		 $hex4= {2473343d20222f6372}
		 $hex5= {2473353d2022404d53}
		 $hex6= {2473363d2022404d53}
		 $hex7= {2473373d2022404d53}

	condition:
		2 of them
}
