
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Hupigon 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Hupigon {
	meta: 
		 description= "Win32_Hupigon Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-30" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8f90057ab244bd8b612cd09f566eac0c"

	strings:

	
 		 $a1= "SoftwareMicrosoftWindowsCurrentVersionPoliciesWinOlfApp" fullword ascii
		 $a2= "SystemCurrentControlSetControlKeyboard Layouts%.8x" fullword ascii

		 $hex1= {2461313d2022536f66}
		 $hex2= {2461323d2022537973}

	condition:
		1 of them
}
