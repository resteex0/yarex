
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_Swen 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_Swen {
	meta: 
		 description= "W32_Swen Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "9d4f624495fb078d4aad32901a1bdf52"
		 hash2= "9e4fd94e55753ea03584f2473f4a0d5e"

	strings:

	
 		 $a1= "SOFTWAREMicrosoftWindowsCurrentVersionApp Paths" fullword ascii
		 $a2= "SOFTWAREMicrosoftWindowsCurrentVersionExplorer" fullword ascii
		 $a3= "SoftwareMicrosoftWindowsCurrentVersionPoliciesSystem" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {2461323d2022534f46}
		 $hex3= {2461333d2022536f66}

	condition:
		2 of them
}
