
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Infostealer_Dexter 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Infostealer_Dexter {
	meta: 
		 description= "Win32_Infostealer_Dexter Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-30" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "140d24af0c2b3a18529df12dfbc5f6de"
		 hash2= "7d419cd096fec8bcf945e00e70a9bc41"

	strings:

	
 		 $s1= "Internet Exploreriexplore.exe" fullword wide
		 $a1= ".DEFAULTSOFTWAREMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a2= "SoftwareMicrosoftWindowsCurrentVersionPoliciesAssociations" fullword ascii

		 $hex1= {2461313d20222e4445}
		 $hex2= {2461323d2022536f66}
		 $hex3= {2473313d2022496e74}

	condition:
		2 of them
}
