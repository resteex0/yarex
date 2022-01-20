
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Taleret 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Taleret {
	meta: 
		 description= "Win32_Taleret Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-56" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "c4de3fea790f8ff6452016db5d7aa33f"
		 hash2= "d9940a3da42eb2bb8e19a84235d86e91"
		 hash3= "fed166a667ab9cbb1ef6331b8e9d7894"

	strings:

	
 		 $s1= "DocumentSummaryInformation" fullword wide
		 $a1= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword ascii

		 $hex1= {2461313d2022536f66}
		 $hex2= {2473313d2022446f63}

	condition:
		1 of them
}
