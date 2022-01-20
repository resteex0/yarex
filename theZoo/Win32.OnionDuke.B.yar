
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_OnionDuke_B 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_OnionDuke_B {
	meta: 
		 description= "Win32_OnionDuke_B Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-38" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "c8eb6040fd02d77660d19057a38ff769"

	strings:

	
 		 $a1= ".?AVITempFileCreator@NtHttpModule_UrlDownloadToFile@@" fullword ascii

		 $hex1= {2461313d20222e3f41}

	condition:
		0 of them
}
