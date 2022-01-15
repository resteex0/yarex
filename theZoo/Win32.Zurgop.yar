
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Zurgop 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Zurgop {
	meta: 
		 description= "Win32_Zurgop Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-39-30" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "c1e5dae72a51a7b7219346c4a360d867"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "Lighttek Software" fullword wide
		 $s3= "OriginalFilename" fullword wide
		 $s4= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d202246696c}
		 $hex2= {2473323d20224c6967}
		 $hex3= {2473333d20224f7269}
		 $hex4= {2473343d202256535f}

	condition:
		1 of them
}
