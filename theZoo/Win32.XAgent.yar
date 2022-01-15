
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
		 date = "2022-01-14_21-39-28" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2f6d1bed602a3ad749301e7aa3800139"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "Microsoft Corporation" fullword wide
		 $s3= "OriginalFilename" fullword wide
		 $s4= "RegisterServiceCtrlHandler" fullword wide
		 $s5= "StartServiceCtrlDispatcher" fullword wide
		 $s6= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d202246696c}
		 $hex2= {2473323d20224d6963}
		 $hex3= {2473333d20224f7269}
		 $hex4= {2473343d2022526567}
		 $hex5= {2473353d2022537461}
		 $hex6= {2473363d202256535f}

	condition:
		2 of them
}
