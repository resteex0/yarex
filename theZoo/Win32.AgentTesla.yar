
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_AgentTesla 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_AgentTesla {
	meta: 
		 description= "Win32_AgentTesla Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-38-34" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2b294b3499d1cce794badffc959b7618"

	strings:

	
 		 $s1= "Assembly Version" fullword wide
		 $s2= "Comverse Technology" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d2022417373}
		 $hex2= {2473323d2022436f6d}
		 $hex3= {2473333d202246696c}
		 $hex4= {2473343d20224f7269}
		 $hex5= {2473353d202256535f}

	condition:
		1 of them
}
