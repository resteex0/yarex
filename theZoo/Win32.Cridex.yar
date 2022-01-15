
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Cridex 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Cridex {
	meta: 
		 description= "Win32_Cridex Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-38-44" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "acdd4c2a377933d89139b5ee6eefc464"

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
