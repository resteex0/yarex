
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Win32_Bechiro_BCD 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Win32_Bechiro_BCD {
	meta: 
		 description= "Trojan_Win32_Bechiro_BCD Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-38-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0d06681f63f3026260aa1e15d86520a0"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "OriginalFilename" fullword wide
		 $s3= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d202246696c}
		 $hex2= {2473323d20224f7269}
		 $hex3= {2473333d202256535f}

	condition:
		1 of them
}
