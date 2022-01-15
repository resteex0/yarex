
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Carberp 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Carberp {
	meta: 
		 description= "Win32_Carberp Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-38-44" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "11bba9b2333559b727caf22896092217"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "OriginalFilename" fullword wide
		 $s3= "VS_VERSION_INFO" fullword wide
		 $s4= "!x-sys-default-locale" fullword wide

		 $hex1= {2473313d202246696c}
		 $hex2= {2473323d20224f7269}
		 $hex3= {2473333d202256535f}
		 $hex4= {2473343d202221782d}

	condition:
		1 of them
}
