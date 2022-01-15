
/*
   YARA Rule Set
   Author: resteex
   Identifier: Somoto 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Somoto {
	meta: 
		 description= "Somoto Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-38-02" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "02e0b78e2876087f678f070ed60e4c30"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "MSCTLS_PROGRESS32" fullword wide
		 $s3= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d202246696c}
		 $hex2= {2473323d20224d5343}
		 $hex3= {2473333d202256535f}

	condition:
		1 of them
}
