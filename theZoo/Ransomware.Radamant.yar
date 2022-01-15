
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Radamant 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Radamant {
	meta: 
		 description= "Ransomware_Radamant Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "6152709e741c4d5a5d793d35817b4c3d"
		 hash2= "892626ba70f22a5c7593116b8d2defcf"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "LegalTrademarks" fullword wide
		 $s3= "Microsoft Corporation" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d202246696c}
		 $hex2= {2473323d20224c6567}
		 $hex3= {2473333d20224d6963}
		 $hex4= {2473343d20224f7269}
		 $hex5= {2473353d202256535f}

	condition:
		1 of them
}
