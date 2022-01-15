
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_WannaCry 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_WannaCry {
	meta: 
		 description= "Ransomware_WannaCry Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-57" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "84c82835a5d21bbcf75a61706d8ab549"

	strings:

	
 		 $s1= "6.1.7601.17514 (win7sp1_rtm.101119-1850)" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "Microsoft Corporation" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide
		 $a1= "6.1.7601.17514 (win7sp1_rtm.101119-1850)" fullword ascii

		 $hex1= {2461313d2022362e31}
		 $hex2= {2473313d2022362e31}
		 $hex3= {2473323d202246696c}
		 $hex4= {2473333d20224d6963}
		 $hex5= {2473343d20224f7269}
		 $hex6= {2473353d202256535f}

	condition:
		2 of them
}
