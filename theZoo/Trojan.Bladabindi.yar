
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Bladabindi 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Bladabindi {
	meta: 
		 description= "Trojan_Bladabindi Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-38-17" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "5a559b6d223c79f3736dc52794636cfd"

	strings:

	
 		 $s1= "Assembly Version" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "OriginalFilename" fullword wide
		 $s4= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d2022417373}
		 $hex2= {2473323d202246696c}
		 $hex3= {2473333d20224f7269}
		 $hex4= {2473343d202256535f}

	condition:
		1 of them
}
