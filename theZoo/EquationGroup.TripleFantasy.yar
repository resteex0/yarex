
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_TripleFantasy 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_TripleFantasy {
	meta: 
		 description= "EquationGroup_TripleFantasy Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-27" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "9180d5affe1e5df0717d7385e7f54386"

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
