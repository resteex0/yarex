
/*
   YARA Rule Set
   Author: resteex
   Identifier: BlackEnergy2_1 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_BlackEnergy2_1 {
	meta: 
		 description= "BlackEnergy2_1 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-19" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "9219e2cfcc64ccde2d8de507538b9991"

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
