
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_EquationLaser 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_EquationLaser {
	meta: 
		 description= "EquationGroup_EquationLaser Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-26" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "752af597e6d9fd70396accc0b9013dbe"

	strings:

	
 		 $s1= "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "Microsoft Corporation" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide
		 $a1= "5.2.3790.220 (srv03_gdr.040918-1552)" fullword ascii

		 $hex1= {2461313d2022352e32}
		 $hex2= {2473313d2022352e32}
		 $hex3= {2473323d202246696c}
		 $hex4= {2473333d20224d6963}
		 $hex5= {2473343d20224f7269}
		 $hex6= {2473353d202256535f}

	condition:
		2 of them
}
