
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
		 date = "2022-01-20_04-42-23" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "752af597e6d9fd70396accc0b9013dbe"

	strings:

	
 		 $s1= "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide

		 $hex1= {2473313d2022352e32}

	condition:
		0 of them
}
