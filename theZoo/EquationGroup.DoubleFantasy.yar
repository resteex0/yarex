
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_DoubleFantasy 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_DoubleFantasy {
	meta: 
		 description= "EquationGroup_DoubleFantasy Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-42-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2a12630ff976ba0994143ca93fecd17f"

	strings:

	
 		 $s1= "!#%')+-/13579;=?ACEGIKMOQSUWY[]_acegikmoq" fullword wide
		 $a1= "SRJYNHoHNUR[oY_INUHExYO_NULHSNhSoY_INUHExYO_NULHSN}" fullword ascii

		 $hex1= {2461313d202253524a}
		 $hex2= {2473313d2022212325}

	condition:
		1 of them
}
