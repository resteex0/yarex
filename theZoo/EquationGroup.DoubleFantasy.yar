
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
		 date = "2022-01-14_21-37-25" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2a12630ff976ba0994143ca93fecd17f"

	strings:

	
 		 $s1= "!#%')+-/13579;=?ACEGIKMOQSUWY[]_acegikmoq" fullword wide
		 $s2= "@DHLPTX`dhlpv|" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide
		 $a1= "!#%')+-/13579;=?ACEGIKMOQSUWY[]_acegikmoq" fullword ascii

		 $hex1= {2461313d2022212325}
		 $hex2= {2473313d2022212325}
		 $hex3= {2473323d2022404448}
		 $hex4= {2473333d202246696c}
		 $hex5= {2473343d20224f7269}
		 $hex6= {2473353d202256535f}

	condition:
		2 of them
}
