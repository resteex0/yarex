
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_GrayFish 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_GrayFish {
	meta: 
		 description= "EquationGroup_GrayFish Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-53-17" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "9b1ca66aab784dc5f1dfe635d8f8a904"

	strings:

	
 		 $s1= "''2]ZEh*2@''izGWE~]''h@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h" fullword wide
		 $s2= "BsDADm$}u))ms''D@h*]iN[''" fullword wide
		 $s3= "cnFormSyncExFBC" fullword wide
		 $s4= "FileDescription" fullword wide
		 $s5= "Microsoft Corporation" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= "S]*Fc2XY+hhcGEz*]h" fullword wide
		 $s8= "sGh@h*]i2cc*sG''h@h*]iN[''g2EK]2h''sh" fullword wide
		 $s9= "tB''CRS%)CD''D@h*]iN[''" fullword wide
		 $s10= "tB''CRS%)CD''D@h*]iN[''%2EK]2h''" fullword wide
		 $s11= "''u]ZEh*2@''}zGWE~]''D@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h''" fullword wide
		 $s12= "VS_VERSION_INFO" fullword wide
		 $a1= "''2]ZEh*2@''izGWE~]''h@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h" fullword ascii
		 $a2= "sGh@h*]i2cc*sG''h@h*]iN[''g2EK]2h''sh" fullword ascii
		 $a3= "''u]ZEh*2@''}zGWE~]''D@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h''" fullword ascii

		 $hex1= {2461313d2022272732}
		 $hex2= {2461323d2022734768}
		 $hex3= {2461333d2022272775}
		 $hex4= {247331303d20227442}
		 $hex5= {247331313d20222727}
		 $hex6= {247331323d20225653}
		 $hex7= {2473313d2022272732}
		 $hex8= {2473323d2022427344}
		 $hex9= {2473333d2022636e46}
		 $hex10= {2473343d202246696c}
		 $hex11= {2473353d20224d6963}
		 $hex12= {2473363d20224f7269}
		 $hex13= {2473373d2022535d2a}
		 $hex14= {2473383d2022734768}
		 $hex15= {2473393d2022744227}

	condition:
		1 of them
}
