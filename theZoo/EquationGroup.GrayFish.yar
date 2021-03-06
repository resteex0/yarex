
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_EquationGroup_GrayFish 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_EquationGroup_GrayFish {
	meta: 
		 description= "theZoo_EquationGroup_GrayFish Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-34-56" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "9b1ca66aab784dc5f1dfe635d8f8a904"

	strings:

	
 		 $s1= "''2]ZEh*2@''izGWE~]''h@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h" fullword wide
		 $s2= "BsDADm$}u))ms''D@h*]iN[''" fullword wide
		 $s3= "sGh@h*]i2cc*sG''h@h*]iN[''g2EK]2h''sh" fullword wide
		 $s4= "tB''CRS%)CD''D@h*]iN[''%2EK]2h''" fullword wide
		 $s5= "''u]ZEh*2@''}zGWE~]''D@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h''" fullword wide

		 $hex1= {2473313d2022272732}
		 $hex2= {2473323d2022427344}
		 $hex3= {2473333d2022734768}
		 $hex4= {2473343d2022744227}
		 $hex5= {2473353d2022272775}

	condition:
		3 of them
}
