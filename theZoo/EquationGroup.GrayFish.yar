
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
		 date = "2022-01-14_22-51-02" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "9b1ca66aab784dc5f1dfe635d8f8a904"

	strings:

	
 		 $s1= "''2]ZEh*2@''izGWE~]''h@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h" fullword wide
		 $s2= "BsDADm$}u))ms''D@h*]iN[''" fullword wide
		 $s3= "sGh@h*]i2cc*sG''h@h*]iN[''g2EK]2h''sh" fullword wide
		 $s4= "tB''CRS%)CD''D@h*]iN[''%2EK]2h''" fullword wide
		 $s5= "''u]ZEh*2@''}zGWE~]''D@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h''" fullword wide
		 $a1= "''2]ZEh*2@''izGWE~]''h@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h" fullword ascii
		 $a2= "''u]ZEh*2@''}zGWE~]''D@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h''" fullword ascii

		 $hex1= {2461313d2022272732}
		 $hex2= {2461323d2022272775}
		 $hex3= {2473313d2022272732}
		 $hex4= {2473323d2022427344}
		 $hex5= {2473333d2022734768}
		 $hex6= {2473343d2022744227}
		 $hex7= {2473353d2022272775}

	condition:
		4 of them
}
