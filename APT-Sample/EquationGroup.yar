
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_EquationGroup 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_EquationGroup {
	meta: 
		 description= "APT_Sample_EquationGroup Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-22_14-16-08" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "03718676311de33dd0b8f4f18cffd488"
		 hash2= "0a209ac0de4ac033f31d6ba9191a8f7a"
		 hash3= "11fb08b9126cdb4668b3f5135cf7a6c5"
		 hash4= "24a6ec8ebf9c0867ed1c097f4a653b8d"
		 hash5= "2a12630ff976ba0994143ca93fecd17f"
		 hash6= "4556ce5eb007af1de5bd3b457f0b216d"
		 hash7= "6fe6c03b938580ebf9b82f3b9cd4c4aa"
		 hash8= "752af597e6d9fd70396accc0b9013dbe"
		 hash9= "9180d5affe1e5df0717d7385e7f54386"
		 hash10= "9b1ca66aab784dc5f1dfe635d8f8a904"
		 hash11= "f3a9e9a174772a0f6e597d4cde47c24b"

	strings:

	
 		 $s1= "!#%')+-/13579;=?ACEGIKMOQSUWY[]_acegikmoq" fullword wide
		 $s2= "''2]ZEh*2@''izGWE~]''h@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h" fullword wide
		 $s3= "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide
		 $s4= "BsDADm$}u))ms''D@h*]iN[''" fullword wide
		 $s5= "registrymachinesoftwareMicrosoftWindows NTCurrentVersion" fullword wide
		 $s6= "sGh@h*]i2cc*sG''h@h*]iN[''g2EK]2h''sh" fullword wide
		 $s7= "tB''CRS%)CD''D@h*]iN[''%2EK]2h''" fullword wide
		 $s8= "''u]ZEh*2@''}zGWE~]''D@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h''" fullword wide

		 $hex1= {21232527292b2d2f31}
		 $hex2= {2727325d5a45682a32}
		 $hex3= {2727755d5a45682a32}
		 $hex4= {352e322e333739302e}
		 $hex5= {42734441446d247d75}
		 $hex6= {72656769737472796d}
		 $hex7= {73476840682a5d6932}
		 $hex8= {744227274352532529}

	condition:
		5 of them
}
