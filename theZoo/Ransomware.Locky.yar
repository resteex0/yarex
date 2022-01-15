
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Locky 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Locky {
	meta: 
		 description= "Ransomware_Locky Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-53-36" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "b06d9dd17c69ed2ae75d9e40b2631b42"

	strings:

	
 		 $s1= "E56467wJ f14247Q9" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "hLbPhA Dpm3f12Z" fullword wide
		 $s4= "&ht49y39 wJt5zXU" fullword wide
		 $s5= "HvEEL8a V782Jcv" fullword wide
		 $s6= "kR3113hA r16VKeI" fullword wide
		 $s7= "LegalTrademarks" fullword wide
		 $s8= "Lipreading Fenced" fullword wide
		 $s9= "OriginalFilename" fullword wide
		 $s10= "q3JvWzy nzY2Gi4c" fullword wide
		 $s11= "&v9SVCzg AHdhC1E" fullword wide
		 $s12= "VS_VERSION_INFO" fullword wide
		 $s13= "zQ332C4 n0wywB8R" fullword wide

		 $hex1= {247331303d20227133}
		 $hex2= {247331313d20222676}
		 $hex3= {247331323d20225653}
		 $hex4= {247331333d20227a51}
		 $hex5= {2473313d2022453536}
		 $hex6= {2473323d202246696c}
		 $hex7= {2473333d2022684c62}
		 $hex8= {2473343d2022266874}
		 $hex9= {2473353d2022487645}
		 $hex10= {2473363d20226b5233}
		 $hex11= {2473373d20224c6567}
		 $hex12= {2473383d20224c6970}
		 $hex13= {2473393d20224f7269}

	condition:
		1 of them
}
