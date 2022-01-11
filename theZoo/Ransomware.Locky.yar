
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
		 date = "2022-01-10_19-27-31" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "b06d9dd17c69ed2ae75d9e40b2631b42"

	strings:

	
 		 $s1= "A5591i1a qXX4k bK0cZYZ c6Uo35uI" fullword wide
		 $s2= "B8640 t3it ziS492" fullword wide
		 $s3= "&c5l6t5 JyTm73u7 kL6sBT j85Z074" fullword wide
		 $s4= "&CmQQK jF71w0m4 XD7" fullword wide
		 $s5= "E05UWP88 BYT477 Ng15p9" fullword wide
		 $s6= "E56467wJ f14247Q9" fullword wide
		 $s7= "&e87h Y5MN0 B6801N C5B3K" fullword wide
		 $s8= "FileDescription" fullword wide
		 $s9= "gMGE P62CD X0t7F4I3 g88K1" fullword wide
		 $s10= "h13J67 T7z Lh2242bW" fullword wide
		 $s11= "hLbPhA Dpm3f12Z" fullword wide
		 $s12= "&ht49y39 wJt5zXU" fullword wide
		 $s13= "HvEEL8a V782Jcv" fullword wide
		 $s14= "Intend (C) 2013" fullword wide
		 $s15= "JuXz3P08 Fkz727 fh4b5E7 k4X0" fullword wide
		 $s16= "kR3113hA r16VKeI" fullword wide
		 $s17= "L78D0 wWG45b3S in4 iiJ5g6" fullword wide
		 $s18= "LegalTrademarks" fullword wide
		 $s19= "Lipreading Fenced" fullword wide
		 $s20= "Microsoft Sans Serif" fullword wide
		 $s21= "mp50Qr d801U9 C3O" fullword wide
		 $s22= "N9366ig PAn4jJ2 va6653" fullword wide
		 $s23= "n985j gmHd5455 r4H" fullword wide
		 $s24= "Nls82 F31 bTs02P" fullword wide
		 $s25= "&o221 VR69953 McpL5U0E OREu22J" fullword wide
		 $s26= "OriginalFilename" fullword wide
		 $s27= "q3JvWzy nzY2Gi4c" fullword wide
		 $s28= "qW2aZj0 RT1 Vi05" fullword wide
		 $s29= "rWR Fd12I QT9w66Y" fullword wide
		 $s30= "tB70F15 j24 D8H J09" fullword wide
		 $s31= "ty3834 lew0 REY9j S7AKWo4" fullword wide
		 $s32= "V0U4pu J97I0i0D c1Au38" fullword wide
		 $s33= "&v9SVCzg AHdhC1E" fullword wide
		 $s34= "vcPEc hQ3P g28Km9 E5g70P" fullword wide
		 $s35= "VS_VERSION_INFO" fullword wide
		 $s36= "wcf7J3w8 r3aX lb2 b1j" fullword wide
		 $s37= "wM124m F8Q uo4D1" fullword wide
		 $s38= "&Y9le1 d78Q4mcR fqX62" fullword wide
		 $s39= "yEUK2 DMUK gY47IG x5Ewn03" fullword wide
		 $s40= "Yf5j0 FA2BQXE6 T6P733Z YL48" fullword wide
		 $s41= "&YU4 L2q1505 a32880x K0QB169" fullword wide
		 $s42= "&Z3ZW3 K6P638e yv5PTs" fullword wide
		 $s43= "ZEla31c h6FT d674Bc11" fullword wide
		 $s44= "zQ332C4 n0wywB8R" fullword wide
		 $s45= "zq7y25 QVE24 WSfm w8MF6" fullword wide
		 $s46= "zTm1R3l0 jx5jNg6y z511G3" fullword wide
		 $a1= "#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0" fullword ascii
		 $a2= "CreateDialogIndirectParamW" fullword ascii
		 $a3= "GetSecurityDescriptorDacl" fullword ascii
		 $a4= "GetSidIdentifierAuthority" fullword ascii
		 $a5= "HousebuildingIndirectness" fullword ascii
		 $a6= "ImmGetCandidateListCountA" fullword ascii
		 $a7= "InadvisabilityHeartwarming" fullword ascii
		 $a8= "InitializeSecurityDescriptor" fullword ascii
		 $a9= "InterdisciplinaryInvested" fullword ascii
		 $a10= "InterrelationshipsMeadows" fullword ascii
		 $a11= "LsaQueryInformationPolicy" fullword ascii
		 $a12= "MagnetosphereHyperventilated" fullword ascii
		 $a13= "MercenariesInfinitesimals" fullword ascii
		 $a14= "MusicalityInconsiderately" fullword ascii
		 $a15= "SetSecurityDescriptorSacl" fullword ascii

		 $hex1= {246131303d2022496e}
		 $hex2= {246131313d20224c73}
		 $hex3= {246131323d20224d61}
		 $hex4= {246131333d20224d65}
		 $hex5= {246131343d20224d75}
		 $hex6= {246131353d20225365}
		 $hex7= {2461313d2022233023}
		 $hex8= {2461323d2022437265}
		 $hex9= {2461333d2022476574}
		 $hex10= {2461343d2022476574}
		 $hex11= {2461353d2022486f75}
		 $hex12= {2461363d2022496d6d}
		 $hex13= {2461373d2022496e61}
		 $hex14= {2461383d2022496e69}
		 $hex15= {2461393d2022496e74}
		 $hex16= {247331303d20226831}
		 $hex17= {247331313d2022684c}
		 $hex18= {247331323d20222668}
		 $hex19= {247331333d20224876}
		 $hex20= {247331343d2022496e}
		 $hex21= {247331353d20224a75}
		 $hex22= {247331363d20226b52}
		 $hex23= {247331373d20224c37}
		 $hex24= {247331383d20224c65}
		 $hex25= {247331393d20224c69}
		 $hex26= {2473313d2022413535}
		 $hex27= {247332303d20224d69}
		 $hex28= {247332313d20226d70}
		 $hex29= {247332323d20224e39}
		 $hex30= {247332333d20226e39}
		 $hex31= {247332343d20224e6c}
		 $hex32= {247332353d2022266f}
		 $hex33= {247332363d20224f72}
		 $hex34= {247332373d20227133}
		 $hex35= {247332383d20227157}
		 $hex36= {247332393d20227257}
		 $hex37= {2473323d2022423836}
		 $hex38= {247333303d20227442}
		 $hex39= {247333313d20227479}
		 $hex40= {247333323d20225630}
		 $hex41= {247333333d20222676}
		 $hex42= {247333343d20227663}
		 $hex43= {247333353d20225653}
		 $hex44= {247333363d20227763}
		 $hex45= {247333373d2022774d}
		 $hex46= {247333383d20222659}
		 $hex47= {247333393d20227945}
		 $hex48= {2473333d2022266335}
		 $hex49= {247334303d20225966}
		 $hex50= {247334313d20222659}
		 $hex51= {247334323d2022265a}
		 $hex52= {247334333d20225a45}
		 $hex53= {247334343d20227a51}
		 $hex54= {247334353d20227a71}
		 $hex55= {247334363d20227a54}
		 $hex56= {2473343d202226436d}
		 $hex57= {2473353d2022453035}
		 $hex58= {2473363d2022453536}
		 $hex59= {2473373d2022266538}
		 $hex60= {2473383d202246696c}
		 $hex61= {2473393d2022674d47}

	condition:
		7 of them
}
