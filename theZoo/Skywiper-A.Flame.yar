
/*
   YARA Rule Set
   Author: resteex
   Identifier: Skywiper_A_Flame 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Skywiper_A_Flame {
	meta: 
		 description= "Skywiper_A_Flame Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-53-51" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "bb5441af1e1741fca600e9c433cb1550"
		 hash2= "c81d037b723adc43e3ee17b1eee9d6cc"
		 hash3= "c9e00c9d94d1a790d5923b050b0bd741"

	strings:

	
 		 $s1= "D:(A;OICI;GA;;;WD)" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "GetModuleHandleA" fullword wide
		 $s4= "GetModuleHandleW" fullword wide
		 $s5= "Microsoft Corporation" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= "RtlCreateUserThread" fullword wide
		 $s8= "RtlExpandEnvironmentStrings_U" fullword wide
		 $s9= "RtlInitUnicodeString" fullword wide
		 $s10= "Session%dTH_POOL_SHD_MTX_FSW95XQ_TEST" fullword wide
		 $s11= "S:(ML;;NW;;;LW)" fullword wide
		 $s12= "S:(ML;;NW;;;LW)D:(A;OICI;GA;;;WD)" fullword wide
		 $s13= "%sTH_POOL_SHD_MTX_FSW95XQ_%d" fullword wide
		 $s14= "%sTH_POOL_SHD_PQOISNG_%dSYNCMTX" fullword wide
		 $s15= "TH_POOL_SHD_MTX_GMN94XQ_%d" fullword wide
		 $s16= "TH_POOL_SHD_PQOMGMN_%dSYNCMTX" fullword wide
		 $s17= "UPDT_SYNC_MTX_TME_ON_OFF_%d_%d" fullword wide
		 $s18= "VS_VERSION_INFO" fullword wide
		 $a1= "Session%dTH_POOL_SHD_MTX_FSW95XQ_TEST" fullword ascii

		 $hex1= {2461313d2022536573}
		 $hex2= {247331303d20225365}
		 $hex3= {247331313d2022533a}
		 $hex4= {247331323d2022533a}
		 $hex5= {247331333d20222573}
		 $hex6= {247331343d20222573}
		 $hex7= {247331353d20225448}
		 $hex8= {247331363d20225448}
		 $hex9= {247331373d20225550}
		 $hex10= {247331383d20225653}
		 $hex11= {2473313d2022443a28}
		 $hex12= {2473323d202246696c}
		 $hex13= {2473333d2022476574}
		 $hex14= {2473343d2022476574}
		 $hex15= {2473353d20224d6963}
		 $hex16= {2473363d20224f7269}
		 $hex17= {2473373d202252746c}
		 $hex18= {2473383d202252746c}
		 $hex19= {2473393d202252746c}

	condition:
		2 of them
}
