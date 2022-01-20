
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
		 date = "2022-01-20_04-43-26" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "bb5441af1e1741fca600e9c433cb1550"
		 hash2= "c81d037b723adc43e3ee17b1eee9d6cc"
		 hash3= "c9e00c9d94d1a790d5923b050b0bd741"

	strings:

	
 		 $s1= "RtlExpandEnvironmentStrings_U" fullword wide
		 $s2= "Session%dTH_POOL_SHD_MTX_FSW95XQ_TEST" fullword wide
		 $s3= "S:(ML;;NW;;;LW)D:(A;OICI;GA;;;WD)" fullword wide
		 $s4= "%sTH_POOL_SHD_MTX_FSW95XQ_%d" fullword wide
		 $s5= "%sTH_POOL_SHD_PQOISNG_%dSYNCMTX" fullword wide
		 $s6= "TH_POOL_SHD_MTX_GMN94XQ_%d" fullword wide
		 $s7= "TH_POOL_SHD_PQOMGMN_%dSYNCMTX" fullword wide
		 $s8= "UPDT_SYNC_MTX_TME_ON_OFF_%d_%d" fullword wide
		 $a1= ".?AVTohkuixgRflZavycpWtohkuIxgrflzav@qsbdzsml@sr@@" fullword ascii
		 $a2= ".?AVXcyfvsawkyZkgVqxqXcyfvsawKyzkgvqxq@ezrqwlx@sr@@" fullword ascii
		 $a3= "ConvertStringSecurityDescriptorToSecurityDescriptorW" fullword ascii

		 $hex1= {2461313d20222e3f41}
		 $hex2= {2461323d20222e3f41}
		 $hex3= {2461333d2022436f6e}
		 $hex4= {2473313d202252746c}
		 $hex5= {2473323d2022536573}
		 $hex6= {2473333d2022533a28}
		 $hex7= {2473343d2022257354}
		 $hex8= {2473353d2022257354}
		 $hex9= {2473363d202254485f}
		 $hex10= {2473373d202254485f}
		 $hex11= {2473383d2022555044}

	condition:
		7 of them
}
