
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Emotet 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Emotet {
	meta: 
		 description= "Win32_Emotet Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-21" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8baa9b809b591a11af423824f4d9726a"

	strings:

	
 		 $s1= "57576736879580478257258376974939" fullword wide
		 $s2= "Remounter (2)RemounterVeladonACCOJ.vbp" fullword wide
		 $a1= "JIHKMMJNOALAKBEGWX[Y_Q[PPSW[RYjihkmmjnoalakbegw|x{y" fullword ascii
		 $a2= "LONMKKLHIGJGMDCAQZ^]_YW]VVZUQ]T_lonmkklhigjgmdfasy" fullword ascii

		 $hex1= {2461313d20224a4948}
		 $hex2= {2461323d20224c4f4e}
		 $hex3= {2473313d2022353735}
		 $hex4= {2473323d202252656d}

	condition:
		2 of them
}
