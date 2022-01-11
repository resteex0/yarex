
/*
   YARA Rule Set
   Author: resteex
   Identifier: WM_Alliance_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_WM_Alliance_A {
	meta: 
		 description= "WM_Alliance_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-35-39" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "35445cce9ab35fbc3b78bfac96874879"
		 hash2= "df6dca243d6230c78b88d6ee24398f58"

	strings:

	
 		 $s1= "SummaryInformation" fullword wide
		 $a1= "------------------------------------------------" fullword ascii
		 $a2= "!!!!!###$$$$$$$$$$$$$$$$$$$!!!##$$$$$$$$$$$#" fullword ascii
		 $a3= "!!!!!!!!!###$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$#" fullword ascii
		 $a4= "!!!!!###$$$$$$$$$$$$$$$$$$$$$$$$$$$$($$$$$!" fullword ascii
		 $a5= "$,,,33333333333333333333333334444433$" fullword ascii
		 $a6= "&12255222222222222111111111" fullword ascii
		 $a7= "22222222222222111111111**" fullword ascii
		 $a8= "2445555555555555422555555*" fullword ascii
		 $a9= "*25889999999999998888881%" fullword ascii
		 $a10= "32255555555555552225555552&" fullword ascii
		 $a11= "!),,333333333333333333333333334433," fullword ascii
		 $a12= "33333,3333333333344444444444," fullword ascii
		 $a13= "6::::::::::::::'$::::::,)" fullword ascii
		 $a14= "C:MSOFFICEWINWORDTEMPLATENORMAL.DOT" fullword ascii
		 $a15= "@NZIAN_02HP4M_WRITERS" fullword ascii

		 $hex1= {246131303d20223332}
		 $hex2= {246131313d20222129}
		 $hex3= {246131323d20223333}
		 $hex4= {246131333d2022363a}
		 $hex5= {246131343d2022433a}
		 $hex6= {246131353d2022401b}
		 $hex7= {2461313d20222d2d2d}
		 $hex8= {2461323d2022212121}
		 $hex9= {2461333d2022212121}
		 $hex10= {2461343d2022212121}
		 $hex11= {2461353d2022242c2c}
		 $hex12= {2461363d2022263132}
		 $hex13= {2461373d2022323232}
		 $hex14= {2461383d2022323434}
		 $hex15= {2461393d20222a3235}
		 $hex16= {2473313d202253756d}

	condition:
		2 of them
}
