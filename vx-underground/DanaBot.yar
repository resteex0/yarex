
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_DanaBot 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_DanaBot {
	meta: 
		 description= "vx_underground2_DanaBot Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-54-38" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ab4cf6181cfb102ec86c66d56af2d229"

	strings:

	
 		 $s1= "lafolawilugehazocinogohigugalug" fullword wide
		 $s2= "SEJUWUSIZABUTUXAKAYUPIGIGEYOKAHA" fullword wide
		 $a1= "cahenokejocijugujinugacokimugizirafehewisamiwetutonuwacogohatudo" fullword ascii

		 $hex1= {2461313d2022636168}
		 $hex2= {2473313d20226c6166}
		 $hex3= {2473323d202253454a}

	condition:
		2 of them
}
