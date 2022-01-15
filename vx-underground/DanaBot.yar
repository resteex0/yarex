
/*
   YARA Rule Set
   Author: resteex
   Identifier: DanaBot 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_DanaBot {
	meta: 
		 description= "DanaBot Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-02-12" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ab4cf6181cfb102ec86c66d56af2d229"

	strings:

	
 		 $s1= "lafolawilugehazocinogohigugalug" fullword wide
		 $s2= "SEJUWUSIZABUTUXAKAYUPIGIGEYOKAHA" fullword wide

		 $hex1= {2473313d20226c6166}
		 $hex2= {2473323d202253454a}

	condition:
		1 of them
}
