
/*
   YARA Rule Set
   Author: resteex
   Identifier: Shamoon 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Shamoon {
	meta: 
		 description= "Shamoon Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-51-29" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "b14299fd4d1cbfb4cc7486d978398214"
		 hash2= "d214c717a357fe3a455610b197c390aa"

	strings:

	
 		 $s1= "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
		 $s2= "SYSTEMCurrentControlSetControlSession ManagerEnvironment" fullword wide
		 $s3= "SYSTEMCurrentControlSetServicesTrkSvr" fullword wide
		 $a1= "SYSTEMCurrentControlSetControlSession ManagerEnvironment" fullword ascii

		 $hex1= {2461313d2022535953}
		 $hex2= {2473313d2022352e32}
		 $hex3= {2473323d2022535953}
		 $hex4= {2473333d2022535953}

	condition:
		2 of them
}
