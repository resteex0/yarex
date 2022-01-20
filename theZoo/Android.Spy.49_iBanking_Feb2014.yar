
/*
   YARA Rule Set
   Author: resteex
   Identifier: Android_Spy_49_iBanking_Feb2014 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Android_Spy_49_iBanking_Feb2014 {
	meta: 
		 description= "Android_Spy_49_iBanking_Feb2014 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-42-06" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "e1b86054468d6ac1274188c0c579ccaf"
		 hash2= "f06af629d33f17938849f822930ae428"
		 hash3= "f0a1475583278466b673ac902b664e42"

	strings:

	
 		 $s1= "com.BioTechnology.iClientsService4" fullword wide

		 $hex1= {2473313d2022636f6d}

	condition:
		0 of them
}
