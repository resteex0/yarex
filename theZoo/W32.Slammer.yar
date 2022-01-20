
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_Slammer 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_Slammer {
	meta: 
		 description= "W32_Slammer Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0895501a7e2494b5b46bd98836052f8d"
		 hash2= "81090a2a0db5ba1252c090ba199b82fd"
		 hash3= "e7486668f47b733f0af041029685a246"
		 hash4= "f1c976985e864b6f617daf9cd3af47b0"

	strings:

	
 		 $a1= "PRE>C:&gt;scanslam 192.168.0.0-192.168.255.255" fullword ascii

		 $hex1= {2461313d2022505245}

	condition:
		0 of them
}
