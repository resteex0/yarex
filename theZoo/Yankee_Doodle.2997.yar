
/*
   YARA Rule Set
   Author: resteex
   Identifier: Yankee_Doodle_2997 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Yankee_Doodle_2997 {
	meta: 
		 description= "Yankee_Doodle_2997 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-45-28" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "54caf0a5f988123667929206f3aa5f6c"
		 hash2= "76213bf17f60d4f8f4818e0eab0b6f65"

	strings:

	
 		 $s1= "=>?@ABCDGHIKMOPQRSTUVWXYZ[]st" fullword wide

		 $hex1= {2473313d20223d3e3f}

	condition:
		0 of them
}
