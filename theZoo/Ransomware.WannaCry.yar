
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_WannaCry 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_WannaCry {
	meta: 
		 description= "Ransomware_WannaCry Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-43-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "84c82835a5d21bbcf75a61706d8ab549"

	strings:

	
 		 $s1= "6.1.7601.17514 (win7sp1_rtm.101119-1850)" fullword wide

		 $hex1= {2473313d2022362e31}

	condition:
		0 of them
}
