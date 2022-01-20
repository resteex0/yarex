
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Ransom_Hells 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Ransom_Hells {
	meta: 
		 description= "Trojan_Ransom_Hells Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-43-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "a158607e499d658b54d123daf0fdb1b6"

	strings:

	
 		 $a1= "C:UsersdhillDownloadsHellsReleaseHellsRansomware.pdb" fullword ascii

		 $hex1= {2461313d2022433a55}

	condition:
		0 of them
}
