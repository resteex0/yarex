
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
		 date = "2022-01-10_19-30-47" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "a158607e499d658b54d123daf0fdb1b6"

	strings:

	
 		 $a1= "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" fullword ascii
		 $a2= "28@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@A(" fullword ascii
		 $a3= "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@A" fullword ascii
		 $a4= "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@A" fullword ascii
		 $a5= "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@A(" fullword ascii
		 $a6= "@@@@@@@@@@@@@@@@@@@@@@@@A" fullword ascii
		 $a7= "{@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@A" fullword ascii
		 $a8= "C:/Users/dhill/Desktop/test" fullword ascii
		 $a9= "C:UsersdhillDownloadsHellsReleaseHellsRansomware.pdb" fullword ascii
		 $a10= "ExpandEnvironmentStringsA" fullword ascii
		 $a11= "V@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@A" fullword ascii

		 $hex1= {246131303d20224578}
		 $hex2= {246131313d20225640}
		 $hex3= {2461313d2022404040}
		 $hex4= {2461323d2022323840}
		 $hex5= {2461333d2022404040}
		 $hex6= {2461343d2022404040}
		 $hex7= {2461353d2022404040}
		 $hex8= {2461363d2022404040}
		 $hex9= {2461373d20227b4040}
		 $hex10= {2461383d2022433a2f}
		 $hex11= {2461393d2022433a55}

	condition:
		1 of them
}
