
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Emotet 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Emotet {
	meta: 
		 description= "APT_Sample_Emotet Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-22_17-55-42" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0ef5ed6cd6b1917807ad2ed87e377540"

	strings:

	
 		 $s1= "DocumentSummaryInformation" fullword wide
		 $s2= "Project.NLMPGANATmYQ.AutoOpen" fullword wide

		 $hex1= {2473313d2022446f63}
		 $hex2= {2473323d202250726f}

	condition:
		1 of them
}
