
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
		 date = "2022-03-22_14-15-35" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0ef5ed6cd6b1917807ad2ed87e377540"

	strings:

	
 		 $s1= "DocumentSummaryInformation" fullword wide
		 $s2= "Project.NLMPGANATmYQ.AutoOpen" fullword wide

		 $hex1= {446f63756d656e7453}
		 $hex2= {50726f6a6563742e4e}

	condition:
		1 of them
}
