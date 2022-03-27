
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
		 date = "2022-03-27_09-56-41" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0ef5ed6cd6b1917807ad2ed87e377540"

	strings:

	
 		 $s1= "DocumentSummaryInformation" fullword wide
		 $s2= "Project.NLMPGANATmYQ.AutoOpen" fullword wide

		 $hex1= {44??6f??63??75??6d??65??6e??74??53??75??6d??6d??61??72??79??49??6e??66??6f??72??6d??61??74??69??6f??6e??0a??}
		 $hex2= {50??72??6f??6a??65??63??74??2e??4e??4c??4d??50??47??41??4e??41??54??6d??59??51??2e??41??75??74??6f??4f??70??65??6e??0a??}

	condition:
		2 of them
}
