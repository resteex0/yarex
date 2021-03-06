
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_MuddyWaterAPT_shakva_lb_doc_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_MuddyWaterAPT_shakva_lb_doc_bin {
	meta: 
		 description= "APT_Sample_MuddyWaterAPT_shakva_lb_doc_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-26-34" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0cf25597343240f88358c694d7ae7e0a"

	strings:

	
 		 $s1= "(1Normal.ThisDocument" fullword wide
		 $s2= "DocumentSummaryInformation" fullword wide
		 $s3= "SummaryInformation" fullword wide

		 $hex1= {28??31??4e??6f??72??6d??61??6c??2e??54??68??69??73??44??6f??63??75??6d??65??6e??74??0a??}
		 $hex2= {44??6f??63??75??6d??65??6e??74??53??75??6d??6d??61??72??79??49??6e??66??6f??72??6d??61??74??69??6f??6e??0a??}
		 $hex3= {53??75??6d??6d??61??72??79??49??6e??66??6f??72??6d??61??74??69??6f??6e??0a??}

	condition:
		3 of them
}
