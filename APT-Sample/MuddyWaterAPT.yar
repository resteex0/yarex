
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_MuddyWaterAPT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_MuddyWaterAPT {
	meta: 
		 description= "APT_Sample_MuddyWaterAPT Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_02-23-48" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0cf25597343240f88358c694d7ae7e0a"
		 hash2= "5b5b3cb0948ee56ea761ed31d53c29ad"
		 hash3= "ca9230a54f40a6a0fe52d7379459189c"

	strings:

	
 		 $s1= "084118118120134134105085098096" fullword wide
		 $s2= "088129119051102136117" fullword wide
		 $s3= "102136117051120059060" fullword wide
		 $s4= "105124134124117127120" fullword wide
		 $s5= "106130133126117130130126134" fullword wide
		 $s6= "(1Normal.ThisDocument" fullword wide
		 $s7= "(1Normal.ThisDocument " fullword wide
		 $s8= "DocumentSummaryInformation" fullword wide
		 $s9= "SummaryInformation" fullword wide

		 $hex1= {28??31??4e??6f??72??6d??61??6c??2e??54??68??69??73??44??6f??63??75??6d??65??6e??74??0a??}
		 $hex2= {30??38??34??31??31??38??31??31??38??31??32??30??31??33??34??31??33??34??31??30??35??30??38??35??30??39??38??30??39??36??}
		 $hex3= {30??38??38??31??32??39??31??31??39??30??35??31??31??30??32??31??33??36??31??31??37??0a??}
		 $hex4= {31??30??32??31??33??36??31??31??37??30??35??31??31??32??30??30??35??39??30??36??30??0a??}
		 $hex5= {31??30??35??31??32??34??31??33??34??31??32??34??31??31??37??31??32??37??31??32??30??0a??}
		 $hex6= {31??30??36??31??33??30??31??33??33??31??32??36??31??31??37??31??33??30??31??33??30??31??32??36??31??33??34??0a??}
		 $hex7= {44??6f??63??75??6d??65??6e??74??53??75??6d??6d??61??72??79??49??6e??66??6f??72??6d??61??74??69??6f??6e??0a??}
		 $hex8= {53??75??6d??6d??61??72??79??49??6e??66??6f??72??6d??61??74??69??6f??6e??0a??}

	condition:
		9 of them
}
