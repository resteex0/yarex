
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_DPRK_DLL#1_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_DPRK_DLL#1_bin {
	meta: 
		 description= "APT_Sample_DPRK_DLL#1_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-22-32" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "e86c2f4fc88918246bf697b6a404c3ea"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "LegalTrademarks" fullword wide
		 $s3= "Microsoft Corporation" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide

		 $hex1= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex2= {4c??65??67??61??6c??54??72??61??64??65??6d??61??72??6b??73??0a??}
		 $hex3= {4d??69??63??72??6f??73??6f??66??74??20??43??6f??72??70??6f??72??61??74??69??6f??6e??0a??}
		 $hex4= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex5= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}

	condition:
		5 of them
}
