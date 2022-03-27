
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_DoquAPT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_DoquAPT {
	meta: 
		 description= "APT_Sample_DoquAPT Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-27_12-27-06" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "e8eaec1f021a564b82b824af1dbe6c4d"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "LegalTrademarks" fullword wide
		 $s3= "OriginalFilename" fullword wide
		 $s4= "Process Explorer" fullword wide
		 $s5= "Sysinternals installer" fullword wide
		 $s6= "VS_VERSION_INFO" fullword wide

		 $hex1= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex2= {4c??65??67??61??6c??54??72??61??64??65??6d??61??72??6b??73??0a??}
		 $hex3= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex4= {50??72??6f??63??65??73??73??20??45??78??70??6c??6f??72??65??72??0a??}
		 $hex5= {53??79??73??69??6e??74??65??72??6e??61??6c??73??20??69??6e??73??74??61??6c??6c??65??72??0a??}
		 $hex6= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}

	condition:
		6 of them
}
