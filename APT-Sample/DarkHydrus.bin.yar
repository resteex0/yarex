
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_DarkHydrus_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_DarkHydrus_bin {
	meta: 
		 description= "APT_Sample_DarkHydrus_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-39-42" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "21e9451af7c59a4a136f4046d036352a"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "VS_VERSION_INFO" fullword wide

		 $hex1= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex2= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}

	condition:
		2 of them
}
