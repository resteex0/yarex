
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_APT28_Xagent64_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_APT28_Xagent64_bin {
	meta: 
		 description= "APT_Sample_APT28_Xagent64_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-22-13" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "cc9e6578a47182a941a478b276320e06"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "OriginalFilename" fullword wide
		 $s3= "unsuccess&nbsp:&nbsp" fullword wide
		 $s4= "VS_VERSION_INFO" fullword wide

		 $hex1= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex2= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex3= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}
		 $hex4= {75??6e??73??75??63??63??65??73??73??26??6e??62??73??70??3a??26??6e??62??73??70??0a??}

	condition:
		4 of them
}