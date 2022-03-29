
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_AudioSes_dll 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_AudioSes_dll {
	meta: 
		 description= "APT_Sample_AudioSes_dll Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-41-04" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "16bbc967a8b6a365871a05c74a4f345b"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "OriginalFilename" fullword wide
		 $s3= "VS_VERSION_INFO" fullword wide

		 $hex1= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex2= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex3= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}

	condition:
		3 of them
}
