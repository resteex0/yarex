
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_APT28_APT28wmsApplication_exe 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_APT28_APT28wmsApplication_exe {
	meta: 
		 description= "APT_Sample_APT28_APT28wmsApplication_exe Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-22-00" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "92b90b0208805daaa8ab45fa19d36b14"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "Microsoft Corp." fullword wide
		 $s3= "OriginalFilename" fullword wide
		 $s4= "VS_VERSION_INFO" fullword wide

		 $hex1= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex2= {4d??69??63??72??6f??73??6f??66??74??20??43??6f??72??70??2e??0a??}
		 $hex3= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex4= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}

	condition:
		4 of them
}