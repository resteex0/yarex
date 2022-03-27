
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_GoziGroup 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_GoziGroup {
	meta: 
		 description= "APT_Sample_GoziGroup Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-27_12-27-47" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "531bfea83204df3fab21f07a9751bcb7"
		 hash2= "68c00c7706169601ead8a0383a812525"
		 hash3= "7137532f7c07b66b72b5873a1929db34"
		 hash4= "ead038e42b00e08e4293917e00d40e75"
		 hash5= "f947d58595fc0567fb9bfa3c7f609ebc"

	strings:

	
 		 $s1= "11.00.9600.16428 (wr2_df.121013" fullword wide
		 $s2= "11.00.9600.16429" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide
		 $s6= "Windows Cryptographic" fullword wide

		 $hex1= {31??31??2e??30??30??2e??39??36??30??30??2e??31??36??34??32??38??20??28??77??72??32??5f??64??66??2e??31??32??31??30??31??}
		 $hex2= {31??31??2e??30??30??2e??39??36??30??30??2e??31??36??34??32??39??0a??}
		 $hex3= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex4= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex5= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}
		 $hex6= {57??69??6e??64??6f??77??73??20??43??72??79??70??74??6f??67??72??61??70??68??69??63??0a??}

	condition:
		6 of them
}
