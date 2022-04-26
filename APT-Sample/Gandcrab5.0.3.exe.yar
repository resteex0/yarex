
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_GandCrab_Gandcrab5_0_3_exe 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_GandCrab_Gandcrab5_0_3_exe {
	meta: 
		 description= "APT_Sample_GandCrab_Gandcrab5_0_3_exe Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-22-57" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "95557a29de4b70a25ce62a03472be684"

	strings:

	
 		 $s1= "&About XTokenStringTest..." fullword wide
		 $s2= "About XTokenStringTest" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "Token delimiter(s):" fullword wide
		 $s6= "Trim whitespace" fullword wide
		 $s7= "VS_VERSION_INFO" fullword wide
		 $s8= "www.sopcast.com" fullword wide
		 $s9= "XTokenStringTest" fullword wide

		 $hex1= {26??41??62??6f??75??74??20??58??54??6f??6b??65??6e??53??74??72??69??6e??67??54??65??73??74??2e??2e??2e??0a??}
		 $hex2= {41??62??6f??75??74??20??58??54??6f??6b??65??6e??53??74??72??69??6e??67??54??65??73??74??0a??}
		 $hex3= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex4= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex5= {54??6f??6b??65??6e??20??64??65??6c??69??6d??69??74??65??72??28??73??29??3a??0a??}
		 $hex6= {54??72??69??6d??20??77??68??69??74??65??73??70??61??63??65??0a??}
		 $hex7= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}
		 $hex8= {58??54??6f??6b??65??6e??53??74??72??69??6e??67??54??65??73??74??0a??}
		 $hex9= {77??77??77??2e??73??6f??70??63??61??73??74??2e??63??6f??6d??0a??}

	condition:
		10 of them
}
