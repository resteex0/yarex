
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_GamaredonGroup_GamaredonImplant_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_GamaredonGroup_GamaredonImplant_bin {
	meta: 
		 description= "APT_Sample_GamaredonGroup_GamaredonImplant_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-20-25" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "c7bda65e820338a42a02eb0c1e20d961"

	strings:

	
 		 $s1= "@7zSfxFolder%02d" fullword wide
		 $s2= "BeginPromptTimeout" fullword wide
		 $s3= "CommonDocuments" fullword wide
		 $s4= "ExecuteParameters" fullword wide
		 $s5= "ExtractCancelText" fullword wide
		 $s6= "ExtractDialogText" fullword wide
		 $s7= "ExtractDialogWidth" fullword wide
		 $s8= "ExtractPathText" fullword wide
		 $s9= "ExtractPathTitle" fullword wide
		 $s10= "ExtractPathWidth" fullword wide
		 $s11= "FileDescription" fullword wide
		 $s12= "msctls_progress32" fullword wide
		 $s13= "OriginalFilename" fullword wide
		 $s14= "VS_VERSION_INFO" fullword wide

		 $hex1= {40??37??7a??53??66??78??46??6f??6c??64??65??72??25??30??32??64??0a??}
		 $hex2= {42??65??67??69??6e??50??72??6f??6d??70??74??54??69??6d??65??6f??75??74??0a??}
		 $hex3= {43??6f??6d??6d??6f??6e??44??6f??63??75??6d??65??6e??74??73??0a??}
		 $hex4= {45??78??65??63??75??74??65??50??61??72??61??6d??65??74??65??72??73??0a??}
		 $hex5= {45??78??74??72??61??63??74??43??61??6e??63??65??6c??54??65??78??74??0a??}
		 $hex6= {45??78??74??72??61??63??74??44??69??61??6c??6f??67??54??65??78??74??0a??}
		 $hex7= {45??78??74??72??61??63??74??44??69??61??6c??6f??67??57??69??64??74??68??0a??}
		 $hex8= {45??78??74??72??61??63??74??50??61??74??68??54??65??78??74??0a??}
		 $hex9= {45??78??74??72??61??63??74??50??61??74??68??54??69??74??6c??65??0a??}
		 $hex10= {45??78??74??72??61??63??74??50??61??74??68??57??69??64??74??68??0a??}
		 $hex11= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex12= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex13= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}
		 $hex14= {6d??73??63??74??6c??73??5f??70??72??6f??67??72??65??73??73??33??32??0a??}

	condition:
		15 of them
}
