
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Turla_TurlaAgent_exe 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Turla_TurlaAgent_exe {
	meta: 
		 description= "APT_Sample_Turla_TurlaAgent_exe Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-20-49" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "a352f93e5f63bbf5cd0905c38f054d27"

	strings:

	
 		 $s1= "%02d:%02d:%04d %02d:%02d:%02d" fullword wide
		 $s2= "/AppendLog>" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "Infecting level" fullword wide
		 $s5= "Microsoft Corporation" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= "Processing volumes" fullword wide
		 $s8= "/TVer>" fullword wide
		 $s9= "VS_VERSION_INFO" fullword wide

		 $hex1= {25??30??32??64??3a??25??30??32??64??3a??25??30??34??64??20??25??30??32??64??3a??25??30??32??64??3a??25??30??32??64??0a??}
		 $hex2= {2f??41??70??70??65??6e??64??4c??6f??67??3e??0a??}
		 $hex3= {2f??54??56??65??72??3e??0a??}
		 $hex4= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex5= {49??6e??66??65??63??74??69??6e??67??20??6c??65??76??65??6c??0a??}
		 $hex6= {4d??69??63??72??6f??73??6f??66??74??20??43??6f??72??70??6f??72??61??74??69??6f??6e??0a??}
		 $hex7= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex8= {50??72??6f??63??65??73??73??69??6e??67??20??76??6f??6c??75??6d??65??73??0a??}
		 $hex9= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}

	condition:
		10 of them
}
