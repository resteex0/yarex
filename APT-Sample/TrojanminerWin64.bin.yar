
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_TrojanminerWin64_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_TrojanminerWin64_bin {
	meta: 
		 description= "APT_Sample_TrojanminerWin64_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-40-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "fbfe67defe5443cbdc89dee20fbad068"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s2= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s5= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s6= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s7= "api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s8= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s9= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s10= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s11= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s12= "FileDescription" fullword wide
		 $s13= "Microsoft Corporation" fullword wide
		 $s14= "OriginalFilename" fullword wide
		 $s15= "SeLockMemoryPrivilege" fullword wide
		 $s16= "VS_VERSION_INFO" fullword wide

		 $hex1= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex2= {4d??69??63??72??6f??73??6f??66??74??20??43??6f??72??70??6f??72??61??74??69??6f??6e??0a??}
		 $hex3= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex4= {53??65??4c??6f??63??6b??4d??65??6d??6f??72??79??50??72??69??76??69??6c??65??67??65??0a??}
		 $hex5= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}
		 $hex6= {61??70??69??2d??6d??73??2d??77??69??6e??2d??61??70??70??6d??6f??64??65??6c??2d??72??75??6e??74??69??6d??65??2d??6c??31??}
		 $hex7= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??64??61??74??65??74??69??6d??65??2d??6c??31??2d??31??2d??}
		 $hex8= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??62??65??72??73??2d??6c??31??2d??31??2d??31??0a??}
		 $hex9= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??6c??65??2d??6c??31??2d??32??2d??32??0a??}
		 $hex10= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??74??72??69??6e??67??2d??6c??31??2d??31??2d??30??0a??}
		 $hex11= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??6e??63??68??2d??6c??31??2d??32??2d??30??0a??}
		 $hex12= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??6e??63??68??2d??6c??31??2d??32??2d??30??2e??64??}
		 $hex13= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??73??69??6e??66??6f??2d??6c??31??2d??32??2d??31??}
		 $hex14= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??77??69??6e??72??74??2d??6c??31??2d??31??2d??30??0a??}
		 $hex15= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??78??73??74??61??74??65??2d??6c??32??2d??31??2d??30??0a??}
		 $hex16= {65??78??74??2d??6d??73??2d??77??69??6e??2d??6e??74??75??73??65??72??2d??64??69??61??6c??6f??67??62??6f??78??2d??6c??31??}

	condition:
		17 of them
}
