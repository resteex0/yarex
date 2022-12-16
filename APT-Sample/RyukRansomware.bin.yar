
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Lazarus_RyukRansomware_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Lazarus_RyukRansomware_bin {
	meta: 
		 description= "APT_Sample_Lazarus_RyukRansomware_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-24-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "86c314bc2dc37ba84f7364acd5108c2b"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s5= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s6= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s7= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s8= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s9= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s10= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s11= "SeDebugPrivilege" fullword wide
		 $s12= "System32cmd.exe" fullword wide
		 $s13= "UNIQUE_ID_DO_NOT_REMOVE" fullword wide
		 $s14= "usersPublicfinish" fullword wide
		 $s15= "usersPublicsys" fullword wide

		 $hex1= {53??65??44??65??62??75??67??50??72??69??76??69??6c??65??67??65??0a??}
		 $hex2= {53??79??73??74??65??6d??33??32??63??6d??64??2e??65??78??65??0a??}
		 $hex3= {55??4e??49??51??55??45??5f??49??44??5f??44??4f??5f??4e??4f??54??5f??52??45??4d??4f??56??45??0a??}
		 $hex4= {61??70??69??2d??6d??73??2d??77??69??6e??2d??61??70??70??6d??6f??64??65??6c??2d??72??75??6e??74??69??6d??65??2d??6c??31??}
		 $hex5= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??64??61??74??65??74??69??6d??65??2d??6c??31??2d??31??2d??}
		 $hex6= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??62??65??72??73??2d??6c??31??2d??31??2d??31??0a??}
		 $hex7= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??6c??65??2d??6c??32??2d??31??2d??31??0a??}
		 $hex8= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??74??72??69??6e??67??2d??6c??31??2d??31??2d??30??0a??}
		 $hex9= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??6e??63??68??2d??6c??31??2d??32??2d??30??0a??}
		 $hex10= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??73??69??6e??66??6f??2d??6c??31??2d??32??2d??31??}
		 $hex11= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??77??69??6e??72??74??2d??6c??31??2d??31??2d??30??0a??}
		 $hex12= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??78??73??74??61??74??65??2d??6c??32??2d??31??2d??30??0a??}
		 $hex13= {65??78??74??2d??6d??73??2d??77??69??6e??2d??6e??74??75??73??65??72??2d??64??69??61??6c??6f??67??62??6f??78??2d??6c??31??}
		 $hex14= {75??73??65??72??73??50??75??62??6c??69??63??66??69??6e??69??73??68??0a??}
		 $hex15= {75??73??65??72??73??50??75??62??6c??69??63??73??79??73??0a??}

	condition:
		16 of them
}