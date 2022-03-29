
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_OlympicDestroyer 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_OlympicDestroyer {
	meta: 
		 description= "APT_Sample_OlympicDestroyer Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-49-49" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ca0eaca077aa67f2609f612cefe7f1f3"
		 hash2= "cfdd16225e67471f5ef54cab9b3a5558"
		 hash3= "d9c37b937ffde812ae15de885913e101"
		 hash4= "ec724ef33521c4c2965de078e36c8277"

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
		 $s10= "del %programdata%evtchk.txt" fullword wide
		 $s11= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s12= "SeDebugPrivilege" fullword wide

		 $hex1= {53??65??44??65??62??75??67??50??72??69??76??69??6c??65??67??65??0a??}
		 $hex2= {61??70??69??2d??6d??73??2d??77??69??6e??2d??61??70??70??6d??6f??64??65??6c??2d??72??75??6e??74??69??6d??65??2d??6c??31??}
		 $hex3= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??64??61??74??65??74??69??6d??65??2d??6c??31??2d??31??2d??}
		 $hex4= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??62??65??72??73??2d??6c??31??2d??31??2d??31??0a??}
		 $hex5= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??6c??65??2d??6c??32??2d??31??2d??31??0a??}
		 $hex6= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??74??72??69??6e??67??2d??6c??31??2d??31??2d??30??0a??}
		 $hex7= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??6e??63??68??2d??6c??31??2d??32??2d??30??0a??}
		 $hex8= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??73??69??6e??66??6f??2d??6c??31??2d??32??2d??31??}
		 $hex9= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??77??69??6e??72??74??2d??6c??31??2d??31??2d??30??0a??}
		 $hex10= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??78??73??74??61??74??65??2d??6c??32??2d??31??2d??30??0a??}
		 $hex11= {64??65??6c??20??25??70??72??6f??67??72??61??6d??64??61??74??61??25??65??76??74??63??68??6b??2e??74??78??74??0a??}
		 $hex12= {65??78??74??2d??6d??73??2d??77??69??6e??2d??6e??74??75??73??65??72??2d??64??69??61??6c??6f??67??62??6f??78??2d??6c??31??}

	condition:
		13 of them
}
