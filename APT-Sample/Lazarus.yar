
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Lazarus 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Lazarus {
	meta: 
		 description= "APT_Sample_Lazarus Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_02-22-36" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "4f6b0be2dbd49871ff32e8388b011d90"
		 hash2= "5f9a6b47e1d2f0ad1494504398877c10"
		 hash3= "86c314bc2dc37ba84f7364acd5108c2b"
		 hash4= "9ce9a0b3876aacbf0e8023c97fd0a21d"

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
		 $s10= "CelasTradePro.pk" fullword wide
		 $s11= "CelasTradePro.pkg" fullword wide
		 $s12= "com.apple.cs.CodeDirectory" fullword wide
		 $s13= "com.apple.cs.CodeRequirements" fullword wide
		 $s14= "com.apple.cs.CodeRequirements-1" fullword wide
		 $s15= "com.apple.cs.CodeSignature" fullword wide
		 $s16= "com.apple.lastuseddate#PS" fullword wide
		 $s17= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s18= ".journal_info_block" fullword wide
		 $s19= "SeDebugPrivilege" fullword wide
		 $s20= "System32cmd.exe" fullword wide

		 $hex1= {2e??6a??6f??75??72??6e??61??6c??5f??69??6e??66??6f??5f??62??6c??6f??63??6b??0a??}
		 $hex2= {43??65??6c??61??73??54??72??61??64??65??50??72??6f??2e??70??6b??0a??}
		 $hex3= {43??65??6c??61??73??54??72??61??64??65??50??72??6f??2e??70??6b??67??0a??}
		 $hex4= {53??65??44??65??62??75??67??50??72??69??76??69??6c??65??67??65??0a??}
		 $hex5= {53??79??73??74??65??6d??33??32??63??6d??64??2e??65??78??65??0a??}
		 $hex6= {61??70??69??2d??6d??73??2d??77??69??6e??2d??61??70??70??6d??6f??64??65??6c??2d??72??75??6e??74??69??6d??65??2d??6c??31??}
		 $hex7= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??64??61??74??65??74??69??6d??65??2d??6c??31??2d??31??2d??}
		 $hex8= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??62??65??72??73??2d??6c??31??2d??31??2d??31??0a??}
		 $hex9= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??6c??65??2d??6c??32??2d??31??2d??31??0a??}
		 $hex10= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??74??72??69??6e??67??2d??6c??31??2d??31??2d??30??0a??}
		 $hex11= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??6e??63??68??2d??6c??31??2d??32??2d??30??0a??}
		 $hex12= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??73??69??6e??66??6f??2d??6c??31??2d??32??2d??31??}
		 $hex13= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??77??69??6e??72??74??2d??6c??31??2d??31??2d??30??0a??}
		 $hex14= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??78??73??74??61??74??65??2d??6c??32??2d??31??2d??30??0a??}
		 $hex15= {63??6f??6d??2e??61??70??70??6c??65??2e??63??73??2e??43??6f??64??65??44??69??72??65??63??74??6f??72??79??0a??}
		 $hex16= {63??6f??6d??2e??61??70??70??6c??65??2e??63??73??2e??43??6f??64??65??52??65??71??75??69??72??65??6d??65??6e??74??73??0a??}
		 $hex17= {63??6f??6d??2e??61??70??70??6c??65??2e??63??73??2e??43??6f??64??65??52??65??71??75??69??72??65??6d??65??6e??74??73??2d??}
		 $hex18= {63??6f??6d??2e??61??70??70??6c??65??2e??63??73??2e??43??6f??64??65??53??69??67??6e??61??74??75??72??65??0a??}
		 $hex19= {63??6f??6d??2e??61??70??70??6c??65??2e??6c??61??73??74??75??73??65??64??64??61??74??65??23??50??53??0a??}
		 $hex20= {65??78??74??2d??6d??73??2d??77??69??6e??2d??6e??74??75??73??65??72??2d??64??69??61??6c??6f??67??62??6f??78??2d??6c??31??}

	condition:
		22 of them
}
