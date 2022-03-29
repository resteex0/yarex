
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_TheBigBangImplant_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_TheBigBangImplant_bin {
	meta: 
		 description= "APT_Sample_TheBigBangImplant_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-36-33" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "87d7d314f86f61a9099a51c269b4ec78"

	strings:

	
 		 $s1= "american english" fullword wide
		 $s2= "american-english" fullword wide
		 $s3= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s5= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s6= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s7= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s8= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s9= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s10= "Assertion failed!" fullword wide
		 $s11= "binMSPDB140.DLL" fullword wide
		 $s12= "chinese-hongkong" fullword wide
		 $s13= "chinese-simplified" fullword wide
		 $s14= "chinese-singapore" fullword wide
		 $s15= "chinese-traditional" fullword wide
		 $s16= "english-american" fullword wide
		 $s17= "english-caribbean" fullword wide
		 $s18= "english-jamaica" fullword wide
		 $s19= "english-south africa" fullword wide
		 $s20= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide

		 $hex1= {41??73??73??65??72??74??69??6f??6e??20??66??61??69??6c??65??64??21??0a??}
		 $hex2= {61??6d??65??72??69??63??61??6e??20??65??6e??67??6c??69??73??68??0a??}
		 $hex3= {61??6d??65??72??69??63??61??6e??2d??65??6e??67??6c??69??73??68??0a??}
		 $hex4= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??64??61??74??65??74??69??6d??65??2d??6c??31??2d??31??2d??}
		 $hex5= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??6c??65??2d??6c??32??2d??31??2d??31??0a??}
		 $hex6= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??74??72??69??6e??67??2d??6c??31??2d??31??2d??30??0a??}
		 $hex7= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??6e??63??68??2d??6c??31??2d??32??2d??30??0a??}
		 $hex8= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??73??69??6e??66??6f??2d??6c??31??2d??32??2d??31??}
		 $hex9= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??77??69??6e??72??74??2d??6c??31??2d??31??2d??30??0a??}
		 $hex10= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??78??73??74??61??74??65??2d??6c??32??2d??31??2d??30??0a??}
		 $hex11= {62??69??6e??4d??53??50??44??42??31??34??30??2e??44??4c??4c??0a??}
		 $hex12= {63??68??69??6e??65??73??65??2d??68??6f??6e??67??6b??6f??6e??67??0a??}
		 $hex13= {63??68??69??6e??65??73??65??2d??73??69??6d??70??6c??69??66??69??65??64??0a??}
		 $hex14= {63??68??69??6e??65??73??65??2d??73??69??6e??67??61??70??6f??72??65??0a??}
		 $hex15= {63??68??69??6e??65??73??65??2d??74??72??61??64??69??74??69??6f??6e??61??6c??0a??}
		 $hex16= {65??6e??67??6c??69??73??68??2d??61??6d??65??72??69??63??61??6e??0a??}
		 $hex17= {65??6e??67??6c??69??73??68??2d??63??61??72??69??62??62??65??61??6e??0a??}
		 $hex18= {65??6e??67??6c??69??73??68??2d??6a??61??6d??61??69??63??61??0a??}
		 $hex19= {65??6e??67??6c??69??73??68??2d??73??6f??75??74??68??20??61??66??72??69??63??61??0a??}
		 $hex20= {65??78??74??2d??6d??73??2d??77??69??6e??2d??6e??74??75??73??65??72??2d??64??69??61??6c??6f??67??62??6f??78??2d??6c??31??}

	condition:
		22 of them
}
