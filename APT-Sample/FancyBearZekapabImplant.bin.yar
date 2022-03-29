
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_FancyBearZekapabImplant_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_FancyBearZekapabImplant_bin {
	meta: 
		 description= "APT_Sample_FancyBearZekapabImplant_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-38-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "d1755976a6f7e1cbf21132ac4fdcf553"

	strings:

	
 		 $s1= "Access violation" fullword wide
		 $s2= "Assertion failed" fullword wide
		 $s3= "August September" fullword wide
		 $s4= "Connection refused." fullword wide
		 $s5= "Enhanced Metafiles" fullword wide
		 $s6= "FileDescription" fullword wide
		 $s7= "Host unreachable." fullword wide
		 $s8= "Invalid argument" fullword wide
		 $s9= "Invalid argument." fullword wide
		 $s10= "Invalid filename" fullword wide
		 $s11= "Invalid ImageList" fullword wide
		 $s12= "IPv6 unavailable" fullword wide
		 $s13= "LegalTrademarks" fullword wide
		 $s14= "Network unreachable." fullword wide
		 $s15= "OriginalFilename" fullword wide
		 $s16= "Protection Storage" fullword wide
		 $s17= "Protection Technologies" fullword wide
		 $s18= "Tuesday Wednesday" fullword wide
		 $s19= "Unsupported operation." fullword wide
		 $s20= "Variant overflow" fullword wide

		 $hex1= {41??63??63??65??73??73??20??76??69??6f??6c??61??74??69??6f??6e??0a??}
		 $hex2= {41??73??73??65??72??74??69??6f??6e??20??66??61??69??6c??65??64??0a??}
		 $hex3= {41??75??67??75??73??74??20??53??65??70??74??65??6d??62??65??72??0a??}
		 $hex4= {43??6f??6e??6e??65??63??74??69??6f??6e??20??72??65??66??75??73??65??64??2e??0a??}
		 $hex5= {45??6e??68??61??6e??63??65??64??20??4d??65??74??61??66??69??6c??65??73??0a??}
		 $hex6= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex7= {48??6f??73??74??20??75??6e??72??65??61??63??68??61??62??6c??65??2e??0a??}
		 $hex8= {49??50??76??36??20??75??6e??61??76??61??69??6c??61??62??6c??65??0a??}
		 $hex9= {49??6e??76??61??6c??69??64??20??49??6d??61??67??65??4c??69??73??74??0a??}
		 $hex10= {49??6e??76??61??6c??69??64??20??61??72??67??75??6d??65??6e??74??0a??}
		 $hex11= {49??6e??76??61??6c??69??64??20??61??72??67??75??6d??65??6e??74??2e??0a??}
		 $hex12= {49??6e??76??61??6c??69??64??20??66??69??6c??65??6e??61??6d??65??0a??}
		 $hex13= {4c??65??67??61??6c??54??72??61??64??65??6d??61??72??6b??73??0a??}
		 $hex14= {4e??65??74??77??6f??72??6b??20??75??6e??72??65??61??63??68??61??62??6c??65??2e??0a??}
		 $hex15= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex16= {50??72??6f??74??65??63??74??69??6f??6e??20??53??74??6f??72??61??67??65??0a??}
		 $hex17= {50??72??6f??74??65??63??74??69??6f??6e??20??54??65??63??68??6e??6f??6c??6f??67??69??65??73??0a??}
		 $hex18= {54??75??65??73??64??61??79??20??57??65??64??6e??65??73??64??61??79??0a??}
		 $hex19= {55??6e??73??75??70??70??6f??72??74??65??64??20??6f??70??65??72??61??74??69??6f??6e??2e??0a??}
		 $hex20= {56??61??72??69??61??6e??74??20??6f??76??65??72??66??6c??6f??77??0a??}

	condition:
		22 of them
}
