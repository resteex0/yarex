
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Trojans 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Trojans {
	meta: 
		 description= "APT_Sample_Trojans Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-50-00" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "22de52ac8f1e5c5c9741c606a352dc21"
		 hash2= "38634ac90a7a6cc51024fc9e81facddd"
		 hash3= "548a63e9162fbe13dda1dcda1ffda2b6"
		 hash4= "5d455f154ee0a74c1315d4a84b9b5505"
		 hash5= "9319231e507d66161a60eacc23958923"
		 hash6= "fb2ca93f987313108abdd4a6d687783a"

	strings:

	
 		 $s1= "!$).056;>ACENQV[_`eimuz" fullword wide
		 $s2= "255.255.255.255" fullword wide
		 $s3= "%4d%02d%02d%02d%02d%02d" fullword wide
		 $s4= "9de81469-550d-bd" fullword wide
		 $s5= "ADLIBUNREGISTER" fullword wide
		 $s6= "allOyMANYCUTS allOyMANYCUTS" fullword wide
		 $s7= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s8= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s9= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s10= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s11= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s12= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s13= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s14= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s15= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s16= "APPDATACOMMONDIR" fullword wide
		 $s17= "Assembly Version" fullword wide
		 $s18= "attitudinizing5" fullword wide
		 $s19= "/AutoIt3ExecuteLine" fullword wide
		 $s20= "/AutoIt3ExecuteScript" fullword wide

		 $hex1= {21??24??29??2e??30??35??36??3b??3e??41??43??45??4e??51??56??5b??5f??60??65??69??6d??75??7a??0a??}
		 $hex2= {25??34??64??25??30??32??64??25??30??32??64??25??30??32??64??25??30??32??64??25??30??32??64??0a??}
		 $hex3= {2f??41??75??74??6f??49??74??33??45??78??65??63??75??74??65??4c??69??6e??65??0a??}
		 $hex4= {2f??41??75??74??6f??49??74??33??45??78??65??63??75??74??65??53??63??72??69??70??74??0a??}
		 $hex5= {32??35??35??2e??32??35??35??2e??32??35??35??2e??32??35??35??0a??}
		 $hex6= {39??64??65??38??31??34??36??39??2d??35??35??30??64??2d??62??64??0a??}
		 $hex7= {41??44??4c??49??42??55??4e??52??45??47??49??53??54??45??52??0a??}
		 $hex8= {41??50??50??44??41??54??41??43??4f??4d??4d??4f??4e??44??49??52??0a??}
		 $hex9= {41??73??73??65??6d??62??6c??79??20??56??65??72??73??69??6f??6e??0a??}
		 $hex10= {61??6c??6c??4f??79??4d??41??4e??59??43??55??54??53??20??61??6c??6c??4f??79??4d??41??4e??59??43??55??54??53??0a??}
		 $hex11= {61??70??69??2d??6d??73??2d??77??69??6e??2d??61??70??70??6d??6f??64??65??6c??2d??72??75??6e??74??69??6d??65??2d??6c??31??}
		 $hex12= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??64??61??74??65??74??69??6d??65??2d??6c??31??2d??31??2d??}
		 $hex13= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??62??65??72??73??2d??6c??31??2d??31??2d??31??0a??}
		 $hex14= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??6c??65??2d??6c??32??2d??31??2d??31??0a??}
		 $hex15= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??74??72??69??6e??67??2d??6c??31??2d??31??2d??30??0a??}
		 $hex16= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??6e??63??68??2d??6c??31??2d??32??2d??30??0a??}
		 $hex17= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??73??69??6e??66??6f??2d??6c??31??2d??32??2d??31??}
		 $hex18= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??77??69??6e??72??74??2d??6c??31??2d??31??2d??30??0a??}
		 $hex19= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??78??73??74??61??74??65??2d??6c??32??2d??31??2d??30??0a??}
		 $hex20= {61??74??74??69??74??75??64??69??6e??69??7a??69??6e??67??35??0a??}

	condition:
		22 of them
}
