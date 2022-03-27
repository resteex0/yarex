
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_GandCrab 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_GandCrab {
	meta: 
		 description= "APT_Sample_GandCrab Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-27_09-57-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0301296543c91492d49847ae636857a4"
		 hash2= "2d351d67eab01124b7189c02cff7595f"
		 hash3= "41c673415dabbfa63905ff273bdc34e9"
		 hash4= "700a4f7ed40dd9ac29891c2ec3d4bef7"
		 hash5= "7a1c3b29dd8088985e2b9a329315d5d0"
		 hash6= "95557a29de4b70a25ce62a03472be684"
		 hash7= "97a449fed7d800a8a635592605ff8a67"
		 hash8= "c805528f6844d7caf5793c025b56f67d"
		 hash9= "de030d9ae03c9a8d2bee41c0df01ee4d"

	strings:

	
 		 $s1= "&About XTokenStringTest..." fullword wide
		 $s2= "agntsvc.exeisqlplussvc.exe" fullword wide
		 $s3= "america-height-level-copy-half-four^" fullword wide
		 $s4= "best`nothing`save`area`sort`cloud>" fullword wide
		 $s5= "Content-Type: multipart/form-data" fullword wide
		 $s6= "Control PanelInternational" fullword wide
		 $s7= "GlobalXlAKFoxSKGOfSGOoSFOOFNOLPE" fullword wide
		 $s8= "HARDWAREDESCRIPTIONSystemCentralProcessor0" fullword wide
		 $s9= "PCI-X PC-98/C20 PC-98/C24" fullword wide
		 $s10= "SOFTWAREMicrosoftWindows NTCurrentVersion" fullword wide
		 $s11= "SOFTWAREWow6432NodeMicrosoftWindows NTCurrentVersion" fullword wide
		 $s12= "sorry.fire.below.four.strike.firm]" fullword wide
		 $s13= "SYSTEMCurrentControlSetservicesTcpipParameters" fullword wide
		 $s14= "weather/thirteen/lose/office/while/india." fullword wide
		 $s15= "xContent-Type: multipart/form-data" fullword wide
		 $a1= "SystemCurrentControlSetServicesMIT KerberosNetworkProvider" fullword ascii

		 $hex1= {26??41??62??6f??75??74??20??58??54??6f??6b??65??6e??53??74??72??69??6e??67??54??65??73??74??2e??2e??2e??0a??}
		 $hex2= {43??6f??6e??74??65??6e??74??2d??54??79??70??65??3a??20??6d??75??6c??74??69??70??61??72??74??2f??66??6f??72??6d??2d??64??}
		 $hex3= {43??6f??6e??74??72??6f??6c??20??50??61??6e??65??6c??49??6e??74??65??72??6e??61??74??69??6f??6e??61??6c??0a??}
		 $hex4= {47??6c??6f??62??61??6c??58??6c??41??4b??46??6f??78??53??4b??47??4f??66??53??47??4f??6f??53??46??4f??4f??46??4e??4f??4c??}
		 $hex5= {48??41??52??44??57??41??52??45??44??45??53??43??52??49??50??54??49??4f??4e??53??79??73??74??65??6d??43??65??6e??74??72??}
		 $hex6= {50??43??49??2d??58??20??50??43??2d??39??38??2f??43??32??30??20??50??43??2d??39??38??2f??43??32??34??0a??}
		 $hex7= {53??4f??46??54??57??41??52??45??4d??69??63??72??6f??73??6f??66??74??57??69??6e??64??6f??77??73??20??4e??54??43??75??72??}
		 $hex8= {53??4f??46??54??57??41??52??45??57??6f??77??36??34??33??32??4e??6f??64??65??4d??69??63??72??6f??73??6f??66??74??57??69??}
		 $hex9= {53??59??53??54??45??4d??43??75??72??72??65??6e??74??43??6f??6e??74??72??6f??6c??53??65??74??73??65??72??76??69??63??65??}
		 $hex10= {53??79??73??74??65??6d??43??75??72??72??65??6e??74??43??6f??6e??74??72??6f??6c??53??65??74??53??65??72??76??69??63??65??}
		 $hex11= {61??67??6e??74??73??76??63??2e??65??78??65??69??73??71??6c??70??6c??75??73??73??76??63??2e??65??78??65??0a??}
		 $hex12= {61??6d??65??72??69??63??61??2d??68??65??69??67??68??74??2d??6c??65??76??65??6c??2d??63??6f??70??79??2d??68??61??6c??66??}
		 $hex13= {62??65??73??74??60??6e??6f??74??68??69??6e??67??60??73??61??76??65??60??61??72??65??61??60??73??6f??72??74??60??63??6c??}
		 $hex14= {73??6f??72??72??79??2e??66??69??72??65??2e??62??65??6c??6f??77??2e??66??6f??75??72??2e??73??74??72??69??6b??65??2e??66??}
		 $hex15= {77??65??61??74??68??65??72??2f??74??68??69??72??74??65??65??6e??2f??6c??6f??73??65??2f??6f??66??66??69??63??65??2f??77??}
		 $hex16= {78??43??6f??6e??74??65??6e??74??2d??54??79??70??65??3a??20??6d??75??6c??74??69??70??61??72??74??2f??66??6f??72??6d??2d??}

	condition:
		17 of them
}
