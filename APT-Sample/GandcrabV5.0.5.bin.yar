
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_GandCrab_GandcrabV5_0_5_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_GandCrab_GandcrabV5_0_5_bin {
	meta: 
		 description= "APT_Sample_GandCrab_GandcrabV5_0_5_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-22-58" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "c805528f6844d7caf5793c025b56f67d"

	strings:

	
 		 $s1= "agntsvc.exeagntsvc.exe" fullword wide
		 $s2= "agntsvc.exeencsvc.exe" fullword wide
		 $s3= "agntsvc.exeisqlplussvc.exe" fullword wide
		 $s4= "Content-Type: multipart/form-data" fullword wide
		 $s5= "Control PanelInternational" fullword wide
		 $s6= "CRAB-DECRYPT.txt" fullword wide
		 $s7= "firefoxconfig.exe" fullword wide
		 $s8= "GlobalXlAKFoxSKGOfSGOoSFOOFNOLPE" fullword wide
		 $s9= "Keyboard LayoutPreload" fullword wide
		 $s10= "KRAB-DECRYPT.html" fullword wide
		 $s11= "KRAB-DECRYPT.txt" fullword wide
		 $s12= "Local Settings" fullword wide
		 $s13= "mydesktopqos.exe" fullword wide
		 $s14= "mydesktopservice.exe" fullword wide
		 $s15= "NortonAntiBot.exe" fullword wide
		 $s16= "ProcessorNameString" fullword wide
		 $s17= "Program Files" fullword wide
		 $s18= "%s-DECRYPT.html" fullword wide
		 $s19= "%sKRAB-DECRYPT.txt" fullword wide
		 $s20= "SOFTWAREex_datadata" fullword wide

		 $hex1= {25??73??2d??44??45??43??52??59??50??54??2e??68??74??6d??6c??0a??}
		 $hex2= {25??73??4b??52??41??42??2d??44??45??43??52??59??50??54??2e??74??78??74??0a??}
		 $hex3= {43??52??41??42??2d??44??45??43??52??59??50??54??2e??74??78??74??0a??}
		 $hex4= {43??6f??6e??74??65??6e??74??2d??54??79??70??65??3a??20??6d??75??6c??74??69??70??61??72??74??2f??66??6f??72??6d??2d??64??}
		 $hex5= {43??6f??6e??74??72??6f??6c??20??50??61??6e??65??6c??49??6e??74??65??72??6e??61??74??69??6f??6e??61??6c??0a??}
		 $hex6= {47??6c??6f??62??61??6c??58??6c??41??4b??46??6f??78??53??4b??47??4f??66??53??47??4f??6f??53??46??4f??4f??46??4e??4f??4c??}
		 $hex7= {4b??52??41??42??2d??44??45??43??52??59??50??54??2e??68??74??6d??6c??0a??}
		 $hex8= {4b??52??41??42??2d??44??45??43??52??59??50??54??2e??74??78??74??0a??}
		 $hex9= {4b??65??79??62??6f??61??72??64??20??4c??61??79??6f??75??74??50??72??65??6c??6f??61??64??0a??}
		 $hex10= {4c??6f??63??61??6c??20??53??65??74??74??69??6e??67??73??0a??}
		 $hex11= {4e??6f??72??74??6f??6e??41??6e??74??69??42??6f??74??2e??65??78??65??0a??}
		 $hex12= {50??72??6f??63??65??73??73??6f??72??4e??61??6d??65??53??74??72??69??6e??67??0a??}
		 $hex13= {50??72??6f??67??72??61??6d??20??46??69??6c??65??73??0a??}
		 $hex14= {53??4f??46??54??57??41??52??45??65??78??5f??64??61??74??61??64??61??74??61??0a??}
		 $hex15= {61??67??6e??74??73??76??63??2e??65??78??65??61??67??6e??74??73??76??63??2e??65??78??65??0a??}
		 $hex16= {61??67??6e??74??73??76??63??2e??65??78??65??65??6e??63??73??76??63??2e??65??78??65??0a??}
		 $hex17= {61??67??6e??74??73??76??63??2e??65??78??65??69??73??71??6c??70??6c??75??73??73??76??63??2e??65??78??65??0a??}
		 $hex18= {66??69??72??65??66??6f??78??63??6f??6e??66??69??67??2e??65??78??65??0a??}
		 $hex19= {6d??79??64??65??73??6b??74??6f??70??71??6f??73??2e??65??78??65??0a??}
		 $hex20= {6d??79??64??65??73??6b??74??6f??70??73??65??72??76??69??63??65??2e??65??78??65??0a??}

	condition:
		22 of them
}
