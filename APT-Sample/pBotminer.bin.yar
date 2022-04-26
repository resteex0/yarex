
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Coinminers_pBotminer_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Coinminers_pBotminer_bin {
	meta: 
		 description= "APT_Sample_Coinminers_pBotminer_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-24-16" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "a50ea10ce3e08bf5095c12503ccc5d95"

	strings:

	
 		 $s1= "255.255.255.255" fullword wide
		 $s2= "%4d%02d%02d%02d%02d%02d" fullword wide
		 $s3= "ADLIBUNREGISTER" fullword wide
		 $s4= "APPDATACOMMONDIR" fullword wide
		 $s5= "/AutoIt3ExecuteLine" fullword wide
		 $s6= "/AutoIt3ExecuteScript" fullword wide
		 $s7= "/AutoIt3OutputDebug" fullword wide
		 $s8= "AUTOITCALLVARIABLE%d" fullword wide
		 $s9= "AUTOITSETOPTION" fullword wide
		 $s10= "AUTOITWINGETTITLE" fullword wide
		 $s11= "AUTOITWINSETTITLE" fullword wide
		 $s12= "BROWSER_FAVORTIES" fullword wide
		 $s13= "BROWSER_FORWARD" fullword wide
		 $s14= "BROWSER_REFRESH" fullword wide
		 $s15= "#comments-start" fullword wide
		 $s16= "CONSOLEWRITEERROR" fullword wide
		 $s17= "CONTROLGETFOCUS" fullword wide
		 $s18= "CONTROLGETHANDLE" fullword wide
		 $s19= "CONTROLLISTVIEW" fullword wide
		 $s20= "Control PanelAppearance" fullword wide

		 $hex1= {23??63??6f??6d??6d??65??6e??74??73??2d??73??74??61??72??74??0a??}
		 $hex2= {25??34??64??25??30??32??64??25??30??32??64??25??30??32??64??25??30??32??64??25??30??32??64??0a??}
		 $hex3= {2f??41??75??74??6f??49??74??33??45??78??65??63??75??74??65??4c??69??6e??65??0a??}
		 $hex4= {2f??41??75??74??6f??49??74??33??45??78??65??63??75??74??65??53??63??72??69??70??74??0a??}
		 $hex5= {2f??41??75??74??6f??49??74??33??4f??75??74??70??75??74??44??65??62??75??67??0a??}
		 $hex6= {32??35??35??2e??32??35??35??2e??32??35??35??2e??32??35??35??0a??}
		 $hex7= {41??44??4c??49??42??55??4e??52??45??47??49??53??54??45??52??0a??}
		 $hex8= {41??50??50??44??41??54??41??43??4f??4d??4d??4f??4e??44??49??52??0a??}
		 $hex9= {41??55??54??4f??49??54??43??41??4c??4c??56??41??52??49??41??42??4c??45??25??64??0a??}
		 $hex10= {41??55??54??4f??49??54??53??45??54??4f??50??54??49??4f??4e??0a??}
		 $hex11= {41??55??54??4f??49??54??57??49??4e??47??45??54??54??49??54??4c??45??0a??}
		 $hex12= {41??55??54??4f??49??54??57??49??4e??53??45??54??54??49??54??4c??45??0a??}
		 $hex13= {42??52??4f??57??53??45??52??5f??46??41??56??4f??52??54??49??45??53??0a??}
		 $hex14= {42??52??4f??57??53??45??52??5f??46??4f??52??57??41??52??44??0a??}
		 $hex15= {42??52??4f??57??53??45??52??5f??52??45??46??52??45??53??48??0a??}
		 $hex16= {43??4f??4e??53??4f??4c??45??57??52??49??54??45??45??52??52??4f??52??0a??}
		 $hex17= {43??4f??4e??54??52??4f??4c??47??45??54??46??4f??43??55??53??0a??}
		 $hex18= {43??4f??4e??54??52??4f??4c??47??45??54??48??41??4e??44??4c??45??0a??}
		 $hex19= {43??4f??4e??54??52??4f??4c??4c??49??53??54??56??49??45??57??0a??}
		 $hex20= {43??6f??6e??74??72??6f??6c??20??50??61??6e??65??6c??41??70??70??65??61??72??61??6e??63??65??0a??}

	condition:
		22 of them
}
