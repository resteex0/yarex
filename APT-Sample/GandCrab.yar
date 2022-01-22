
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
		 date = "2022-01-22_17-55-55" 
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

		 $hex1= {2461313d2022537973}
		 $hex2= {247331303d2022534f}
		 $hex3= {247331313d2022534f}
		 $hex4= {247331323d2022736f}
		 $hex5= {247331333d20225359}
		 $hex6= {247331343d20227765}
		 $hex7= {247331353d20227843}
		 $hex8= {2473313d2022264162}
		 $hex9= {2473323d202261676e}
		 $hex10= {2473333d2022616d65}
		 $hex11= {2473343d2022626573}
		 $hex12= {2473353d2022436f6e}
		 $hex13= {2473363d2022436f6e}
		 $hex14= {2473373d2022476c6f}
		 $hex15= {2473383d2022484152}
		 $hex16= {2473393d2022504349}

	condition:
		10 of them
}
