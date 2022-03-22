
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
		 date = "2022-03-22_14-16-13" 
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

		 $hex1= {2641626f7574205854}
		 $hex2= {436f6e74656e742d54}
		 $hex3= {436f6e74726f6c2050}
		 $hex4= {476c6f62616c586c41}
		 $hex5= {484152445741524544}
		 $hex6= {5043492d582050432d}
		 $hex7= {534f4654574152454d}
		 $hex8= {534f46545741524557}
		 $hex9= {53595354454d437572}
		 $hex10= {53797374656d437572}
		 $hex11= {61676e747376632e65}
		 $hex12= {616d65726963612d68}
		 $hex13= {62657374606e6f7468}
		 $hex14= {736f7272792e666972}
		 $hex15= {776561746865722f74}
		 $hex16= {78436f6e74656e742d}

	condition:
		10 of them
}
