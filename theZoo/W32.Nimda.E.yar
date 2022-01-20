
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_Nimda_E 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_Nimda_E {
	meta: 
		 description= "W32_Nimda_E Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "130d2fe8174481170b3d78627c6b5e13"

	strings:

	
 		 $a1= "SOFTWAREMicrosoftWindowsCurrentVersionApp Paths" fullword ascii
		 $a2= "SOFTWAREMicrosoftWindowsCurrentVersionApp Paths" fullword ascii
		 $a3= "SoftwareMicrosoftWindowsCurrentVersionExplorerAdvanced" fullword ascii
		 $a4= "SoftwareMicrosoftWindowsCurrentVersionExplorerMapMail" fullword ascii
		 $a5= "SoftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword ascii
		 $a6= "SOFTWAREMicrosoftWindowsCurrentVersionNetworkLanMan" fullword ascii
		 $a7= "SOFTWAREMicrosoftWindowsCurrentVersionNetworkLanMan" fullword ascii
		 $a8= "SOFTWAREMicrosoftWindowsCurrentVersionNetworkLanManX$" fullword ascii
		 $a9= "softwaremicrosoftwindows ntcurrentversionperflib" fullword ascii
		 $a10= "softwaremicrosoftwindows ntcurrentversionperflib009" fullword ascii
		 $a11= "SYSTEMCurrentControlSetServiceslanmanserverShares" fullword ascii
		 $a12= "SYSTEMCurrentControlSetServiceslanmanserverSharesSecurity" fullword ascii
		 $a13= "SYSTEMCurrentControlSetServicesTcpipParametersInterfaces" fullword ascii
		 $a14= "SYSTEMCurrentControlSetServicesTcpipParametersInterfaces" fullword ascii

		 $hex1= {246131303d2022736f}
		 $hex2= {246131313d20225359}
		 $hex3= {246131323d20225359}
		 $hex4= {246131333d20225359}
		 $hex5= {246131343d20225359}
		 $hex6= {2461313d2022534f46}
		 $hex7= {2461323d2022534f46}
		 $hex8= {2461333d2022536f66}
		 $hex9= {2461343d2022536f66}
		 $hex10= {2461353d2022536f66}
		 $hex11= {2461363d2022534f46}
		 $hex12= {2461373d2022534f46}
		 $hex13= {2461383d2022534f46}
		 $hex14= {2461393d2022736f66}

	condition:
		9 of them
}
