
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
		 date = "2022-01-10_19-31-18" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "130d2fe8174481170b3d78627c6b5e13"

	strings:

	
 		 $a1= "=#=)=0=5=;=B=G=M=T=Y=_=f=k=q=x=}=" fullword ascii
		 $a2= "--====_ABC09876j54321DEF_====" fullword ascii
		 $a3= "--====_ABC09876j54321DEF_====--" fullword ascii
		 $a4= "--====_ABC123456j7890DEF_====" fullword ascii
		 $a5= "/_mem_bin/..%255c../..%255c../..%255c.." fullword ascii
		 $a6= "/msadc/..%255c../..%255c../..%255c/..%c1%1c../..%c1%1c../..%c1%1c.." fullword ascii
		 $a7= "SoftwareMicrosoftWindowsCurrentVersionExplorerAdvanced" fullword ascii
		 $a8= "SoftwareMicrosoftWindowsCurrentVersionExplorerMapMail" fullword ascii
		 $a9= "SOFTWAREMicrosoftWindowsCurrentVersionNetworkLanMan" fullword ascii
		 $a10= "SOFTWAREMicrosoftWindowsCurrentVersionNetworkLanMan" fullword ascii
		 $a11= "SOFTWAREMicrosoftWindowsCurrentVersionNetworkLanManX$" fullword ascii
		 $a12= "SYSTEMCurrentControlSetServiceslanmanserverShares" fullword ascii
		 $a13= "SYSTEMCurrentControlSetServiceslanmanserverSharesSecurity" fullword ascii
		 $a14= "SYSTEMCurrentControlSetServicesTcpipParametersInterfaces" fullword ascii
		 $a15= "SYSTEMCurrentControlSetServicesTcpipParametersInterfaces" fullword ascii
		 $a16= "SystemCurrentControlSetServicesVxDMSTCP" fullword ascii
		 $a17= "tftp%%20-i%%20%s%%20GET%%20cool.dll%%20" fullword ascii
		 $a18= "/_vti_bin/..%255c../..%255c../..%255c.." fullword ascii
		 $a19= "/winnt/system32/cmd.exe?/c+" fullword ascii
		 $a20= "WritePrivateProfileStringA" fullword ascii

		 $hex1= {246131303d2022534f}
		 $hex2= {246131313d2022534f}
		 $hex3= {246131323d20225359}
		 $hex4= {246131333d20225359}
		 $hex5= {246131343d20225359}
		 $hex6= {246131353d20225359}
		 $hex7= {246131363d20225379}
		 $hex8= {246131373d20227466}
		 $hex9= {246131383d20222f5f}
		 $hex10= {246131393d20222f77}
		 $hex11= {2461313d20223d233d}
		 $hex12= {246132303d20225772}
		 $hex13= {2461323d20222d2d3d}
		 $hex14= {2461333d20222d2d3d}
		 $hex15= {2461343d20222d2d3d}
		 $hex16= {2461353d20222f5f6d}
		 $hex17= {2461363d20222f6d73}
		 $hex18= {2461373d2022536f66}
		 $hex19= {2461383d2022536f66}
		 $hex20= {2461393d2022534f46}

	condition:
		2 of them
}
