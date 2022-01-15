
/*
   YARA Rule Set
   Author: resteex
   Identifier: Dino 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Dino {
	meta: 
		 description= "Dino Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-50-59" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ab2e178c77f6df518024a71d05e98451"

	strings:

	
 		 $s1= "%08X-%04X-%04X-%02X%02X-%02X%02X-%02X%02X%02X%02X" fullword wide
		 $s2= "Control PanelInternational" fullword wide
		 $s3= "Id Cron String Local Count Command Visibility" fullword wide
		 $s4= "%s|D|%04d%02d%02d-%02d%02d%02d|%.1f%s|%s|" fullword wide
		 $s5= "%s|F|%04d%02d%02d-%02d%02d%02d|%.1f%s|%s|" fullword wide
		 $s6= "SoftwareClientsStartMenuInternet" fullword wide
		 $s7= "SOFTWAREMICROSOFTWINDOWSCurrentVersion" fullword wide
		 $s8= "SOFTWAREMicrosoftWindowsCurrentVersionAuthenticationLogonUI" fullword wide
		 $s9= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword wide
		 $s10= "SOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s11= "SOFTWAREMICROSOFTWINDOWSCurrentVersionWinlogon" fullword wide
		 $s12= "SoftwareMicrosoftWindowsKickStart" fullword wide
		 $s13= "SOFTWAREMICROSOFTWINDOWS NTCurrentVersion" fullword wide
		 $s14= "SOFTWAREMICROSOFTWINDOWS NTCurrentVersionWinlogon" fullword wide
		 $s15= "SYSTEMCurrentControlSetControlComputerNameComputerName" fullword wide
		 $s16= "SYSTEMCurrentControlSetServices%sParameters" fullword wide
		 $a1= "SOFTWAREMicrosoftWindowsCurrentVersionAuthenticationLogonUI" fullword ascii
		 $a2= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword ascii
		 $a3= "SOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem" fullword ascii
		 $a4= "SOFTWAREMICROSOFTWINDOWSCurrentVersionWinlogon" fullword ascii
		 $a5= "SOFTWAREMICROSOFTWINDOWS NTCurrentVersionWinlogon" fullword ascii
		 $a6= "SYSTEMCurrentControlSetControlComputerNameComputerName" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {2461323d2022536f66}
		 $hex3= {2461333d2022534f46}
		 $hex4= {2461343d2022534f46}
		 $hex5= {2461353d2022534f46}
		 $hex6= {2461363d2022535953}
		 $hex7= {247331303d2022534f}
		 $hex8= {247331313d2022534f}
		 $hex9= {247331323d2022536f}
		 $hex10= {247331333d2022534f}
		 $hex11= {247331343d2022534f}
		 $hex12= {247331353d20225359}
		 $hex13= {247331363d20225359}
		 $hex14= {2473313d2022253038}
		 $hex15= {2473323d2022436f6e}
		 $hex16= {2473333d2022496420}
		 $hex17= {2473343d202225737c}
		 $hex18= {2473353d202225737c}
		 $hex19= {2473363d2022536f66}
		 $hex20= {2473373d2022534f46}
		 $hex21= {2473383d2022534f46}
		 $hex22= {2473393d2022536f66}

	condition:
		14 of them
}
