
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Dino 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Dino {
	meta: 
		 description= "theZoo_Dino Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-34-52" 
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

		 $hex1= {247331303d2022534f}
		 $hex2= {247331313d2022534f}
		 $hex3= {247331323d2022536f}
		 $hex4= {247331333d2022534f}
		 $hex5= {247331343d2022534f}
		 $hex6= {247331353d20225359}
		 $hex7= {247331363d20225359}
		 $hex8= {2473313d2022253038}
		 $hex9= {2473323d2022436f6e}
		 $hex10= {2473333d2022496420}
		 $hex11= {2473343d202225737c}
		 $hex12= {2473353d202225737c}
		 $hex13= {2473363d2022536f66}
		 $hex14= {2473373d2022534f46}
		 $hex15= {2473383d2022534f46}
		 $hex16= {2473393d2022536f66}

	condition:
		10 of them
}
