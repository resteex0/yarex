
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
		 date = "2022-01-14_20-53-14" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ab2e178c77f6df518024a71d05e98451"

	strings:

	
 		 $s1= "%02hd%02hd%04hd" fullword wide
		 $s2= "%08X-%04X-%04X-%02X%02X-%02X%02X-%02X%02X%02X%02X" fullword wide
		 $s3= "bad daysfromnow" fullword wide
		 $s4= "%CommonProgramFiles%" fullword wide
		 $s5= "Control PanelInternational" fullword wide
		 $s6= "DefaultDomainName" fullword wide
		 $s7= "DefaultUserName" fullword wide
		 $s8= "HTTPSHELLopencommand" fullword wide
		 $s9= "Id Cron String Local Count Command Visibility" fullword wide
		 $s10= "incorrect value" fullword wide
		 $s11= "LastLoggedOnUser" fullword wide
		 $s12= "Microsoft Corporation" fullword wide
		 $s13= "OriginalFilename" fullword wide
		 $s14= "RegisteredOrganization" fullword wide
		 $s15= "RegisteredOwner" fullword wide
		 $s16= "R:S:K:UFB:D:C:I:A:" fullword wide
		 $s17= "%s|D|%04d%02d%02d-%02d%02d%02d|%.1f%s|%s|" fullword wide
		 $s18= "%s|F|%04d%02d%02d-%02d%02d%02d|%.1f%s|%s|" fullword wide
		 $s19= "SoftwareClientsStartMenuInternet" fullword wide
		 $s20= "SOFTWAREMICROSOFTWINDOWSCurrentVersion" fullword wide
		 $s21= "SOFTWAREMicrosoftWindowsCurrentVersionAuthenticationLogonUI" fullword wide
		 $s22= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword wide
		 $s23= "SOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s24= "SOFTWAREMICROSOFTWINDOWSCurrentVersionWinlogon" fullword wide
		 $s25= "SoftwareMicrosoftWindowsKickStart" fullword wide
		 $s26= "SOFTWAREMICROSOFTWINDOWS NTCurrentVersion" fullword wide
		 $s27= "SOFTWAREMICROSOFTWINDOWS NTCurrentVersionWinlogon" fullword wide
		 $s28= "SYSTEMCurrentControlSetControlComputerNameComputerName" fullword wide
		 $s29= "SYSTEMCurrentControlSetServices%sParameters" fullword wide
		 $s30= "trestart scheduled" fullword wide
		 $s31= "unarchived successfully" fullword wide
		 $s32= "unknown ZRESULT" fullword wide
		 $s33= "upload scheduled" fullword wide
		 $s34= "Volatile Environment" fullword wide
		 $s35= "VS_VERSION_INFO" fullword wide
		 $s36= "WinSta0Default" fullword wide
		 $a1= "%08X-%04X-%04X-%02X%02X-%02X%02X-%02X%02X%02X%02X" fullword ascii
		 $a2= "Id Cron String Local Count Command Visibility" fullword ascii
		 $a3= "%s|D|%04d%02d%02d-%02d%02d%02d|%.1f%s|%s|" fullword ascii
		 $a4= "%s|F|%04d%02d%02d-%02d%02d%02d|%.1f%s|%s|" fullword ascii
		 $a5= "SOFTWAREMICROSOFTWINDOWSCurrentVersion" fullword ascii
		 $a6= "SOFTWAREMicrosoftWindowsCurrentVersionAuthenticationLogonUI" fullword ascii
		 $a7= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword ascii
		 $a8= "SOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem" fullword ascii
		 $a9= "SOFTWAREMICROSOFTWINDOWSCurrentVersionWinlogon" fullword ascii
		 $a10= "SoftwareMicrosoftWindowsKickStart" fullword ascii
		 $a11= "SOFTWAREMICROSOFTWINDOWS NTCurrentVersion" fullword ascii
		 $a12= "SOFTWAREMICROSOFTWINDOWS NTCurrentVersionWinlogon" fullword ascii
		 $a13= "SYSTEMCurrentControlSetControlComputerNameComputerName" fullword ascii
		 $a14= "SYSTEMCurrentControlSetServices%sParameters" fullword ascii

		 $hex1= {246131303d2022536f}
		 $hex2= {246131313d2022534f}
		 $hex3= {246131323d2022534f}
		 $hex4= {246131333d20225359}
		 $hex5= {246131343d20225359}
		 $hex6= {2461313d2022253038}
		 $hex7= {2461323d2022496420}
		 $hex8= {2461333d202225737c}
		 $hex9= {2461343d202225737c}
		 $hex10= {2461353d2022534f46}
		 $hex11= {2461363d2022534f46}
		 $hex12= {2461373d2022536f66}
		 $hex13= {2461383d2022534f46}
		 $hex14= {2461393d2022534f46}
		 $hex15= {247331303d2022696e}
		 $hex16= {247331313d20224c61}
		 $hex17= {247331323d20224d69}
		 $hex18= {247331333d20224f72}
		 $hex19= {247331343d20225265}
		 $hex20= {247331353d20225265}
		 $hex21= {247331363d2022523a}
		 $hex22= {247331373d20222573}
		 $hex23= {247331383d20222573}
		 $hex24= {247331393d2022536f}
		 $hex25= {2473313d2022253032}
		 $hex26= {247332303d2022534f}
		 $hex27= {247332313d2022534f}
		 $hex28= {247332323d2022536f}
		 $hex29= {247332333d2022534f}
		 $hex30= {247332343d2022534f}
		 $hex31= {247332353d2022536f}
		 $hex32= {247332363d2022534f}
		 $hex33= {247332373d2022534f}
		 $hex34= {247332383d20225359}
		 $hex35= {247332393d20225359}
		 $hex36= {2473323d2022253038}
		 $hex37= {247333303d20227472}
		 $hex38= {247333313d2022756e}
		 $hex39= {247333323d2022756e}
		 $hex40= {247333333d20227570}
		 $hex41= {247333343d2022566f}
		 $hex42= {247333353d20225653}
		 $hex43= {247333363d20225769}
		 $hex44= {2473333d2022626164}
		 $hex45= {2473343d202225436f}
		 $hex46= {2473353d2022436f6e}
		 $hex47= {2473363d2022446566}
		 $hex48= {2473373d2022446566}
		 $hex49= {2473383d2022485454}
		 $hex50= {2473393d2022496420}

	condition:
		6 of them
}
