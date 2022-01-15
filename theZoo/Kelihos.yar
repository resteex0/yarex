
/*
   YARA Rule Set
   Author: resteex
   Identifier: Kelihos 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Kelihos {
	meta: 
		 description= "Kelihos Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_19-53-40" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1c837a8f652c36ea8d85f5ffee70068e"
		 hash2= "91f25b52d9bf833b9ac36e7258e44807"

	strings:

	
 		 $s1= "GPSoftwareDirectory OpusConfigFilesftp.oxc" fullword wide
		 $s2= "GPSoftwareDirectory OpusLayoutsSystemdefault.oll" fullword wide
		 $s3= "ISOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s4= "RegistryMachineSOFTWARECaceTechWinPcapOemNPF" fullword wide
		 $s5= "SmartFTPClient 2.0FavoritesFavorites.dat" fullword wide
		 $s6= "SoftwareFar2SavedDialogHistoryFTPHost" fullword wide
		 $s7= "SoftwareFarSavedDialogHistoryFTPHost" fullword wide
		 $s8= "SOFTWAREMicrosoftWindowsCurrentVersionUninstallUltraFXP" fullword wide
		 $s9= "SoftwareNCH SoftwareClassicFTPFTPAccounts" fullword wide
		 $s10= "SOFTWARENCH SoftwareFlingAccounts" fullword wide
		 $s11= "StringFileInfo%04x%04xFileVersion" fullword wide
		 $s12= "SYSTEMCurrentControlSetServicesTcpipLinkage" fullword wide
		 $s13= "SYSTEMCurrentControlSetServicesTcpipParametersInterfaces" fullword wide
		 $a1= "GPSoftwareDirectory OpusLayoutsSystemdefault.oll" fullword ascii
		 $a2= "ISOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword ascii
		 $a3= "RegistryMachineSOFTWARECaceTechWinPcapOemNPF" fullword ascii
		 $a4= "SOFTWAREMicrosoftWindowsCurrentVersionUninstallUltraFXP" fullword ascii
		 $a5= "SYSTEMCurrentControlSetServicesTcpipParametersInterfaces" fullword ascii

		 $hex1= {2461313d2022475053}
		 $hex2= {2461323d202249534f}
		 $hex3= {2461333d2022526567}
		 $hex4= {2461343d2022534f46}
		 $hex5= {2461353d2022535953}
		 $hex6= {247331303d2022534f}
		 $hex7= {247331313d20225374}
		 $hex8= {247331323d20225359}
		 $hex9= {247331333d20225359}
		 $hex10= {2473313d2022475053}
		 $hex11= {2473323d2022475053}
		 $hex12= {2473333d202249534f}
		 $hex13= {2473343d2022526567}
		 $hex14= {2473353d2022536d61}
		 $hex15= {2473363d2022536f66}
		 $hex16= {2473373d2022536f66}
		 $hex17= {2473383d2022534f46}
		 $hex18= {2473393d2022536f66}

	condition:
		2 of them
}
