
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Kelihos 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Kelihos {
	meta: 
		 description= "theZoo_Kelihos Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-35-02" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1c837a8f652c36ea8d85f5ffee70068e"
		 hash2= "91f25b52d9bf833b9ac36e7258e44807"

	strings:

	
 		 $s1= "8lmUbWdlmlmvQopqrstvopqrst|}m$" fullword wide
		 $s2= "FileZillarecentservers.xml" fullword wide
		 $s3= "FileZillasitemanager.xml" fullword wide
		 $s4= "FTP Explorerprofiles.xml" fullword wide
		 $s5= "FVanDykeConfigSessions" fullword wide
		 $s6= "GlobalSCAPECuteFTP Lite" fullword wide
		 $s7= "GPSoftwareDirectory OpusConfigFilesftp.oxc" fullword wide
		 $s8= "GPSoftwareDirectory OpusLayoutsSystemdefault.oll" fullword wide
		 $s9= "IpswitchWS_FTP HomeSites" fullword wide
		 $s10= "ISoftwareCryerWebSitePublisher" fullword wide
		 $s11= "ISOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s12= "RegistryMachineSOFTWARECaceTechWinPcapOemNPF" fullword wide
		 $s13= "SmartFTPClient 2.0Favorites" fullword wide
		 $s14= "SmartFTPClient 2.0FavoritesFavorites.dat" fullword wide
		 $s15= "SOFTWAREFar2PluginsFTPHosts" fullword wide
		 $s16= "SoftwareFar2SavedDialogHistoryFTPHost" fullword wide
		 $s17= "SOFTWAREFarPluginsFTPHosts" fullword wide
		 $s18= "SoftwareFarSavedDialogHistoryFTPHost" fullword wide
		 $s19= "SoftwareFTP ExplorerProfiles" fullword wide
		 $s20= "SoftwareFTPWareCOREFTPSites" fullword wide
		 $s21= "SoftwareGhislerTotal Commander" fullword wide
		 $s22= "SoftwareGhislerWindows Commander" fullword wide
		 $s23= "SOFTWAREMicrosoftWindowsCurrentVersionUninstallUltraFXP" fullword wide
		 $s24= "SoftwareNCH SoftwareClassicFTPFTPAccounts" fullword wide
		 $s25= "SOFTWARENCH SoftwareFlingAccounts" fullword wide
		 $s26= "SoftwareSoftX.orgFTPClientSites" fullword wide
		 $s27= "SoftwareSotaFFFTPOptions" fullword wide
		 $s28= "SoftwareVanDykeSecureFX" fullword wide
		 $s29= "StringFileInfo%04x%04xFileVersion" fullword wide
		 $s30= "SYSTEMCurrentControlSetServices" fullword wide
		 $s31= "SYSTEMCurrentControlSetServicesTcpipLinkage" fullword wide
		 $s32= "SYSTEMCurrentControlSetServicesTcpipParametersInterfaces" fullword wide
		 $a1= ".?AVPK_DeterministicSignatureMessageEncodingMethod@CryptoPP@@" fullword ascii
		 $a2= "C:ARCboost_1_45_0boost/exception/detail/exception_ptr.hpp" fullword ascii

		 $hex1= {2461313d20222e3f41}
		 $hex2= {2461323d2022433a41}
		 $hex3= {247331303d20224953}
		 $hex4= {247331313d20224953}
		 $hex5= {247331323d20225265}
		 $hex6= {247331333d2022536d}
		 $hex7= {247331343d2022536d}
		 $hex8= {247331353d2022534f}
		 $hex9= {247331363d2022536f}
		 $hex10= {247331373d2022534f}
		 $hex11= {247331383d2022536f}
		 $hex12= {247331393d2022536f}
		 $hex13= {2473313d2022386c6d}
		 $hex14= {247332303d2022536f}
		 $hex15= {247332313d2022536f}
		 $hex16= {247332323d2022536f}
		 $hex17= {247332333d2022534f}
		 $hex18= {247332343d2022536f}
		 $hex19= {247332353d2022534f}
		 $hex20= {247332363d2022536f}
		 $hex21= {247332373d2022536f}
		 $hex22= {247332383d2022536f}
		 $hex23= {247332393d20225374}
		 $hex24= {2473323d202246696c}
		 $hex25= {247333303d20225359}
		 $hex26= {247333313d20225359}
		 $hex27= {247333323d20225359}
		 $hex28= {2473333d202246696c}
		 $hex29= {2473343d2022465450}
		 $hex30= {2473353d2022465661}
		 $hex31= {2473363d2022476c6f}
		 $hex32= {2473373d2022475053}
		 $hex33= {2473383d2022475053}
		 $hex34= {2473393d2022497073}

	condition:
		22 of them
}
