
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
		 date = "2022-01-20_04-42-30" 
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
		 $a1= "0http://crl.verisign.com/ThawteTimestampingCA.crl0" fullword ascii
		 $a2= "3http://CSC3-2004-aia.verisign.com/CSC3-2004-aia.cer0" fullword ascii
		 $a3= "aAbBcCdDeEfFgGhHjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ" fullword ascii
		 $a4= ".?AUNoChannelSupport@BufferedTransformation@CryptoPP@@" fullword ascii
		 $a5= ".?AV?$OAEP@VSHA1@CryptoPP@@VP1363_MGF1@2@@CryptoPP@@" fullword ascii
		 $a6= ".?AV?$VariableKeyLength@$0BA@$00$0BAA@$00$03$0A@@CryptoPP@@" fullword ascii
		 $a7= ".?AVInvalidKeyLength@PK_SignatureScheme@CryptoPP@@" fullword ascii
		 $a8= ".?AVParameterNotUsed@AlgorithmParametersBase@CryptoPP@@" fullword ascii
		 $a9= ".?AVPKCS1v15_SignatureMessageEncodingMethod@CryptoPP@@" fullword ascii
		 $a10= ".?AVPK_DeterministicSignatureMessageEncodingMethod@CryptoPP@@" fullword ascii
		 $a11= "boost::filesystem::basic_directory_iterator constructor" fullword ascii
		 $a12= "boost::filesystem::basic_directory_iterator increment" fullword ascii
		 $a13= "C:ARCboost_1_45_0boost/exception/detail/exception_ptr.hpp" fullword ascii
		 $a14= "/http://CSC3-2004-crl.verisign.com/CSC3-2004.crl0D" fullword ascii
		 $a15= "Local{C15730E2-145C-4c5e-B005-3BC753F42475}-once-flag" fullword ascii

		 $hex1= {246131303d20222e3f}
		 $hex2= {246131313d2022626f}
		 $hex3= {246131323d2022626f}
		 $hex4= {246131333d2022433a}
		 $hex5= {246131343d20222f68}
		 $hex6= {246131353d20224c6f}
		 $hex7= {2461313d2022306874}
		 $hex8= {2461323d2022336874}
		 $hex9= {2461333d2022614162}
		 $hex10= {2461343d20222e3f41}
		 $hex11= {2461353d20222e3f41}
		 $hex12= {2461363d20222e3f41}
		 $hex13= {2461373d20222e3f41}
		 $hex14= {2461383d20222e3f41}
		 $hex15= {2461393d20222e3f41}
		 $hex16= {247331303d20224953}
		 $hex17= {247331313d20224953}
		 $hex18= {247331323d20225265}
		 $hex19= {247331333d2022536d}
		 $hex20= {247331343d2022536d}
		 $hex21= {247331353d2022534f}
		 $hex22= {247331363d2022536f}
		 $hex23= {247331373d2022534f}
		 $hex24= {247331383d2022536f}
		 $hex25= {247331393d2022536f}
		 $hex26= {2473313d2022386c6d}
		 $hex27= {247332303d2022536f}
		 $hex28= {247332313d2022536f}
		 $hex29= {247332323d2022536f}
		 $hex30= {247332333d2022534f}
		 $hex31= {247332343d2022536f}
		 $hex32= {247332353d2022534f}
		 $hex33= {247332363d2022536f}
		 $hex34= {247332373d2022536f}
		 $hex35= {247332383d2022536f}
		 $hex36= {247332393d20225374}
		 $hex37= {2473323d202246696c}
		 $hex38= {247333303d20225359}
		 $hex39= {247333313d20225359}
		 $hex40= {247333323d20225359}
		 $hex41= {2473333d202246696c}
		 $hex42= {2473343d2022465450}
		 $hex43= {2473353d2022465661}
		 $hex44= {2473363d2022476c6f}
		 $hex45= {2473373d2022475053}
		 $hex46= {2473383d2022475053}
		 $hex47= {2473393d2022497073}

	condition:
		31 of them
}
