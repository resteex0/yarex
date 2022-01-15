
/*
   YARA Rule Set
   Author: resteex
   Identifier: RedLine 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_RedLine {
	meta: 
		 description= "RedLine Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-08" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0adb0e2ac8aa969fb088ee95c4a91536"
		 hash2= "0b5480b9bd031d6eb62e6a7fcd8209b4"
		 hash3= "0d73de42cb4e482062f04c5294ec6a64"
		 hash4= "14c3638c64de46bee97333288e6ffc63"
		 hash5= "1ca3d04a1c28f573e0a31c49881c8c4a"
		 hash6= "41aff158bfefe4084b88da1cb7caa13b"
		 hash7= "4995c492f9ea855bc019e69ca5332013"
		 hash8= "5334fc5de9c7f81c71c59c65768ee158"
		 hash9= "55b6e8d360a9c9beab3fb6208cba8b1b"
		 hash10= "56fbb5d915ff47c20902b8927ba569a3"
		 hash11= "5e7a2fdde2803b22b39abf66ecf9bc33"
		 hash12= "69dd97850f63fac1927313fb9983ab58"
		 hash13= "6a3a3a2ee332b4a6721ad1a740dfb38e"
		 hash14= "6d21a98f7b329aebc671db3660058116"
		 hash15= "707b7a4f6897dfda1902302e6302223b"
		 hash16= "760ae5e7793de36ae8159fc128687577"
		 hash17= "7e03737d683bc19280a5dc25befc85b6"
		 hash18= "836e16ce486f0cbabcddccb107c1d7d0"
		 hash19= "8696e2eb6d13545c8f3a0ae9554875da"
		 hash20= "89b4d24e0eeef1b76a5edc10da4a2233"
		 hash21= "90b1172f054ceae6fe035bac0b16464b"
		 hash22= "9b0aa8a5cb5f6b49918e8e8f54176e7f"
		 hash23= "a4f4b5daa83bb6dc85ede588ffbfdb34"
		 hash24= "a5952beb1c4823eae9fcafff7283c59c"
		 hash25= "a61f6f94009c04607f1ba923adcaba0d"
		 hash26= "aae688a16a5bd098f7b696c2dcdb713c"
		 hash27= "ab5eae79062ddedb6715c265dddd9044"
		 hash28= "ad89e162cf60de99d30e719e1a9c0596"
		 hash29= "afd6309fd7b3122779f6967edec03087"
		 hash30= "bd6fe266f81a88abe3c95129bd77757b"
		 hash31= "be3975e872adb57b05477f2f2c7c5e39"
		 hash32= "c061f6c696cde2214e0425839ae84f84"
		 hash33= "ca192feaaf9b7136cda5339f42501198"
		 hash34= "ca8c28106ef4cf7701356bd97e2ebed2"
		 hash35= "d2792e1448fdf7a225b51b4688b855c9"
		 hash36= "e307bef30d37b965e01405176a9e30fe"
		 hash37= "f9efec24e93faeca1f6b3d17217b4276"

	strings:

	
 		 $s1= "11.00.9600.16384 (winblue_rtm.130821-1623)" fullword wide
		 $s2= ";=4>4?4A@B@C@D@E@" fullword wide
		 $s3= "%4d-%02d-%02d-%02d-%02d-%02d-%03d" fullword wide
		 $s4= "{6cf7ef10-d312-4ad9-8758-335db5fcfa96}" fullword wide
		 $s5= "{8fec2f5e-cc84-44fc-8621-4a616ba27e50}" fullword wide
		 $s6= "9ARCHIVES_DOCUMENTS_FILE_FOLDER_FOLDER_STORAGE_ICON_191100(" fullword wide
		 $s7= ";=;>;?;@;A;B;" fullword wide
		 $s8= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s9= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s10= "/attachments/860627527411302422/862116136866676766/new_runpe.dll" fullword wide
		 $s11= "Capi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s12= "{cdeeabee-e18b-4750-ab77-6aac8793bd31}" fullword wide
		 $s13= "&ChangeIcon; &UserName_*;" fullword wide
		 $s14= "Control PanelDesktopResourceLocale" fullword wide
		 $s15= "CryptProtectMemory failed" fullword wide
		 $s16= "CryptUnprotectMemory failed" fullword wide
		 $s17= "DataGridViewColumnCollection" fullword wide
		 $s18= ".DEFAULTControl PanelInternational" fullword wide
		 $s19= "DiscoveryClientResultCollection Corporation." fullword wide
		 $s20= "EServiceModelChannelsReceiveContext24073TQEPQwiKRwKNSUrKidIUQ==" fullword wide
		 $s21= "etubirttAgnitteSdepocSnoitacilppAnoitarugifnoCmetsyS7111" fullword wide
		 $s22= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s23= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s24= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s25= "EXTRACTOPT FILESIZES FINISHMSG" fullword wide
		 $s26= "FServiceModelChannelsReceiveContext24073F4cKA0lMhYLIj4tEiENHw==" fullword wide
		 $s27= "FServiceModelChannelsReceiveContext24073wIYOg0PExAcHw8r" fullword wide
		 $s28= "GetDelegateForFunctionPointer" fullword wide
		 $s29= "HGIGJGKGLGMGNGYXa`b`c`d`e`f`g`hgi`j`k`mlnlolplql" fullword wide
		 $s30= "http://nsis.sf.net/NSIS_Error" fullword wide
		 $s31= "https://cdn.discordapp.com" fullword wide
		 $s32= "IHJHKHLHMH" fullword wide
		 $s33= "IServiceModelChannelsReceiveContext24073AEcKwsfVQkQHx8hEjEzBw==" fullword wide
		 $s34= "IServiceModelChannelsReceiveContext24073F4iJwt5ABUkNSUuLBFIUQ==" fullword wide
		 $s35= "JServiceModelChannelsReceiveContext24073F4yJwx6MiwfD0IzKiEgUQ==" fullword wide
		 $s36= "karizevodasayohihohecezulamas" fullword wide
		 $s37= "LpOZLTWJLkYoeKREYqcIIDyNUjePtYQzilYCiBEGJrGWTowSXZHRXTchRbeBOhq" fullword wide
		 $s38= "ManagementCommitAttribute.exe" fullword wide
		 $s39= "MicrosoftWinNativeMethodsSECURITYATTRIBUTES75753" fullword wide
		 $s40= "NetUnsafeNclNativeMethodsHttpApiTOKENBINDINGRESULTDATAV3408" fullword wide
		 $s41= "ObjectCreationDelegate Corporation." fullword wide
		 $s42= "pi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s43= "pi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s44= "pi-ms-win-core-file-l2-1-1" fullword wide
		 $s45= "pi-ms-win-core-localization-l1-2-1" fullword wide
		 $s46= "pi-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s47= "pi-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s48= "pi-ms-win-core-string-l1-1-0" fullword wide
		 $s49= "pi-ms-win-core-synch-l1-2-0" fullword wide
		 $s50= "pi-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s51= "pi-ms-win-core-winrt-l1-1-0" fullword wide
		 $s52= "pi-ms-win-core-xstate-l2-1-0" fullword wide
		 $s53= "PortableApps.comFormatVersion" fullword wide
		 $s54= "PortableApps.comInstallerVersion" fullword wide
		 $s55= "ppalrevOefaSseldnaHteNefaSsdohteMevitaNlcNefasnUteNmetsyS81615" fullword wide
		 $s56= "ProfilePropertySettings.exe" fullword wide
		 $s57= "PropertyValueExceptionEventArgs" fullword wide
		 $s58= "ProtectionLevel Corporation." fullword wide
		 $s59= "RecipientInfoType Corporation." fullword wide
		 $s60= "sdqqQGXFhwH6lTulhA.rP6V85kfbfpKRvPQ3L" fullword wide
		 $s61= "SeCreateSymbolicLinkPrivilege" fullword wide
		 $s62= "SecurityTokenException Corporation." fullword wide
		 $s63= "ServiceModelChannelsReceiveContext24073" fullword wide
		 $s64= "ServiceModelConfigurationHttpTransportElement96689" fullword wide
		 $s65= "SettingsManageabilityAttribute.exe" fullword wide
		 $s66= "SettingsPropertyIsReadOnlyException.exe" fullword wide
		 $s67= "Soap12BodyBinding Corporation." fullword wide
		 $s68= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s69= "SystemNetDataParseStatus67672" fullword wide
		 $s70= "SystemNetSocketsDisconnectExDelegate12557" fullword wide
		 $s71= "System.Security.Cryptography.AesCryptoServiceProvider" fullword wide
		 $s72= "SystemServiceModelChannelsInputChannelDemuxer34366" fullword wide
		 $s73= "SystemServiceModelChannelsInputChannelDemuxer97122" fullword wide
		 $s74= "SystemServiceModelPeerResolversRefreshResult24235" fullword wide
		 $s75= "SystemXmlXmlBaseWriterNamespaceManagerXmlAttribute35186" fullword wide
		 $s76= "tcartnoCataDemaNnoitazilaireSemitnuRmetsyS92019" fullword wide
		 $s77= "__tmp_rar_sfx_access_check_%u" fullword wide
		 $s78= "TransportSecurityBindingElement.exe" fullword wide
		 $s79= "verosiwagasedavijozegulozakeawkutafojajocoxelufayifelif" fullword wide
		 $s80= "WindowsMicrosoft.NETFrameworkv4.0.30319vbc.exe" fullword wide
		 $s81= "Wobetesido suvesebuxomelot" fullword wide
		 $a1= "9ARCHIVES_DOCUMENTS_FILE_FOLDER_FOLDER_STORAGE_ICON_191100(" fullword ascii
		 $a2= "/attachments/860627527411302422/862116136866676766/new_runpe.dll" fullword ascii
		 $a3= "EServiceModelChannelsReceiveContext24073TQEPQwiKRwKNSUrKidIUQ==" fullword ascii
		 $a4= "etubirttAgnitteSdepocSnoitacilppAnoitarugifnoCmetsyS7111" fullword ascii
		 $a5= "FServiceModelChannelsReceiveContext24073F4cKA0lMhYLIj4tEiENHw==" fullword ascii
		 $a6= "FServiceModelChannelsReceiveContext24073wIYOg0PExAcHw8r" fullword ascii
		 $a7= "IServiceModelChannelsReceiveContext24073AEcKwsfVQkQHx8hEjEzBw==" fullword ascii
		 $a8= "IServiceModelChannelsReceiveContext24073F4iJwt5ABUkNSUuLBFIUQ==" fullword ascii
		 $a9= "JServiceModelChannelsReceiveContext24073F4yJwx6MiwfD0IzKiEgUQ==" fullword ascii
		 $a10= "LpOZLTWJLkYoeKREYqcIIDyNUjePtYQzilYCiBEGJrGWTowSXZHRXTchRbeBOhq" fullword ascii
		 $a11= "NetUnsafeNclNativeMethodsHttpApiTOKENBINDINGRESULTDATAV3408" fullword ascii
		 $a12= "ppalrevOefaSseldnaHteNefaSsdohteMevitaNlcNefasnUteNmetsyS81615" fullword ascii
		 $a13= "ServiceModelConfigurationHttpTransportElement96689" fullword ascii
		 $a14= "System.Security.Cryptography.AesCryptoServiceProvider" fullword ascii
		 $a15= "SystemServiceModelChannelsInputChannelDemuxer34366" fullword ascii
		 $a16= "SystemServiceModelChannelsInputChannelDemuxer97122" fullword ascii
		 $a17= "SystemXmlXmlBaseWriterNamespaceManagerXmlAttribute35186" fullword ascii
		 $a18= "verosiwagasedavijozegulozakeawkutafojajocoxelufayifelif" fullword ascii
		 $a19= "WindowsMicrosoft.NETFrameworkv4.0.30319vbc.exe" fullword ascii

		 $hex1= {246131303d20224c70}
		 $hex2= {246131313d20224e65}
		 $hex3= {246131323d20227070}
		 $hex4= {246131333d20225365}
		 $hex5= {246131343d20225379}
		 $hex6= {246131353d20225379}
		 $hex7= {246131363d20225379}
		 $hex8= {246131373d20225379}
		 $hex9= {246131383d20227665}
		 $hex10= {246131393d20225769}
		 $hex11= {2461313d2022394152}
		 $hex12= {2461323d20222f6174}
		 $hex13= {2461333d2022455365}
		 $hex14= {2461343d2022657475}
		 $hex15= {2461353d2022465365}
		 $hex16= {2461363d2022465365}
		 $hex17= {2461373d2022495365}
		 $hex18= {2461383d2022495365}
		 $hex19= {2461393d20224a5365}
		 $hex20= {247331303d20222f61}
		 $hex21= {247331313d20224361}
		 $hex22= {247331323d20227b63}
		 $hex23= {247331333d20222643}
		 $hex24= {247331343d2022436f}
		 $hex25= {247331353d20224372}
		 $hex26= {247331363d20224372}
		 $hex27= {247331373d20224461}
		 $hex28= {247331383d20222e44}
		 $hex29= {247331393d20224469}
		 $hex30= {2473313d202231312e}
		 $hex31= {247332303d20224553}
		 $hex32= {247332313d20226574}
		 $hex33= {247332323d20226578}
		 $hex34= {247332333d20226578}
		 $hex35= {247332343d20226578}
		 $hex36= {247332353d20224558}
		 $hex37= {247332363d20224653}
		 $hex38= {247332373d20224653}
		 $hex39= {247332383d20224765}
		 $hex40= {247332393d20224847}
		 $hex41= {2473323d20223b3d34}
		 $hex42= {247333303d20226874}
		 $hex43= {247333313d20226874}
		 $hex44= {247333323d20224948}
		 $hex45= {247333333d20224953}
		 $hex46= {247333343d20224953}
		 $hex47= {247333353d20224a53}
		 $hex48= {247333363d20226b61}
		 $hex49= {247333373d20224c70}
		 $hex50= {247333383d20224d61}
		 $hex51= {247333393d20224d69}
		 $hex52= {2473333d2022253464}
		 $hex53= {247334303d20224e65}
		 $hex54= {247334313d20224f62}
		 $hex55= {247334323d20227069}
		 $hex56= {247334333d20227069}
		 $hex57= {247334343d20227069}
		 $hex58= {247334353d20227069}
		 $hex59= {247334363d20227069}
		 $hex60= {247334373d20227069}
		 $hex61= {247334383d20227069}
		 $hex62= {247334393d20227069}
		 $hex63= {2473343d20227b3663}
		 $hex64= {247335303d20227069}
		 $hex65= {247335313d20227069}
		 $hex66= {247335323d20227069}
		 $hex67= {247335333d2022506f}
		 $hex68= {247335343d2022506f}
		 $hex69= {247335353d20227070}
		 $hex70= {247335363d20225072}
		 $hex71= {247335373d20225072}
		 $hex72= {247335383d20225072}
		 $hex73= {247335393d20225265}
		 $hex74= {2473353d20227b3866}
		 $hex75= {247336303d20227364}
		 $hex76= {247336313d20225365}
		 $hex77= {247336323d20225365}
		 $hex78= {247336333d20225365}
		 $hex79= {247336343d20225365}
		 $hex80= {247336353d20225365}
		 $hex81= {247336363d20225365}
		 $hex82= {247336373d2022536f}
		 $hex83= {247336383d2022536f}
		 $hex84= {247336393d20225379}
		 $hex85= {2473363d2022394152}
		 $hex86= {247337303d20225379}
		 $hex87= {247337313d20225379}
		 $hex88= {247337323d20225379}
		 $hex89= {247337333d20225379}
		 $hex90= {247337343d20225379}
		 $hex91= {247337353d20225379}
		 $hex92= {247337363d20227463}
		 $hex93= {247337373d20225f5f}
		 $hex94= {247337383d20225472}
		 $hex95= {247337393d20227665}
		 $hex96= {2473373d20223b3d3b}
		 $hex97= {247338303d20225769}
		 $hex98= {247338313d2022576f}
		 $hex99= {2473383d2022617069}
		 $hex100= {2473393d2022617069}

	condition:
		66 of them
}
