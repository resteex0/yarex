
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ave Maria 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ave_Maria {
	meta: 
		 description= "Ave Maria Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_19-49-03" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "08d1dcb5143af4f143e0a567725f31ed"
		 hash2= "2e091ca97a12c5965f685acbe71a480c"
		 hash3= "8e4803c57802e00bb2e7ed0cfec61003"
		 hash4= "8f76e8fc87260e7b742076f392a98a8a"

	strings:

	
 		 $s1= "%02d-%02d-%02d_%02d.%02d.%02d" fullword wide
		 $s2= "Ave_Maria Stealer OpenSource github Link: https://github.com/syohex/java-simple-mine-sweeper" fullword wide
		 $s3= "BliskUser DataDefaultLogin Data" fullword wide
		 $s4= "BliskUser DataLocal State" fullword wide
		 $s5= "BraveSoftwareBrave-BrowserUser DataDefaultLogin Data" fullword wide
		 $s6= "BraveSoftwareBrave-BrowserUser DataLocal State" fullword wide
		 $s7= "CentBrowserUser DataDefaultLogin Data" fullword wide
		 $s8= "CentBrowserUser DataLocal State" fullword wide
		 $s9= "ChromiumUser DataDefaultLogin Data" fullword wide
		 $s10= "ChromiumUser DataLocal State" fullword wide
		 $s11= "ComodoDragonUser DataDefaultLogin Data" fullword wide
		 $s12= "ComodoDragonUser DataLocal State" fullword wide
		 $s13= "C:UsersVitali KremezDocumentsMidgetPornworkspaceMsgBox.exe" fullword wide
		 $s14= "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
		 $s15= "Epic Privacy BrowserUser DataDefaultLogin Data" fullword wide
		 $s16= "Epic Privacy BrowserUser DataLocal State" fullword wide
		 $s17= "GoogleChromeUser DataDefaultLogin Data" fullword wide
		 $s18= "GoogleChromeUser DataLocal State" fullword wide
		 $s19= "MicrosoftEdgeUser DataDefaultLogin Data" fullword wide
		 $s20= "MicrosoftEdgeUser DataLocal State" fullword wide
		 $s21= "Opera SoftwareOpera StableLocal State" fullword wide
		 $s22= "Opera SoftwareOpera StableLogin Data" fullword wide
		 $s23= "SELECT Name FROM Win32_VideoController" fullword wide
		 $s24= "SlimjetUser DataDefaultLogin Data" fullword wide
		 $s25= "SlimjetUser DataLocal State" fullword wide
		 $s26= "@SOFTWAREMicrosoftCryptography" fullword wide
		 $s27= "SoftwareMicrosoftWindowsCurrentVersionApp Paths" fullword wide
		 $s28= "SoftwareMicrosoftWindowsCurrentVersionExplorer" fullword wide
		 $s29= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s30= "SoftwareMicrosoftWindows NTCurrentVersionWindows Messaging SubsystemProfilesOutlook9375CFF041" fullword wide
		 $s31= "SOFTWAREMicrosoftWindows NTCurrentVersionWinlogon" fullword wide
		 $s32= "SYSTEMCurrentControlSetControlTerminal Server" fullword wide
		 $s33= "SYSTEMCurrentControlSetControlTerminal ServerAddIns" fullword wide
		 $s34= "SYSTEMCurrentControlSetControlTerminal ServerAddInsClip Redirector" fullword wide
		 $s35= "SYSTEMCurrentControlSetControlTerminal ServerAddInsDynamic VC" fullword wide
		 $s36= "SYSTEMCurrentControlSetControlTerminal ServerLicensing Core" fullword wide
		 $s37= "SYSTEMCurrentControlSetServicesTermService" fullword wide
		 $s38= "SYSTEMCurrentControlSetServicesTermServiceParameters" fullword wide
		 $s39= "TencentQQBrowserUser DataDefaultLogin Data" fullword wide
		 $s40= "TencentQQBrowserUser DataLocal State" fullword wide
		 $s41= "TorchUser DataDefaultLogin Data" fullword wide
		 $s42= "TorchUser DataLocal State" fullword wide
		 $s43= "UCBrowserUser Data_i18nDefaultUC Login Data.17" fullword wide
		 $s44= "UCBrowserUser Data_i18nLocal State" fullword wide
		 $s45= "VivaldiUser DataDefaultLogin Data" fullword wide
		 $s46= "VivaldiUser DataLocal State" fullword wide

		 $hex1= {247331303d20224368}
		 $hex2= {247331313d2022436f}
		 $hex3= {247331323d2022436f}
		 $hex4= {247331333d2022433a}
		 $hex5= {247331343d2022456c}
		 $hex6= {247331353d20224570}
		 $hex7= {247331363d20224570}
		 $hex8= {247331373d2022476f}
		 $hex9= {247331383d2022476f}
		 $hex10= {247331393d20224d69}
		 $hex11= {2473313d2022253032}
		 $hex12= {247332303d20224d69}
		 $hex13= {247332313d20224f70}
		 $hex14= {247332323d20224f70}
		 $hex15= {247332333d20225345}
		 $hex16= {247332343d2022536c}
		 $hex17= {247332353d2022536c}
		 $hex18= {247332363d20224053}
		 $hex19= {247332373d2022536f}
		 $hex20= {247332383d2022536f}
		 $hex21= {247332393d2022536f}
		 $hex22= {2473323d2022417665}
		 $hex23= {247333303d2022536f}
		 $hex24= {247333313d2022534f}
		 $hex25= {247333323d20225359}
		 $hex26= {247333333d20225359}
		 $hex27= {247333343d20225359}
		 $hex28= {247333353d20225359}
		 $hex29= {247333363d20225359}
		 $hex30= {247333373d20225359}
		 $hex31= {247333383d20225359}
		 $hex32= {247333393d20225465}
		 $hex33= {2473333d2022426c69}
		 $hex34= {247334303d20225465}
		 $hex35= {247334313d2022546f}
		 $hex36= {247334323d2022546f}
		 $hex37= {247334333d20225543}
		 $hex38= {247334343d20225543}
		 $hex39= {247334353d20225669}
		 $hex40= {247334363d20225669}
		 $hex41= {2473343d2022426c69}
		 $hex42= {2473353d2022427261}
		 $hex43= {2473363d2022427261}
		 $hex44= {2473373d202243656e}
		 $hex45= {2473383d202243656e}
		 $hex46= {2473393d2022436872}

	condition:
		5 of them
}
