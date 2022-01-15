
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ave_Maria 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ave_Maria {
	meta: 
		 description= "Ave_Maria Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_23-59-44" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "08d1dcb5143af4f143e0a567725f31ed"
		 hash2= "2e091ca97a12c5965f685acbe71a480c"
		 hash3= "8e4803c57802e00bb2e7ed0cfec61003"
		 hash4= "8f76e8fc87260e7b742076f392a98a8a"

	strings:

	
 		 $s1= "BliskUser DataDefaultLogin Data" fullword wide
		 $s2= "BraveSoftwareBrave-BrowserUser DataDefaultLogin Data" fullword wide
		 $s3= "BraveSoftwareBrave-BrowserUser DataLocal State" fullword wide
		 $s4= "CentBrowserUser DataDefaultLogin Data" fullword wide
		 $s5= "ChromiumUser DataDefaultLogin Data" fullword wide
		 $s6= "ComodoDragonUser DataDefaultLogin Data" fullword wide
		 $s7= "ComodoDragonUser DataLocal State" fullword wide
		 $s8= "C:UsersVitali KremezDocumentsMidgetPornworkspaceMsgBox.exe" fullword wide
		 $s9= "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
		 $s10= "GoogleChromeUser DataDefaultLogin Data" fullword wide
		 $s11= "GoogleChromeUser DataLocal State" fullword wide
		 $s12= "MicrosoftEdgeUser DataDefaultLogin Data" fullword wide
		 $s13= "MicrosoftEdgeUser DataLocal State" fullword wide
		 $s14= "SlimjetUser DataDefaultLogin Data" fullword wide
		 $s15= "SoftwareMicrosoftWindowsCurrentVersionApp Paths" fullword wide
		 $s16= "SoftwareMicrosoftWindowsCurrentVersionExplorer" fullword wide
		 $s17= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s18= "SOFTWAREMicrosoftWindows NTCurrentVersionWinlogon" fullword wide
		 $s19= "SYSTEMCurrentControlSetControlTerminal Server" fullword wide
		 $s20= "SYSTEMCurrentControlSetControlTerminal ServerAddIns" fullword wide
		 $s21= "SYSTEMCurrentControlSetControlTerminal ServerAddInsClip Redirector" fullword wide
		 $s22= "SYSTEMCurrentControlSetControlTerminal ServerAddInsDynamic VC" fullword wide
		 $s23= "SYSTEMCurrentControlSetControlTerminal ServerLicensing Core" fullword wide
		 $s24= "SYSTEMCurrentControlSetServicesTermService" fullword wide
		 $s25= "SYSTEMCurrentControlSetServicesTermServiceParameters" fullword wide
		 $s26= "TencentQQBrowserUser DataDefaultLogin Data" fullword wide
		 $s27= "TencentQQBrowserUser DataLocal State" fullword wide
		 $s28= "TorchUser DataDefaultLogin Data" fullword wide
		 $s29= "UCBrowserUser Data_i18nLocal State" fullword wide
		 $s30= "VivaldiUser DataDefaultLogin Data" fullword wide

		 $hex1= {247331303d2022476f}
		 $hex2= {247331313d2022476f}
		 $hex3= {247331323d20224d69}
		 $hex4= {247331333d20224d69}
		 $hex5= {247331343d2022536c}
		 $hex6= {247331353d2022536f}
		 $hex7= {247331363d2022536f}
		 $hex8= {247331373d2022536f}
		 $hex9= {247331383d2022534f}
		 $hex10= {247331393d20225359}
		 $hex11= {2473313d2022426c69}
		 $hex12= {247332303d20225359}
		 $hex13= {247332313d20225359}
		 $hex14= {247332323d20225359}
		 $hex15= {247332333d20225359}
		 $hex16= {247332343d20225359}
		 $hex17= {247332353d20225359}
		 $hex18= {247332363d20225465}
		 $hex19= {247332373d20225465}
		 $hex20= {247332383d2022546f}
		 $hex21= {247332393d20225543}
		 $hex22= {2473323d2022427261}
		 $hex23= {247333303d20225669}
		 $hex24= {2473333d2022427261}
		 $hex25= {2473343d202243656e}
		 $hex26= {2473353d2022436872}
		 $hex27= {2473363d2022436f6d}
		 $hex28= {2473373d2022436f6d}
		 $hex29= {2473383d2022433a55}
		 $hex30= {2473393d2022456c65}

	condition:
		3 of them
}
