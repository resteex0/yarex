
/*
   YARA Rule Set
   Author: resteex
   Identifier: Amavaldo 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Amavaldo {
	meta: 
		 description= "Amavaldo Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_23-46-15" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1091a566e2f44bada1f814998034bd04"
		 hash2= "45c01734ed56c52797156620a5f8b414"
		 hash3= "4a3cdcef8ed41b221f3dbef5792fb52d"
		 hash4= "55ffee241709ae96cf64cb0b9a96f0d7"
		 hash5= "6f2bf181f8b9ca1d28465ed6bab6f3e2"
		 hash6= "88eca26e7f720a3faa94864359681590"
		 hash7= "9f1e5d66c2889018daef4aef604eebc4"
		 hash8= "df3e0e32d1e1fb50cc292aebc5e5b322"
		 hash9= "e880c09454a68b4714c6f184f7968070"

	strings:

	
 		 $s1= "{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}" fullword wide
		 $s2= "{43826D1E-E718-42EE-BC55-A1E261C37BFE}" fullword wide
		 $s3= "{4C5C32FF-BB9D-43b0-B5B4-2D72E54EAAA4}" fullword wide
		 $s4= "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3dZ" fullword wide
		 $s5= "6.1.7600.16385 (win7_rtm.090713-1255)" fullword wide
		 $s6= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s7= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s8= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s9= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s10= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s11= "application/x-javascript; charset=UTF-8" fullword wide
		 $s12= ".document.forms[0].IW_MainPageSubmitControlParam.value=AParam;" fullword wide
		 $s13= ".document.forms[0].IW_MainPageSubmitControl.value=AName;" fullword wide
		 $s14= "document.getElementById('ProgressIndicatorBox').style.visibility='hidden';" fullword wide
		 $s15= "document.getElementById('ProgressIndicatorBox').style.visibility='visible';" fullword wide
		 $s16= "document.getElementById('ProgressIndicator').style.visibility='hidden';" fullword wide
		 $s17= "document.getElementById('ProgressIndicator').style.visibility='visible';" fullword wide
		 $s18= "{ED4824AF-DCE4-45A8-81E2-FC7965083634}" fullword wide
		 $s19= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s20= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s21= "Fapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s22= "function SubmitNextFile(AName,AParam){" fullword wide
		 $s23= "GlobalCplShutdown-8D5475ED-3A12-4f45-9ACE-23289E49C0DF" fullword wide
		 $s24= "GRP_RID_INCOMING_FOREST_TRUST_BUILDERS" fullword wide
		 $s25= "if (window.focus) {xNewWindow.focus()};" fullword wide
		 $s26= "IsThemeBackgroundPartiallyTransparent" fullword wide
		 $s27= "IWCL.Rect = IWTop().CopyRect(lRect);" fullword wide
		 $s28= "[LocalAppDataFolder]ProgramsCommon" fullword wide
		 $s29= "position:absolute;left:-1000px;top:-1000px" fullword wide
		 $s30= "q|%n nr{rk2#4r!2/!m%r( or#n*}n.u#m6#!+" fullword wide
		 $s31= "SoftwareCaphyonAdvanced Installer" fullword wide
		 $s32= "SoftwareCaphyonAdvanced InstallerInstallation Path" fullword wide
		 $s33= "SoftwareJavaSoftJava Development Kit" fullword wide
		 $s34= "SoftwareJavaSoftJava Runtime Environment" fullword wide
		 $s35= "SOFTWAREMicrosoftWindows NTCurrentVersionFontSubstitutes" fullword wide
		 $s36= "SYSTEMCurrentControlSetControlKeyboard Layouts" fullword wide
		 $s37= "SystemCurrentControlSetControlKeyboard Layouts%.8x" fullword wide
		 $s38= "text/css, text/js, application/x-javascript" fullword wide
		 $a1= "ext_BrowseBr&owse...NewDirIconNewButtonText_Return&ReturnButtonText_Ignore&IgnoreButtonText_Exit&ExitCtrlEvtrepairsrepairsDefaultUIFontDlgFont8CtrlEvt" fullword ascii
		 $a2= "ss2installsAI_FrameColorsteelblueCompleteSetupIconcompletiAiStyleConditions CustomSetupIconcusticonInfoIconinfoAI_PACKAGE_TYPEIntelAI_BUILD_NAMEDefaul" fullword ascii
		 $a3= "tlGroupHeaderCloseSelectedHot$tlGroupHeaderCloseSelectedNotFocused'tlGroupHeaderCloseSelectedNotFocusedHot tlGroupHeaderCloseMixedSelection#tlGroupHea" fullword ascii
		 $a4= "tlGroupHeaderLineCloseSelected!tlGroupHeaderLineCloseSelectedHot(tlGroupHeaderLineCloseSelectedNotFocused+tlGroupHeaderLineCloseSelectedNotFocusedHot$" fullword ascii
		 $a5= "tlGroupHeaderLineOpenSelected tlGroupHeaderLineOpenSelectedHot'tlGroupHeaderLineOpenSelectedNotFocused*tlGroupHeaderLineOpenSelectedNotFocusedHot#tlGr" fullword ascii

		 $hex1= {2461313d2022657874}
		 $hex2= {2461323d2022737332}
		 $hex3= {2461333d2022746c47}
		 $hex4= {2461343d2022746c47}
		 $hex5= {2461353d2022746c47}
		 $hex6= {247331303d20226170}
		 $hex7= {247331313d20226170}
		 $hex8= {247331323d20222e64}
		 $hex9= {247331333d20222e64}
		 $hex10= {247331343d2022646f}
		 $hex11= {247331353d2022646f}
		 $hex12= {247331363d2022646f}
		 $hex13= {247331373d2022646f}
		 $hex14= {247331383d20227b45}
		 $hex15= {247331393d20226578}
		 $hex16= {2473313d20227b3142}
		 $hex17= {247332303d20226578}
		 $hex18= {247332313d20224661}
		 $hex19= {247332323d20226675}
		 $hex20= {247332333d2022476c}
		 $hex21= {247332343d20224752}
		 $hex22= {247332353d20226966}
		 $hex23= {247332363d20224973}
		 $hex24= {247332373d20224957}
		 $hex25= {247332383d20225b4c}
		 $hex26= {247332393d2022706f}
		 $hex27= {2473323d20227b3433}
		 $hex28= {247333303d2022717c}
		 $hex29= {247333313d2022536f}
		 $hex30= {247333323d2022536f}
		 $hex31= {247333333d2022536f}
		 $hex32= {247333343d2022536f}
		 $hex33= {247333353d2022534f}
		 $hex34= {247333363d20225359}
		 $hex35= {247333373d20225379}
		 $hex36= {247333383d20227465}
		 $hex37= {2473333d20227b3443}
		 $hex38= {2473343d2022252e34}
		 $hex39= {2473353d2022362e31}
		 $hex40= {2473363d2022617069}
		 $hex41= {2473373d2022617069}
		 $hex42= {2473383d2022617069}
		 $hex43= {2473393d2022617069}

	condition:
		5 of them
}
