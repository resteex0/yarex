
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Carberp 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Carberp {
	meta: 
		 description= "Win32_Carberp Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-32-09" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "11bba9b2333559b727caf22896092217"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "OriginalFilename" fullword wide
		 $s3= "VS_VERSION_INFO" fullword wide
		 $s4= "!x-sys-default-locale" fullword wide
		 $a1= "AddLocalAlternateComputerNameW" fullword ascii
		 $a2= "BaseCleanupAppcompatCacheSupport" fullword ascii
		 $a3= "CancelDeviceWakeupRequest" fullword ascii
		 $a4= "DebugSetProcessKillOnExit" fullword ascii
		 $a5= "EnumLanguageGroupLocalesW" fullword ascii
		 $a6= "ExpungeConsoleCommandHistoryW" fullword ascii
		 $a7= "FindFirstChangeNotificationW" fullword ascii
		 $a8= "FindFirstUrlCacheContainerW" fullword ascii
		 $a9= "FyGBCRj7DXnCRRjGgHg9Q5XxfSVc" fullword ascii
		 $a10= "GetConsoleKeyboardLayoutNameW" fullword ascii
		 $a11= "GetFileInformationByHandle" fullword ascii
		 $a12= "GetFirmwareEnvironmentVariableW" fullword ascii
		 $a13= "GetVolumePathNamesForVolumeNameA" fullword ascii
		 $a14= "InterlockedPushEntrySList" fullword ascii
		 $a15= "InternetConfirmZoneCrossingA" fullword ascii
		 $a16= "InternetEnumPerSiteCookieDecisionA" fullword ascii
		 $a17= "InternetGetLastResponseInfoW" fullword ascii
		 $a18= "InternetInitializeAutoProxyDll" fullword ascii
		 $a19= "InternetSecurityProtocolToStringW" fullword ascii
		 $a20= "InternetTimeFromSystemTime" fullword ascii
		 $a21= "ldap_create_sort_controlW" fullword ascii
		 $a22= "QueryInformationJobObject" fullword ascii
		 $a23= "RemoveLocalAlternateComputerNameA" fullword ascii
		 $a24= "RetrieveUrlCacheEntryStreamA" fullword ascii
		 $a25= "SetConsoleMaximumWindowSize" fullword ascii
		 $a26= "SetProcessShutdownParameters" fullword ascii
		 $a27= "Toolhelp32ReadProcessMemory" fullword ascii
		 $a28= "WSAGetServiceClassNameByClassIdA" fullword ascii

		 $hex1= {246131303d20224765}
		 $hex2= {246131313d20224765}
		 $hex3= {246131323d20224765}
		 $hex4= {246131333d20224765}
		 $hex5= {246131343d2022496e}
		 $hex6= {246131353d2022496e}
		 $hex7= {246131363d2022496e}
		 $hex8= {246131373d2022496e}
		 $hex9= {246131383d2022496e}
		 $hex10= {246131393d2022496e}
		 $hex11= {2461313d2022416464}
		 $hex12= {246132303d2022496e}
		 $hex13= {246132313d20226c64}
		 $hex14= {246132323d20225175}
		 $hex15= {246132333d20225265}
		 $hex16= {246132343d20225265}
		 $hex17= {246132353d20225365}
		 $hex18= {246132363d20225365}
		 $hex19= {246132373d2022546f}
		 $hex20= {246132383d20225753}
		 $hex21= {2461323d2022426173}
		 $hex22= {2461333d202243616e}
		 $hex23= {2461343d2022446562}
		 $hex24= {2461353d2022456e75}
		 $hex25= {2461363d2022457870}
		 $hex26= {2461373d202246696e}
		 $hex27= {2461383d202246696e}
		 $hex28= {2461393d2022467947}
		 $hex29= {2473313d202246696c}
		 $hex30= {2473323d20224f7269}
		 $hex31= {2473333d202256535f}
		 $hex32= {2473343d202221782d}

	condition:
		4 of them
}
