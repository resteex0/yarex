
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_TripleFantasy 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_TripleFantasy {
	meta: 
		 description= "EquationGroup_TripleFantasy Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-58" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "9180d5affe1e5df0717d7385e7f54386"

	strings:

	
 		 $s1= "=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "Moniter Resource Protocol" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "Original Innovations, LLC." fullword wide
		 $s6= "Original Innovations, LLC" fullword wide
		 $s7= "VS_VERSION_INFO" fullword wide
		 $a1= "8(9.949:9@9F9M9T9[9b9i9p9w9" fullword ascii
		 $a2= "ExpandEnvironmentStringsW" fullword ascii
		 $a3= "Global{8c38e4f3-591f-91cf-06a6-67b84d8a0102}" fullword ascii
		 $a4= "hnetcfg.DllGetClassObject" fullword ascii
		 $a5= "hnetcfg.DllRegisterServer" fullword ascii
		 $a6= "hnetcfg.DllUnregisterServer" fullword ascii
		 $a7= "hnetcfg.HNetDeleteRasConnection" fullword ascii
		 $a8= "hnetcfg.HNetFreeFirewallLoggingSettings" fullword ascii
		 $a9= "hnetcfg.HNetFreeSharingServicesPage" fullword ascii
		 $a10= "hnetcfg.HNetGetFirewallSettingsPage" fullword ascii
		 $a11= "hnetcfg.HNetGetShareAndBridgeSettings" fullword ascii
		 $a12= "hnetcfg.HNetGetSharingServicesPage" fullword ascii
		 $a13= "hnetcfg.HNetSetShareAndBridgeSettings" fullword ascii
		 $a14= "hnetcfg.HNetSharedAccessSettingsDlg" fullword ascii
		 $a15= "hnetcfg.HNetSharingAndFirewallSettingsDlg" fullword ascii
		 $a16= "hnetcfg.IcfChangeNotificationCreate" fullword ascii
		 $a17= "hnetcfg.IcfChangeNotificationDestroy" fullword ascii
		 $a18= "hnetcfg.IcfCheckAppAuthorization" fullword ascii
		 $a19= "hnetcfg.IcfCloseDynamicFwPort" fullword ascii
		 $a20= "hnetcfg.IcfFreeDynamicFwPorts" fullword ascii
		 $a21= "hnetcfg.IcfGetCurrentProfileType" fullword ascii
		 $a22= "hnetcfg.IcfGetDynamicFwPorts" fullword ascii
		 $a23= "hnetcfg.IcfGetOperationalMode" fullword ascii
		 $a24= "hnetcfg.IcfIsIcmpTypeAllowed" fullword ascii
		 $a25= "hnetcfg.IcfOpenDynamicFwPort" fullword ascii
		 $a26= "hnetcfg.IcfOpenDynamicFwPortWithoutSocket" fullword ascii
		 $a27= "hnetcfg.IcfOpenFileSharingPorts" fullword ascii
		 $a28= "hnetcfg.IcfRemoveDisabledAuthorizedApp" fullword ascii
		 $a29= "hnetcfg.IcfSetServicePermission" fullword ascii
		 $a30= "hnetcfg.IcfSubNetsGetScope" fullword ascii
		 $a31= "hnetcfg.IcfSubNetsIsStringValid" fullword ascii
		 $a32= "hnetcfg.IcfSubNetsToString" fullword ascii
		 $a33= "hnetcfg.RegisterClassObjects" fullword ascii
		 $a34= "hnetcfg.ReleaseSingletons" fullword ascii
		 $a35= "hnetcfg.RevokeClassObjects" fullword ascii
		 $a36= "hnetcfg.WinBomConfigureHomeNet" fullword ascii
		 $a37= "hnetcfg.WinBomConfigureWindowsFirewall" fullword ascii
		 $a38= "HNetFreeFirewallLoggingSettings" fullword ascii
		 $a39= "HNetFreeSharingServicesPage" fullword ascii
		 $a40= "HNetGetFirewallSettingsPage" fullword ascii
		 $a41= "HNetGetShareAndBridgeSettings" fullword ascii
		 $a42= "HNetGetSharingServicesPage" fullword ascii
		 $a43= "HNetSetShareAndBridgeSettings" fullword ascii
		 $a44= "HNetSharedAccessSettingsDlg" fullword ascii
		 $a45= "HNetSharingAndFirewallSettingsDlg" fullword ascii
		 $a46= "IcfChangeNotificationCreate" fullword ascii
		 $a47= "IcfChangeNotificationDestroy" fullword ascii
		 $a48= "IcfOpenDynamicFwPortWithoutSocket" fullword ascii
		 $a49= "IcfRemoveDisabledAuthorizedApp" fullword ascii
		 $a50= "InterlockedCompareExchange" fullword ascii
		 $a51= "SetUnhandledExceptionFilter" fullword ascii
		 $a52= "WinBomConfigureWindowsFirewall" fullword ascii

		 $hex1= {246131303d2022686e}
		 $hex2= {246131313d2022686e}
		 $hex3= {246131323d2022686e}
		 $hex4= {246131333d2022686e}
		 $hex5= {246131343d2022686e}
		 $hex6= {246131353d2022686e}
		 $hex7= {246131363d2022686e}
		 $hex8= {246131373d2022686e}
		 $hex9= {246131383d2022686e}
		 $hex10= {246131393d2022686e}
		 $hex11= {2461313d2022382839}
		 $hex12= {246132303d2022686e}
		 $hex13= {246132313d2022686e}
		 $hex14= {246132323d2022686e}
		 $hex15= {246132333d2022686e}
		 $hex16= {246132343d2022686e}
		 $hex17= {246132353d2022686e}
		 $hex18= {246132363d2022686e}
		 $hex19= {246132373d2022686e}
		 $hex20= {246132383d2022686e}
		 $hex21= {246132393d2022686e}
		 $hex22= {2461323d2022457870}
		 $hex23= {246133303d2022686e}
		 $hex24= {246133313d2022686e}
		 $hex25= {246133323d2022686e}
		 $hex26= {246133333d2022686e}
		 $hex27= {246133343d2022686e}
		 $hex28= {246133353d2022686e}
		 $hex29= {246133363d2022686e}
		 $hex30= {246133373d2022686e}
		 $hex31= {246133383d2022484e}
		 $hex32= {246133393d2022484e}
		 $hex33= {2461333d2022476c6f}
		 $hex34= {246134303d2022484e}
		 $hex35= {246134313d2022484e}
		 $hex36= {246134323d2022484e}
		 $hex37= {246134333d2022484e}
		 $hex38= {246134343d2022484e}
		 $hex39= {246134353d2022484e}
		 $hex40= {246134363d20224963}
		 $hex41= {246134373d20224963}
		 $hex42= {246134383d20224963}
		 $hex43= {246134393d20224963}
		 $hex44= {2461343d2022686e65}
		 $hex45= {246135303d2022496e}
		 $hex46= {246135313d20225365}
		 $hex47= {246135323d20225769}
		 $hex48= {2461353d2022686e65}
		 $hex49= {2461363d2022686e65}
		 $hex50= {2461373d2022686e65}
		 $hex51= {2461383d2022686e65}
		 $hex52= {2461393d2022686e65}
		 $hex53= {2473313d20223d3e3f}
		 $hex54= {2473323d202246696c}
		 $hex55= {2473333d20224d6f6e}
		 $hex56= {2473343d20224f7269}
		 $hex57= {2473353d20224f7269}
		 $hex58= {2473363d20224f7269}
		 $hex59= {2473373d202256535f}

	condition:
		7 of them
}
