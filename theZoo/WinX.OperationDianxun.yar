
/*
   YARA Rule Set
   Author: resteex
   Identifier: WinX_OperationDianxun 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_WinX_OperationDianxun {
	meta: 
		 description= "WinX_OperationDianxun Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-45-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "029349d7b378245e1cdc964e21130789"
		 hash2= "1ec914ef8443a1fb259c79b038e64ebf"
		 hash3= "4bb44c229b5ebd44bfabffdbb3635d8b"
		 hash4= "60d083b7c74cc84f38074a5d02a2c07c"
		 hash5= "62779df699c84d665c17c2e217015269"
		 hash6= "675593b67e2c028e1f4270ea4c7ad757"
		 hash7= "95504605bf08d6ffa7c58350cce56478"
		 hash8= "9ee75cd19b3bed6179e81297ae92bd7b"
		 hash9= "a41843d3f65a0381392dad90affa7893"
		 hash10= "a8e3b108e5ccf3d1d0d8fb34e5f96391"
		 hash11= "b748ce395a511824dc753a247fdeed93"
		 hash12= "d79319202727689544cbbbb5c2be59bc"
		 hash13= "de8307a4472b5f0fa0eb2308b169b00f"
		 hash14= "ff76d7009d93b6b9c9d8af81a3a77587"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s3= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s6= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s7= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s8= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s9= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s10= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s11= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s12= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s13= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s14= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s15= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s16= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s17= "ApplicationsVMwareHostOpen.exe" fullword wide
		 $s18= "ClipboardDataObjectInterface" fullword wide
		 $s19= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s20= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s21= "C:WindowsSystem32VBox*.dll" fullword wide
		 $s22= "DisallowStartIfOnBatteries" fullword wide
		 $s23= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s24= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s25= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s26= "__FilterToConsumerBinding" fullword wide
		 $s27= "http://159.138.84.217:81/c0c00c0c/AddTaskPlanDllVerson.dll" fullword wide
		 $s28= "http://flash-update.buyonebuy.top/flach.php" fullword wide
		 $s29= "https://flash-update.buyonebuy.top/download.php?raw=1" fullword wide
		 $s30= "http://update.flach.cn/download.php?raw=1" fullword wide
		 $s31= "__InstanceModificationEvent" fullword wide
		 $s32= "MicrosoftWindowsApplication Experience" fullword wide
		 $s33= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s34= "RunOnlyIfNetworkAvailable" fullword wide
		 $s35= "spanish-dominican republic" fullword wide
		 $s36= "SYSTEMControlSet001ServicesVBoxSF" fullword wide
		 $a1= "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
		 $a2= "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
		 $a3= "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
		 $a4= "/callback.php?token=%s&computername=%s&username=%s" fullword ascii
		 $a5= "C:UsersstandDesktopscloaderCLRLoaderMmloadMmLoadExe.cpp" fullword ascii
		 $a6= "http://worldtimeapi.org/api/timezone/Asia/Shanghai" fullword ascii

		 $hex1= {2461313d2022326874}
		 $hex2= {2461323d2022326874}
		 $hex3= {2461333d2022336874}
		 $hex4= {2461343d20222f6361}
		 $hex5= {2461353d2022433a55}
		 $hex6= {2461363d2022687474}
		 $hex7= {247331303d20226170}
		 $hex8= {247331313d20226170}
		 $hex9= {247331323d20226170}
		 $hex10= {247331333d20226170}
		 $hex11= {247331343d20226170}
		 $hex12= {247331353d20226170}
		 $hex13= {247331363d20226170}
		 $hex14= {247331373d20224170}
		 $hex15= {247331383d2022436c}
		 $hex16= {247331393d20225f5f}
		 $hex17= {2473313d2022617069}
		 $hex18= {247332303d20225f5f}
		 $hex19= {247332313d2022433a}
		 $hex20= {247332323d20224469}
		 $hex21= {247332333d20226578}
		 $hex22= {247332343d20226578}
		 $hex23= {247332353d20226578}
		 $hex24= {247332363d20225f5f}
		 $hex25= {247332373d20226874}
		 $hex26= {247332383d20226874}
		 $hex27= {247332393d20226874}
		 $hex28= {2473323d2022617069}
		 $hex29= {247333303d20226874}
		 $hex30= {247333313d20225f5f}
		 $hex31= {247333323d20224d69}
		 $hex32= {247333333d20226d69}
		 $hex33= {247333343d20225275}
		 $hex34= {247333353d20227370}
		 $hex35= {247333363d20225359}
		 $hex36= {2473333d2022617069}
		 $hex37= {2473343d2022617069}
		 $hex38= {2473353d2022617069}
		 $hex39= {2473363d2022617069}
		 $hex40= {2473373d2022617069}
		 $hex41= {2473383d2022617069}
		 $hex42= {2473393d2022617069}

	condition:
		28 of them
}
