
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
		 date = "2022-01-14_22-52-50" 
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
		 $a1= "http://159.138.84.217:81/c0c00c0c/AddTaskPlanDllVerson.dll" fullword ascii
		 $a2= "https://flash-update.buyonebuy.top/download.php?raw=1" fullword ascii

		 $hex1= {2461313d2022687474}
		 $hex2= {2461323d2022687474}
		 $hex3= {247331303d20226170}
		 $hex4= {247331313d20226170}
		 $hex5= {247331323d20226170}
		 $hex6= {247331333d20226170}
		 $hex7= {247331343d20226170}
		 $hex8= {247331353d20226170}
		 $hex9= {247331363d20226170}
		 $hex10= {247331373d20224170}
		 $hex11= {247331383d2022436c}
		 $hex12= {247331393d20225f5f}
		 $hex13= {2473313d2022617069}
		 $hex14= {247332303d20225f5f}
		 $hex15= {247332313d2022433a}
		 $hex16= {247332323d20224469}
		 $hex17= {247332333d20226578}
		 $hex18= {247332343d20226578}
		 $hex19= {247332353d20226578}
		 $hex20= {247332363d20225f5f}
		 $hex21= {247332373d20226874}
		 $hex22= {247332383d20226874}
		 $hex23= {247332393d20226874}
		 $hex24= {2473323d2022617069}
		 $hex25= {247333303d20226874}
		 $hex26= {247333313d20225f5f}
		 $hex27= {247333323d20224d69}
		 $hex28= {247333333d20226d69}
		 $hex29= {247333343d20225275}
		 $hex30= {247333353d20227370}
		 $hex31= {247333363d20225359}
		 $hex32= {2473333d2022617069}
		 $hex33= {2473343d2022617069}
		 $hex34= {2473353d2022617069}
		 $hex35= {2473363d2022617069}
		 $hex36= {2473373d2022617069}
		 $hex37= {2473383d2022617069}
		 $hex38= {2473393d2022617069}

	condition:
		25 of them
}
