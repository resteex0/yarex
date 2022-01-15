
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
		 date = "2022-01-14_21-39-33" 
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

	
 		 $s1= "2099-05-02T10:52:02" fullword wide
		 $s2= "american english" fullword wide
		 $s3= "american-english" fullword wide
		 $s4= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s5= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s6= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s7= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s8= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s9= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s10= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s11= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s12= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s13= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s14= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s15= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s16= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s17= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s18= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s19= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s20= "ApplicationsVMwareHostOpen.exe" fullword wide
		 $s21= "Assembly Version" fullword wide
		 $s22= "chinese-hongkong" fullword wide
		 $s23= "chinese-simplified" fullword wide
		 $s24= "chinese-singapore" fullword wide
		 $s25= "chinese-traditional" fullword wide
		 $s26= "ClipboardDataObjectInterface" fullword wide
		 $s27= "CLIPBRDWNDCLASS" fullword wide
		 $s28= "CoCreateInstance" fullword wide
		 $s29= "CoInitializeSecurity" fullword wide
		 $s30= "CommandLineEventConsumer" fullword wide
		 $s31= "CommandLineTemplate" fullword wide
		 $s32= "ConsoleApp2.exe" fullword wide
		 $s33= "CoSetProxyBlanket" fullword wide
		 $s34= "CreateFile fail!" fullword wide
		 $s35= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s36= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s37= "C:Windowsexplorer.exe" fullword wide
		 $s38= "C:WindowsSystem32VBox*.dll" fullword wide
		 $s39= "DisallowStartIfOnBatteries" fullword wide
		 $s40= "DotNetLoader.exe" fullword wide
		 $s41= "DotNetLoader.Program" fullword wide
		 $s42= "english-american" fullword wide
		 $s43= "english-caribbean" fullword wide
		 $s44= "english-jamaica" fullword wide
		 $s45= "english-south africa" fullword wide
		 $s46= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s47= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s48= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s49= "FileDescription" fullword wide
		 $s50= "__FilterToConsumerBinding" fullword wide
		 $s51= "FlashUpdate.exe" fullword wide
		 $s52= "FlashUpdate.exe" fullword wide
		 $s53= "french-canadian" fullword wide
		 $s54= "french-luxembourg" fullword wide
		 $s55= "german-austrian" fullword wide
		 $s56= "german-lichtenstein" fullword wide
		 $s57= "german-luxembourg" fullword wide
		 $s58= "http://159.138.84.217:81/c0c00c0c/AddTaskPlanDllVerson.dll" fullword wide
		 $s59= "http://flash-update.buyonebuy.top/flach.php" fullword wide
		 $s60= "https://flash-update.buyonebuy.top/download.php?raw=1" fullword wide
		 $s61= "http://update.flach.cn/download.php?raw=1" fullword wide
		 $s62= "__InstanceModificationEvent" fullword wide
		 $s63= "i\\.PhysicalDrive0" fullword wide
		 $s64= "LegalTrademarks" fullword wide
		 $s65= "MicrosoftWindowsApplication Experience" fullword wide
		 $s66= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s67= "MircoSoft Excel" fullword wide
		 $s68= "MircoSoft Office" fullword wide
		 $s69= "norwegian-bokmal" fullword wide
		 $s70= "norwegian-nynorsk" fullword wide
		 $s71= "OriginalFilename" fullword wide
		 $s72= "\\.PhysicalDrive0" fullword wide
		 $s73= "portuguese-brazilian" fullword wide
		 $s74= "RegisterTaskDefinition" fullword wide
		 $s75= "RegistrationInfo" fullword wide
		 $s76= "RunOnlyIfNetworkAvailable" fullword wide
		 $s77= "Schedule.Service" fullword wide
		 $s78= "spanish-argentina" fullword wide
		 $s79= "spanish-bolivia" fullword wide
		 $s80= "spanish-colombia" fullword wide
		 $s81= "spanish-costa rica" fullword wide
		 $s82= "spanish-dominican republic" fullword wide
		 $s83= "spanish-ecuador" fullword wide
		 $s84= "spanish-el salvador" fullword wide
		 $s85= "spanish-guatemala" fullword wide
		 $s86= "spanish-honduras" fullword wide
		 $s87= "spanish-mexican" fullword wide
		 $s88= "spanish-nicaragua" fullword wide
		 $s89= "spanish-paraguay" fullword wide
		 $s90= "spanish-puerto rico" fullword wide
		 $s91= "spanish-uruguay" fullword wide
		 $s92= "spanish-venezuela" fullword wide
		 $s93= "StartWhenAvailable" fullword wide
		 $s94= "swedish-finland" fullword wide
		 $s95= "system32cmd.exe" fullword wide
		 $s96= "SYSTEMControlSet001ServicesVBoxSF" fullword wide
		 $s97= "VS_VERSION_INFO" fullword wide
		 $s98= "Writefile success" fullword wide
		 $a1= "api-ms-win-core-localization-l1-2-1" fullword ascii
		 $a2= "api-ms-win-core-localization-obsolete-l1-2-0" fullword ascii
		 $a3= "api-ms-win-core-processthreads-l1-1-2" fullword ascii
		 $a4= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword ascii
		 $a5= "api-ms-win-security-systemfunctions-l1-1-0" fullword ascii
		 $a6= "__crt_strtox::floating_point_value::as_double" fullword ascii
		 $a7= "__crt_strtox::floating_point_value::as_float" fullword ascii
		 $a8= "ext-ms-win-kernel32-package-current-l1-1-0" fullword ascii
		 $a9= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword ascii
		 $a10= "http://159.138.84.217:81/c0c00c0c/AddTaskPlanDllVerson.dll" fullword ascii
		 $a11= "http://flash-update.buyonebuy.top/flach.php" fullword ascii
		 $a12= "https://flash-update.buyonebuy.top/download.php?raw=1" fullword ascii
		 $a13= "http://update.flach.cn/download.php?raw=1" fullword ascii
		 $a14= "MicrosoftWindowsApplication Experience" fullword ascii
		 $a15= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword ascii
		 $a16= "SYSTEMControlSet001ServicesVBoxSF" fullword ascii

		 $hex1= {246131303d20226874}
		 $hex2= {246131313d20226874}
		 $hex3= {246131323d20226874}
		 $hex4= {246131333d20226874}
		 $hex5= {246131343d20224d69}
		 $hex6= {246131353d20226d69}
		 $hex7= {246131363d20225359}
		 $hex8= {2461313d2022617069}
		 $hex9= {2461323d2022617069}
		 $hex10= {2461333d2022617069}
		 $hex11= {2461343d2022617069}
		 $hex12= {2461353d2022617069}
		 $hex13= {2461363d20225f5f63}
		 $hex14= {2461373d20225f5f63}
		 $hex15= {2461383d2022657874}
		 $hex16= {2461393d2022657874}
		 $hex17= {247331303d20226170}
		 $hex18= {247331313d20226170}
		 $hex19= {247331323d20226170}
		 $hex20= {247331333d20226170}
		 $hex21= {247331343d20226170}
		 $hex22= {247331353d20226170}
		 $hex23= {247331363d20226170}
		 $hex24= {247331373d20226170}
		 $hex25= {247331383d20226170}
		 $hex26= {247331393d20226170}
		 $hex27= {2473313d2022323039}
		 $hex28= {247332303d20224170}
		 $hex29= {247332313d20224173}
		 $hex30= {247332323d20226368}
		 $hex31= {247332333d20226368}
		 $hex32= {247332343d20226368}
		 $hex33= {247332353d20226368}
		 $hex34= {247332363d2022436c}
		 $hex35= {247332373d2022434c}
		 $hex36= {247332383d2022436f}
		 $hex37= {247332393d2022436f}
		 $hex38= {2473323d2022616d65}
		 $hex39= {247333303d2022436f}
		 $hex40= {247333313d2022436f}
		 $hex41= {247333323d2022436f}
		 $hex42= {247333333d2022436f}
		 $hex43= {247333343d20224372}
		 $hex44= {247333353d20225f5f}
		 $hex45= {247333363d20225f5f}
		 $hex46= {247333373d2022433a}
		 $hex47= {247333383d2022433a}
		 $hex48= {247333393d20224469}
		 $hex49= {2473333d2022616d65}
		 $hex50= {247334303d2022446f}
		 $hex51= {247334313d2022446f}
		 $hex52= {247334323d2022656e}
		 $hex53= {247334333d2022656e}
		 $hex54= {247334343d2022656e}
		 $hex55= {247334353d2022656e}
		 $hex56= {247334363d20226578}
		 $hex57= {247334373d20226578}
		 $hex58= {247334383d20226578}
		 $hex59= {247334393d20224669}
		 $hex60= {2473343d2022617069}
		 $hex61= {247335303d20225f5f}
		 $hex62= {247335313d2022466c}
		 $hex63= {247335323d2022466c}
		 $hex64= {247335333d20226672}
		 $hex65= {247335343d20226672}
		 $hex66= {247335353d20226765}
		 $hex67= {247335363d20226765}
		 $hex68= {247335373d20226765}
		 $hex69= {247335383d20226874}
		 $hex70= {247335393d20226874}
		 $hex71= {2473353d2022617069}
		 $hex72= {247336303d20226874}
		 $hex73= {247336313d20226874}
		 $hex74= {247336323d20225f5f}
		 $hex75= {247336333d2022692e}
		 $hex76= {247336343d20224c65}
		 $hex77= {247336353d20224d69}
		 $hex78= {247336363d20226d69}
		 $hex79= {247336373d20224d69}
		 $hex80= {247336383d20224d69}
		 $hex81= {247336393d20226e6f}
		 $hex82= {2473363d2022617069}
		 $hex83= {247337303d20226e6f}
		 $hex84= {247337313d20224f72}
		 $hex85= {247337323d20222e50}
		 $hex86= {247337333d2022706f}
		 $hex87= {247337343d20225265}
		 $hex88= {247337353d20225265}
		 $hex89= {247337363d20225275}
		 $hex90= {247337373d20225363}
		 $hex91= {247337383d20227370}
		 $hex92= {247337393d20227370}
		 $hex93= {2473373d2022617069}
		 $hex94= {247338303d20227370}
		 $hex95= {247338313d20227370}
		 $hex96= {247338323d20227370}
		 $hex97= {247338333d20227370}
		 $hex98= {247338343d20227370}
		 $hex99= {247338353d20227370}
		 $hex100= {247338363d20227370}
		 $hex101= {247338373d20227370}
		 $hex102= {247338383d20227370}
		 $hex103= {247338393d20227370}
		 $hex104= {2473383d2022617069}
		 $hex105= {247339303d20227370}
		 $hex106= {247339313d20227370}
		 $hex107= {247339323d20227370}
		 $hex108= {247339333d20225374}
		 $hex109= {247339343d20227377}
		 $hex110= {247339353d20227379}
		 $hex111= {247339363d20225359}
		 $hex112= {247339373d20225653}
		 $hex113= {247339383d20225772}
		 $hex114= {2473393d2022617069}

	condition:
		38 of them
}
