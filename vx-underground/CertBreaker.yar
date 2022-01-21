
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_CertBreaker 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_CertBreaker {
	meta: 
		 description= "vx_underground2_CertBreaker Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-53-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "7e0e9bde7fcd5080fad1878f7145fae4"
		 hash2= "8659d6f32dbe6015ec76f1834cac6113"

	strings:

	
 		 $s1= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s4= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s5= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s6= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s7= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s8= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s9= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s10= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s11= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s12= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s13= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s14= "BLUE_IDB_OFFICE2007_GRIPPER" fullword wide
		 $s15= "BLUE_IDB_OFFICE2007_TAB_3D" fullword wide
		 $s16= "BLUE_IDX_OFFICE2007_STYLE" fullword wide
		 $s17= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s18= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s19= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s20= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s21= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s22= "iapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s23= "japi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s24= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s25= "SILVER_IDB_OFFICE2007_GRIPPER" fullword wide
		 $s26= "SILVER_IDB_OFFICE2007_TAB_3D" fullword wide
		 $s27= "spanish-dominican republic" fullword wide
		 $s28= "Window Position &Floating" fullword wide
		 $s29= "WINDOWS7_IDB_MENU_BTN_DISABLED" fullword wide
		 $s30= "WINDOWS7_IDB_MENU_ITEM_BACK" fullword wide
		 $s31= "WINDOWS7_IDB_MENU_ITEM_MARKER_C" fullword wide
		 $s32= "WINDOWS7_IDB_MENU_ITEM_MARKER_R" fullword wide
		 $s33= "WINDOWS7_IDB_RIBBON_BORDER_QAT WINDOWS7_IDB_RIBBON_BORDER_PANEL" fullword wide
		 $s34= "WINDOWS7_IDB_RIBBON_BTN_GROUP_F" fullword wide
		 $s35= "WINDOWS7_IDB_RIBBON_BTN_GROUP_L" fullword wide
		 $s36= "WINDOWS7_IDB_RIBBON_BTN_GROUP_M" fullword wide
		 $s37= "WINDOWS7_IDB_RIBBON_BTN_MAIN" fullword wide
		 $s38= "WINDOWS7_IDB_RIBBON_BTN_PAGE_L" fullword wide
		 $s39= "WINDOWS7_IDB_RIBBON_BTN_PAGE_R" fullword wide
		 $s40= "WINDOWS7_IDB_RIBBON_PANEL_MAIN" fullword wide
		 $a1= ".?AVCancellationTokenRegistration_TaskProc@details@Concurrency@@" fullword ascii
		 $a2= ".?AVinvalid_scheduler_policy_thread_specification@Concurrency@@" fullword ascii
		 $a3= "http://cacerts.digicert.com/DigiCertEVCodeSigningCA-SHA2.crt0" fullword ascii

		 $hex1= {2461313d20222e3f41}
		 $hex2= {2461323d20222e3f41}
		 $hex3= {2461333d2022687474}
		 $hex4= {247331303d20226170}
		 $hex5= {247331313d20226170}
		 $hex6= {247331323d20226170}
		 $hex7= {247331333d20226170}
		 $hex8= {247331343d2022424c}
		 $hex9= {247331353d2022424c}
		 $hex10= {247331363d2022424c}
		 $hex11= {247331373d20225f5f}
		 $hex12= {247331383d20225f5f}
		 $hex13= {247331393d20226578}
		 $hex14= {2473313d2022617069}
		 $hex15= {247332303d20226578}
		 $hex16= {247332313d20226578}
		 $hex17= {247332323d20226961}
		 $hex18= {247332333d20226a61}
		 $hex19= {247332343d20226d69}
		 $hex20= {247332353d20225349}
		 $hex21= {247332363d20225349}
		 $hex22= {247332373d20227370}
		 $hex23= {247332383d20225769}
		 $hex24= {247332393d20225749}
		 $hex25= {2473323d2022617069}
		 $hex26= {247333303d20225749}
		 $hex27= {247333313d20225749}
		 $hex28= {247333323d20225749}
		 $hex29= {247333333d20225749}
		 $hex30= {247333343d20225749}
		 $hex31= {247333353d20225749}
		 $hex32= {247333363d20225749}
		 $hex33= {247333373d20225749}
		 $hex34= {247333383d20225749}
		 $hex35= {247333393d20225749}
		 $hex36= {2473333d2022617069}
		 $hex37= {247334303d20225749}
		 $hex38= {2473343d2022617069}
		 $hex39= {2473353d2022617069}
		 $hex40= {2473363d2022617069}
		 $hex41= {2473373d2022617069}
		 $hex42= {2473383d2022617069}
		 $hex43= {2473393d2022617069}

	condition:
		28 of them
}
