
/*
   YARA Rule Set
   Author: resteex
   Identifier: CertBreaker 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_CertBreaker {
	meta: 
		 description= "CertBreaker Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-01-21" 
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
		 $a1= "WINDOWS7_IDB_RIBBON_BORDER_QAT WINDOWS7_IDB_RIBBON_BORDER_PANEL" fullword ascii

		 $hex1= {2461313d202257494e}
		 $hex2= {247331303d20226170}
		 $hex3= {247331313d20226170}
		 $hex4= {247331323d20226170}
		 $hex5= {247331333d20226170}
		 $hex6= {247331343d2022424c}
		 $hex7= {247331353d2022424c}
		 $hex8= {247331363d2022424c}
		 $hex9= {247331373d20225f5f}
		 $hex10= {247331383d20225f5f}
		 $hex11= {247331393d20226578}
		 $hex12= {2473313d2022617069}
		 $hex13= {247332303d20226578}
		 $hex14= {247332313d20226578}
		 $hex15= {247332323d20226961}
		 $hex16= {247332333d20226a61}
		 $hex17= {247332343d20226d69}
		 $hex18= {247332353d20225349}
		 $hex19= {247332363d20225349}
		 $hex20= {247332373d20227370}
		 $hex21= {247332383d20225769}
		 $hex22= {247332393d20225749}
		 $hex23= {2473323d2022617069}
		 $hex24= {247333303d20225749}
		 $hex25= {247333313d20225749}
		 $hex26= {247333323d20225749}
		 $hex27= {247333333d20225749}
		 $hex28= {247333343d20225749}
		 $hex29= {247333353d20225749}
		 $hex30= {247333363d20225749}
		 $hex31= {247333373d20225749}
		 $hex32= {247333383d20225749}
		 $hex33= {247333393d20225749}
		 $hex34= {2473333d2022617069}
		 $hex35= {247334303d20225749}
		 $hex36= {2473343d2022617069}
		 $hex37= {2473353d2022617069}
		 $hex38= {2473363d2022617069}
		 $hex39= {2473373d2022617069}
		 $hex40= {2473383d2022617069}
		 $hex41= {2473393d2022617069}

	condition:
		27 of them
}
