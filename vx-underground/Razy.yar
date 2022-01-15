
/*
   YARA Rule Set
   Author: resteex
   Identifier: Razy 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Razy {
	meta: 
		 description= "Razy Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-05" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1e936aa4e23a8a846c873fc0b8a5e13e"
		 hash2= "2f858b2cdd1332777a75cb98481fe425"
		 hash3= "42cfb7889c4a5fb1e3ab405d6749ff5c"
		 hash4= "c937fc9ed4325e6ab24d49a3175f3a5c"
		 hash5= "d3b4611df87903b085c123e8506282f7"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s2= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s5= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s6= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s7= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s8= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s9= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s10= "api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s11= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s12= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s13= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s14= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s15= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s16= "Bapi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s17= "Bapi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s18= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s19= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s20= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s21= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s22= "../help/buttonThumbDown.bmp" fullword wide
		 $s23= "../help/buttonThumbUp.bmp" fullword wide
		 $s24= "https://github.com/AsayuGit" fullword wide
		 $s25= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide

		 $hex1= {247331303d20226170}
		 $hex2= {247331313d20226170}
		 $hex3= {247331323d20226170}
		 $hex4= {247331333d20226170}
		 $hex5= {247331343d20226170}
		 $hex6= {247331353d20226170}
		 $hex7= {247331363d20224261}
		 $hex8= {247331373d20224261}
		 $hex9= {247331383d20225f5f}
		 $hex10= {247331393d20225f5f}
		 $hex11= {2473313d2022617069}
		 $hex12= {247332303d20226578}
		 $hex13= {247332313d20226578}
		 $hex14= {247332323d20222e2e}
		 $hex15= {247332333d20222e2e}
		 $hex16= {247332343d20226874}
		 $hex17= {247332353d20226d69}
		 $hex18= {2473323d2022617069}
		 $hex19= {2473333d2022617069}
		 $hex20= {2473343d2022617069}
		 $hex21= {2473353d2022617069}
		 $hex22= {2473363d2022617069}
		 $hex23= {2473373d2022617069}
		 $hex24= {2473383d2022617069}
		 $hex25= {2473393d2022617069}

	condition:
		16 of them
}
