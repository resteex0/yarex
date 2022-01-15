
/*
   YARA Rule Set
   Author: resteex
   Identifier: Babadeda 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Babadeda {
	meta: 
		 description= "Babadeda Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_23-01-42" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0013ee610f83b401007adbefef051305"
		 hash2= "73311d203988335dea75e92d7d8eb1f5"
		 hash3= "bacfa288e5c0f18a8f2c94d208d7c760"
		 hash4= "e653f13bf4b225f1c7dce0e6404fc52a"
		 hash5= "ec538ff191a52b5ca9f67ae5d5d56908"

	strings:

	
 		 $s1= "!$).056;>ACENQVZZ^ceiow{{{~" fullword wide
		 $s2= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s3= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s6= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s7= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s8= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s9= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s10= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s11= "api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s12= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s13= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s14= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s15= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s16= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s17= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s18= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s19= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s20= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s21= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s22= "SDLHelperWindowInputCatcher" fullword wide
		 $s23= "SDLHelperWindowInputMsgWindow" fullword wide
		 $s24= "SOFTWAREMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s25= "spanish-dominican republic" fullword wide
		 $s26= "}{ywusqonkigfdb`^[YVVSRPMLJIGECB@?=;976431/.,+)(&$#! " fullword wide
		 $a1= "}{ywusqonkigfdb`^[YVVSRPMLJIGECB@?=;976431/.,+)(&$#! " fullword ascii

		 $hex1= {2461313d20227d7b79}
		 $hex2= {247331303d20226170}
		 $hex3= {247331313d20226170}
		 $hex4= {247331323d20226170}
		 $hex5= {247331333d20226170}
		 $hex6= {247331343d20226170}
		 $hex7= {247331353d20226170}
		 $hex8= {247331363d20226170}
		 $hex9= {247331373d20225f5f}
		 $hex10= {247331383d20225f5f}
		 $hex11= {247331393d20226578}
		 $hex12= {2473313d2022212429}
		 $hex13= {247332303d20226578}
		 $hex14= {247332313d20226d69}
		 $hex15= {247332323d20225344}
		 $hex16= {247332333d20225344}
		 $hex17= {247332343d2022534f}
		 $hex18= {247332353d20227370}
		 $hex19= {247332363d20227d7b}
		 $hex20= {2473323d2022617069}
		 $hex21= {2473333d2022617069}
		 $hex22= {2473343d2022617069}
		 $hex23= {2473353d2022617069}
		 $hex24= {2473363d2022617069}
		 $hex25= {2473373d2022617069}
		 $hex26= {2473383d2022617069}
		 $hex27= {2473393d2022617069}

	condition:
		18 of them
}
