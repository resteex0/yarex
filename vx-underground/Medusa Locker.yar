
/*
   YARA Rule Set
   Author: resteex
   Identifier: Medusa_Locker 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Medusa_Locker {
	meta: 
		 description= "Medusa_Locker Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-15-36" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "501d18da4a3dd7f3118e4c8419c29dc3"

	strings:

	
 		 $s1= "{8761ABBD-7F85-42EE-B272-A76179687C63}" fullword wide
		 $s2= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s3= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s6= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s7= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s8= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s9= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s10= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s11= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s12= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s13= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s14= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s15= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s16= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s17= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s18= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s19= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s20= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s21= "Recovery_Instructions.mht" fullword wide
		 $s22= "SOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s23= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s24= "spanish-dominican republic" fullword wide
		 $a1= "SOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {247331303d20226170}
		 $hex3= {247331313d20226170}
		 $hex4= {247331323d20226170}
		 $hex5= {247331333d20226170}
		 $hex6= {247331343d20226170}
		 $hex7= {247331353d20226170}
		 $hex8= {247331363d20225f5f}
		 $hex9= {247331373d20225f5f}
		 $hex10= {247331383d20226578}
		 $hex11= {247331393d20226578}
		 $hex12= {2473313d20227b3837}
		 $hex13= {247332303d20226d69}
		 $hex14= {247332313d20225265}
		 $hex15= {247332323d2022534f}
		 $hex16= {247332333d2022536f}
		 $hex17= {247332343d20227370}
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
