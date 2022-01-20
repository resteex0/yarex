
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_RedDelta 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_RedDelta {
	meta: 
		 description= "Win32_RedDelta Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-40" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2ec79d0605a4756f4732aba16ef41b22"
		 hash2= "660d1132888b2a2ff83b695e65452f87"
		 hash3= "83763fe02f41c1b3ce099f277391732a"
		 hash4= "c6206b8eacabc1dc3578cec2b91c949a"
		 hash5= "e57f8364372e3ba866389c2895b42628"

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
		 $s10= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s11= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s12= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s13= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s14= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s15= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s16= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s17= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s18= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s19= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s20= "spanish-dominican republic" fullword wide

		 $hex1= {247331303d20226170}
		 $hex2= {247331313d20226170}
		 $hex3= {247331323d20226170}
		 $hex4= {247331333d20226170}
		 $hex5= {247331343d20226170}
		 $hex6= {247331353d20225f5f}
		 $hex7= {247331363d20225f5f}
		 $hex8= {247331373d20226578}
		 $hex9= {247331383d20226578}
		 $hex10= {247331393d20226d69}
		 $hex11= {2473313d2022617069}
		 $hex12= {247332303d20227370}
		 $hex13= {2473323d2022617069}
		 $hex14= {2473333d2022617069}
		 $hex15= {2473343d2022617069}
		 $hex16= {2473353d2022617069}
		 $hex17= {2473363d2022617069}
		 $hex18= {2473373d2022617069}
		 $hex19= {2473383d2022617069}
		 $hex20= {2473393d2022617069}

	condition:
		13 of them
}
