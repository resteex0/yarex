
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
		 date = "2022-01-14_20-54-58" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2ec79d0605a4756f4732aba16ef41b22"
		 hash2= "660d1132888b2a2ff83b695e65452f87"
		 hash3= "83763fe02f41c1b3ce099f277391732a"
		 hash4= "c6206b8eacabc1dc3578cec2b91c949a"
		 hash5= "e57f8364372e3ba866389c2895b42628"

	strings:

	
 		 $s1= "american english" fullword wide
		 $s2= "american-english" fullword wide
		 $s3= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s4= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s6= "api-ms-win-core-file-l1-2-2" fullword wide
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
		 $s17= "chinese-hongkong" fullword wide
		 $s18= "chinese-simplified" fullword wide
		 $s19= "chinese-singapore" fullword wide
		 $s20= "chinese-traditional" fullword wide
		 $s21= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s22= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s23= "DotNetLoader.Program" fullword wide
		 $s24= "english-american" fullword wide
		 $s25= "english-caribbean" fullword wide
		 $s26= "english-jamaica" fullword wide
		 $s27= "english-south africa" fullword wide
		 $s28= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s29= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s30= "french-canadian" fullword wide
		 $s31= "french-luxembourg" fullword wide
		 $s32= "german-austrian" fullword wide
		 $s33= "german-lichtenstein" fullword wide
		 $s34= "german-luxembourg" fullword wide
		 $s35= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s36= "norwegian-bokmal" fullword wide
		 $s37= "norwegian-nynorsk" fullword wide
		 $s38= "portuguese-brazilian" fullword wide
		 $s39= "spanish-argentina" fullword wide
		 $s40= "spanish-bolivia" fullword wide
		 $s41= "spanish-colombia" fullword wide
		 $s42= "spanish-costa rica" fullword wide
		 $s43= "spanish-dominican republic" fullword wide
		 $s44= "spanish-ecuador" fullword wide
		 $s45= "spanish-el salvador" fullword wide
		 $s46= "spanish-guatemala" fullword wide
		 $s47= "spanish-honduras" fullword wide
		 $s48= "spanish-mexican" fullword wide
		 $s49= "spanish-nicaragua" fullword wide
		 $s50= "spanish-paraguay" fullword wide
		 $s51= "spanish-puerto rico" fullword wide
		 $s52= "spanish-uruguay" fullword wide
		 $s53= "spanish-venezuela" fullword wide
		 $s54= "swedish-finland" fullword wide
		 $a1= "api-ms-win-core-localization-l1-2-1" fullword ascii
		 $a2= "api-ms-win-core-localization-obsolete-l1-2-0" fullword ascii
		 $a3= "api-ms-win-core-processthreads-l1-1-2" fullword ascii
		 $a4= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword ascii
		 $a5= "api-ms-win-security-systemfunctions-l1-1-0" fullword ascii
		 $a6= "__crt_strtox::floating_point_value::as_double" fullword ascii
		 $a7= "__crt_strtox::floating_point_value::as_float" fullword ascii
		 $a8= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword ascii
		 $a9= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword ascii

		 $hex1= {2461313d2022617069}
		 $hex2= {2461323d2022617069}
		 $hex3= {2461333d2022617069}
		 $hex4= {2461343d2022617069}
		 $hex5= {2461353d2022617069}
		 $hex6= {2461363d20225f5f63}
		 $hex7= {2461373d20225f5f63}
		 $hex8= {2461383d2022657874}
		 $hex9= {2461393d20226d696e}
		 $hex10= {247331303d20226170}
		 $hex11= {247331313d20226170}
		 $hex12= {247331323d20226170}
		 $hex13= {247331333d20226170}
		 $hex14= {247331343d20226170}
		 $hex15= {247331353d20226170}
		 $hex16= {247331363d20226170}
		 $hex17= {247331373d20226368}
		 $hex18= {247331383d20226368}
		 $hex19= {247331393d20226368}
		 $hex20= {2473313d2022616d65}
		 $hex21= {247332303d20226368}
		 $hex22= {247332313d20225f5f}
		 $hex23= {247332323d20225f5f}
		 $hex24= {247332333d2022446f}
		 $hex25= {247332343d2022656e}
		 $hex26= {247332353d2022656e}
		 $hex27= {247332363d2022656e}
		 $hex28= {247332373d2022656e}
		 $hex29= {247332383d20226578}
		 $hex30= {247332393d20226578}
		 $hex31= {2473323d2022616d65}
		 $hex32= {247333303d20226672}
		 $hex33= {247333313d20226672}
		 $hex34= {247333323d20226765}
		 $hex35= {247333333d20226765}
		 $hex36= {247333343d20226765}
		 $hex37= {247333353d20226d69}
		 $hex38= {247333363d20226e6f}
		 $hex39= {247333373d20226e6f}
		 $hex40= {247333383d2022706f}
		 $hex41= {247333393d20227370}
		 $hex42= {2473333d2022617069}
		 $hex43= {247334303d20227370}
		 $hex44= {247334313d20227370}
		 $hex45= {247334323d20227370}
		 $hex46= {247334333d20227370}
		 $hex47= {247334343d20227370}
		 $hex48= {247334353d20227370}
		 $hex49= {247334363d20227370}
		 $hex50= {247334373d20227370}
		 $hex51= {247334383d20227370}
		 $hex52= {247334393d20227370}
		 $hex53= {2473343d2022617069}
		 $hex54= {247335303d20227370}
		 $hex55= {247335313d20227370}
		 $hex56= {247335323d20227370}
		 $hex57= {247335333d20227370}
		 $hex58= {247335343d20227377}
		 $hex59= {2473353d2022617069}
		 $hex60= {2473363d2022617069}
		 $hex61= {2473373d2022617069}
		 $hex62= {2473383d2022617069}
		 $hex63= {2473393d2022617069}

	condition:
		7 of them
}
