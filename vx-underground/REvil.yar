
/*
   YARA Rule Set
   Author: resteex
   Identifier: REvil 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_REvil {
	meta: 
		 description= "REvil Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-17" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "395249d3e6dae1caff6b5b2e1f75bacd"
		 hash2= "3faef85636d1a6c20453e714693f0957"
		 hash3= "561cffbaba71a6e8cc1cdceda990ead4"
		 hash4= "6f208841cfd819c29a7cbc0a202bd7a3"
		 hash5= "78066a1c4e075941272a86d4a8e49471"
		 hash6= "a47cf00aedf769d60d58bfe00c0b5421"

	strings:

	
 		 $s1= "!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13" fullword wide
		 $s2= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s3= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s4= "@api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s6= "@api-ms-win-core-fibers-l1-1-1" fullword wide
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
		 $s20= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s21= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s22= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s23= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s24= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s25= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s26= "U_i=V`j>Wak?Xbl@YcmAZdnB[eoCfpD]gq" fullword wide
		 $a1= "!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13" fullword ascii

		 $hex1= {2461313d2022212325}
		 $hex2= {247331303d20226170}
		 $hex3= {247331313d20226170}
		 $hex4= {247331323d20226170}
		 $hex5= {247331333d20226170}
		 $hex6= {247331343d20226170}
		 $hex7= {247331353d20226170}
		 $hex8= {247331363d20226170}
		 $hex9= {247331373d20226170}
		 $hex10= {247331383d20226170}
		 $hex11= {247331393d20226170}
		 $hex12= {2473313d2022212325}
		 $hex13= {247332303d20225f5f}
		 $hex14= {247332313d20225f5f}
		 $hex15= {247332323d20226578}
		 $hex16= {247332333d20226578}
		 $hex17= {247332343d20226578}
		 $hex18= {247332353d20226d69}
		 $hex19= {247332363d2022555f}
		 $hex20= {2473323d2022617069}
		 $hex21= {2473333d2022617069}
		 $hex22= {2473343d2022406170}
		 $hex23= {2473353d2022617069}
		 $hex24= {2473363d2022406170}
		 $hex25= {2473373d2022617069}
		 $hex26= {2473383d2022617069}
		 $hex27= {2473393d2022617069}

	condition:
		18 of them
}
