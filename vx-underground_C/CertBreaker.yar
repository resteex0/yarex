
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
		 date = "2022-01-14_00-28-16" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "7e0e9bde7fcd5080fad1878f7145fae4"
		 hash2= "8659d6f32dbe6015ec76f1834cac6113"

	strings:

	
 		 $s1= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s2= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s3= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s4= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s5= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s6= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s7= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s8= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s9= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s10= "iapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s11= "japi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s12= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s13= "WINDOWS7_IDB_RIBBON_BORDER_QAT WINDOWS7_IDB_RIBBON_BORDER_PANEL" fullword wide
		 $a1= "WINDOWS7_IDB_RIBBON_BORDER_QAT WINDOWS7_IDB_RIBBON_BORDER_PANEL" fullword ascii

		 $hex1= {2461313d202257494e}
		 $hex2= {247331303d20226961}
		 $hex3= {247331313d20226a61}
		 $hex4= {247331323d20226d69}
		 $hex5= {247331333d20225749}
		 $hex6= {2473313d2022617069}
		 $hex7= {2473323d2022617069}
		 $hex8= {2473333d2022617069}
		 $hex9= {2473343d2022617069}
		 $hex10= {2473353d2022617069}
		 $hex11= {2473363d20225f5f63}
		 $hex12= {2473373d20225f5f63}
		 $hex13= {2473383d2022657874}
		 $hex14= {2473393d2022657874}

	condition:
		1 of them
}
