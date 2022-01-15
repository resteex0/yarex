
/*
   YARA Rule Set
   Author: resteex
   Identifier: Remcos 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Remcos {
	meta: 
		 description= "Remcos Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-16" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "02ca3e9c06b2a9b2df05c97a8efa03e7"
		 hash2= "4d0fbb80c91d6c74d2a0510808421bc0"
		 hash3= "af64a7df92d3f72407194dd17b013c86"
		 hash4= "bab85d677cb634a42a890266e000fd79"
		 hash5= "c613f4671dfe8acbc6afacf94e3eb36a"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s2= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s3= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s4= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s5= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s6= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s7= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s8= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s9= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s10= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s11= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s12= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s13= "Bapi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s14= "Bapi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s15= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s16= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s17= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s18= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s19= "../help/buttonThumbDown.bmp" fullword wide
		 $s20= "../help/buttonThumbUp.bmp" fullword wide
		 $s21= "https://github.com/AsayuGit" fullword wide
		 $s22= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide

		 $hex1= {247331303d20226170}
		 $hex2= {247331313d20226170}
		 $hex3= {247331323d20226170}
		 $hex4= {247331333d20224261}
		 $hex5= {247331343d20224261}
		 $hex6= {247331353d20225f5f}
		 $hex7= {247331363d20225f5f}
		 $hex8= {247331373d20226578}
		 $hex9= {247331383d20226578}
		 $hex10= {247331393d20222e2e}
		 $hex11= {2473313d2022617069}
		 $hex12= {247332303d20222e2e}
		 $hex13= {247332313d20226874}
		 $hex14= {247332323d20226d69}
		 $hex15= {2473323d2022617069}
		 $hex16= {2473333d2022617069}
		 $hex17= {2473343d2022617069}
		 $hex18= {2473353d2022617069}
		 $hex19= {2473363d2022617069}
		 $hex20= {2473373d2022617069}
		 $hex21= {2473383d2022617069}
		 $hex22= {2473393d2022617069}

	condition:
		14 of them
}
