
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
		 date = "2022-01-14_19-55-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2ec79d0605a4756f4732aba16ef41b22"
		 hash2= "660d1132888b2a2ff83b695e65452f87"
		 hash3= "83763fe02f41c1b3ce099f277391732a"
		 hash4= "c6206b8eacabc1dc3578cec2b91c949a"
		 hash5= "e57f8364372e3ba866389c2895b42628"

	strings:

	
 		 $s1= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s2= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s3= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s4= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s5= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s6= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s7= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s8= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s9= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide

		 $hex1= {2473313d2022617069}
		 $hex2= {2473323d2022617069}
		 $hex3= {2473333d2022617069}
		 $hex4= {2473343d2022617069}
		 $hex5= {2473353d2022617069}
		 $hex6= {2473363d20225f5f63}
		 $hex7= {2473373d20225f5f63}
		 $hex8= {2473383d2022657874}
		 $hex9= {2473393d20226d696e}

	condition:
		1 of them
}
