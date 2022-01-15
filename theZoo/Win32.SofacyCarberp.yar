
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_SofacyCarberp 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_SofacyCarberp {
	meta: 
		 description= "Win32_SofacyCarberp Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-39-19" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "36524c90ca1fac2102e7653dfadb31b2"
		 hash2= "aa2cd9d9fc5d196caa6f8fd5979e3f14"

	strings:

	
 		 $s1= "13.11.5200.20789" fullword wide
		 $s2= "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-file-l2-1-1" fullword wide
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
		 $s16= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s17= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s18= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s19= "FileDescription" fullword wide
		 $s20= "Microsoft Corporation" fullword wide
		 $s21= "OriginalFilename" fullword wide
		 $s22= "SeSecurityPrivilege" fullword wide
		 $s23= "VS_VERSION_INFO" fullword wide
		 $a1= "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword ascii
		 $a2= "api-ms-win-core-localization-l1-2-1" fullword ascii
		 $a3= "api-ms-win-core-localization-obsolete-l1-2-0" fullword ascii
		 $a4= "api-ms-win-core-processthreads-l1-1-2" fullword ascii
		 $a5= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword ascii
		 $a6= "api-ms-win-security-systemfunctions-l1-1-0" fullword ascii
		 $a7= "ext-ms-win-kernel32-package-current-l1-1-0" fullword ascii
		 $a8= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword ascii

		 $hex1= {2461313d2022416170}
		 $hex2= {2461323d2022617069}
		 $hex3= {2461333d2022617069}
		 $hex4= {2461343d2022617069}
		 $hex5= {2461353d2022617069}
		 $hex6= {2461363d2022617069}
		 $hex7= {2461373d2022657874}
		 $hex8= {2461383d2022657874}
		 $hex9= {247331303d20226170}
		 $hex10= {247331313d20226170}
		 $hex11= {247331323d20226170}
		 $hex12= {247331333d20226170}
		 $hex13= {247331343d20226170}
		 $hex14= {247331353d20226170}
		 $hex15= {247331363d20226578}
		 $hex16= {247331373d20226578}
		 $hex17= {247331383d20226578}
		 $hex18= {247331393d20224669}
		 $hex19= {2473313d202231332e}
		 $hex20= {247332303d20224d69}
		 $hex21= {247332313d20224f72}
		 $hex22= {247332323d20225365}
		 $hex23= {247332333d20225653}
		 $hex24= {2473323d2022416170}
		 $hex25= {2473333d2022617069}
		 $hex26= {2473343d2022617069}
		 $hex27= {2473353d2022617069}
		 $hex28= {2473363d2022617069}
		 $hex29= {2473373d2022617069}
		 $hex30= {2473383d2022617069}
		 $hex31= {2473393d2022617069}

	condition:
		10 of them
}
