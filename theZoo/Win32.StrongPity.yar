
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_StrongPity 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_StrongPity {
	meta: 
		 description= "Win32_StrongPity Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-39-19" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "a4d3b78941da8b6f4edad7cb6f35134b"
		 hash2= "cab76ac00e342f77bdfec3e85b6b85a9"

	strings:

	
 		 $s1= "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-file-l2-1-1" fullword wide
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
		 $s15= "Connection: close" fullword wide
		 $s16= "Content-Length: %lu" fullword wide
		 $s17= "Content-Type: application/x-www-form-urlencoded" fullword wide
		 $s18= "Digest Security" fullword wide
		 $s19= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s20= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s21= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s22= "FileDescription" fullword wide
		 $s23= "OriginalFilename" fullword wide
		 $s24= "VS_VERSION_INFO" fullword wide
		 $a1= "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword ascii
		 $a2= "api-ms-win-core-localization-l1-2-1" fullword ascii
		 $a3= "api-ms-win-core-localization-obsolete-l1-2-0" fullword ascii
		 $a4= "api-ms-win-core-processthreads-l1-1-2" fullword ascii
		 $a5= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword ascii
		 $a6= "api-ms-win-security-systemfunctions-l1-1-0" fullword ascii
		 $a7= "Content-Type: application/x-www-form-urlencoded" fullword ascii
		 $a8= "ext-ms-win-kernel32-package-current-l1-1-0" fullword ascii
		 $a9= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword ascii

		 $hex1= {2461313d2022416170}
		 $hex2= {2461323d2022617069}
		 $hex3= {2461333d2022617069}
		 $hex4= {2461343d2022617069}
		 $hex5= {2461353d2022617069}
		 $hex6= {2461363d2022617069}
		 $hex7= {2461373d2022436f6e}
		 $hex8= {2461383d2022657874}
		 $hex9= {2461393d2022657874}
		 $hex10= {247331303d20226170}
		 $hex11= {247331313d20226170}
		 $hex12= {247331323d20226170}
		 $hex13= {247331333d20226170}
		 $hex14= {247331343d20226170}
		 $hex15= {247331353d2022436f}
		 $hex16= {247331363d2022436f}
		 $hex17= {247331373d2022436f}
		 $hex18= {247331383d20224469}
		 $hex19= {247331393d20226578}
		 $hex20= {2473313d2022416170}
		 $hex21= {247332303d20226578}
		 $hex22= {247332313d20226578}
		 $hex23= {247332323d20224669}
		 $hex24= {247332333d20224f72}
		 $hex25= {247332343d20225653}
		 $hex26= {2473323d2022617069}
		 $hex27= {2473333d2022617069}
		 $hex28= {2473343d2022617069}
		 $hex29= {2473353d2022617069}
		 $hex30= {2473363d2022617069}
		 $hex31= {2473373d2022617069}
		 $hex32= {2473383d2022617069}
		 $hex33= {2473393d2022617069}

	condition:
		11 of them
}
