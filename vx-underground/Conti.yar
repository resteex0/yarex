
/*
   YARA Rule Set
   Author: resteex
   Identifier: Conti 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Conti {
	meta: 
		 description= "Conti Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-01-49" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2a380d0c2aa2234c0a37bdaaaa9489ef"
		 hash2= "2cc630e080bb8de5faf9f5ae87f43f8b"
		 hash3= "31db87c5d3b970b42cb577611f851c7a"
		 hash4= "45295780f2ba837be42ccf50710bd2b5"
		 hash5= "5c6273b024c93c5bdf557813868f9337"
		 hash6= "617ccca7d5753993cbfd1309d1a18e1c"
		 hash7= "6c0bb20e1158593211a7cbcbacb3dd83"
		 hash8= "7364f6222ac58896e8920f32e4d30aac"
		 hash9= "89895cf4c88f13e5797aab63dddf1078"
		 hash10= "a5e03a5150537126dffcf2391dfab934"
		 hash11= "b1ad9afd96168db991f79eb546d6b79a"
		 hash12= "c0f972c5e033c0b4dc268a805cfa16a2"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s3= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s6= "api-ms-win-core-file-l2-1-1" fullword wide
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
		 $s17= "Bapi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s18= "Bapi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s19= "C:UsersPublicCUIsJTCvolan.exe" fullword wide
		 $s20= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s21= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s22= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide

		 $hex1= {247331303d20226170}
		 $hex2= {247331313d20226170}
		 $hex3= {247331323d20226170}
		 $hex4= {247331333d20226170}
		 $hex5= {247331343d20226170}
		 $hex6= {247331353d20226170}
		 $hex7= {247331363d20226170}
		 $hex8= {247331373d20224261}
		 $hex9= {247331383d20224261}
		 $hex10= {247331393d2022433a}
		 $hex11= {2473313d2022617069}
		 $hex12= {247332303d20226578}
		 $hex13= {247332313d20226578}
		 $hex14= {247332323d20226578}
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
