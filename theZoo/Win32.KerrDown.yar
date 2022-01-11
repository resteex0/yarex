
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_KerrDown 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_KerrDown {
	meta: 
		 description= "Win32_KerrDown Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-32-44" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "518f52aabd9a059d181bfe864097091e"
		 hash2= "6aa3115fa1f3adb8f0539e93d2cf21ca"
		 hash3= "70a64ae401c0a5f091b5382dea2432df"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
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
		 $s15= "dddd, MMMM dd, yyyy" fullword wide
		 $s16= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s17= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s18= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $a1= "8@8D8H8L8P8T8X88`8d8h8l8p8t8x8|8" fullword ascii
		 $a2= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a3= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a4= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii
		 $a5= ".?AVbad_array_new_length@std@@" fullword ascii
		 $a6= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a7= "InitializeCriticalSectionEx" fullword ascii
		 $a8= "IsProcessorFeaturePresent" fullword ascii
		 $a9= "SetUnhandledExceptionFilter" fullword ascii
		 $a10= "word/_rels/document.xml.relsPK" fullword ascii

		 $hex1= {246131303d2022776f}
		 $hex2= {2461313d2022384038}
		 $hex3= {2461323d2022616263}
		 $hex4= {2461333d2022414243}
		 $hex5= {2461343d2022414243}
		 $hex6= {2461353d20222e3f41}
		 $hex7= {2461363d2022496e69}
		 $hex8= {2461373d2022496e69}
		 $hex9= {2461383d2022497350}
		 $hex10= {2461393d2022536574}
		 $hex11= {247331303d20226170}
		 $hex12= {247331313d20226170}
		 $hex13= {247331323d20226170}
		 $hex14= {247331333d20226170}
		 $hex15= {247331343d20226170}
		 $hex16= {247331353d20226464}
		 $hex17= {247331363d20226578}
		 $hex18= {247331373d20226578}
		 $hex19= {247331383d20226578}
		 $hex20= {2473313d2022617069}
		 $hex21= {2473323d2022617069}
		 $hex22= {2473333d2022617069}
		 $hex23= {2473343d2022617069}
		 $hex24= {2473353d2022617069}
		 $hex25= {2473363d2022617069}
		 $hex26= {2473373d2022617069}
		 $hex27= {2473383d2022617069}
		 $hex28= {2473393d2022617069}

	condition:
		3 of them
}
