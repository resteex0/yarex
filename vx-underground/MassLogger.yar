
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_MassLogger 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_MassLogger {
	meta: 
		 description= "vx_underground2_MassLogger Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-11-28" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "15d1d1f6b45ecb4da929978f8be4ca0f"

	strings:

	
 		 $s1= "%4d-%02d-%02d-%02d-%02d-%02d-%03d" fullword wide
		 $s2= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s3= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s4= "Capi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s5= "CryptProtectMemory failed" fullword wide
		 $s6= "CryptUnprotectMemory failed" fullword wide
		 $s7= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s8= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s9= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s10= "pi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s11= "pi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s12= "pi-ms-win-core-file-l2-1-1" fullword wide
		 $s13= "pi-ms-win-core-localization-l1-2-1" fullword wide
		 $s14= "pi-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s15= "pi-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s16= "pi-ms-win-core-string-l1-1-0" fullword wide
		 $s17= "pi-ms-win-core-synch-l1-2-0" fullword wide
		 $s18= "pi-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s19= "pi-ms-win-core-winrt-l1-1-0" fullword wide
		 $s20= "pi-ms-win-core-xstate-l2-1-0" fullword wide
		 $s21= "SeCreateSymbolicLinkPrivilege" fullword wide
		 $s22= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s23= "__tmp_rar_sfx_access_check_%u" fullword wide

		 $hex1= {247331303d20227069}
		 $hex2= {247331313d20227069}
		 $hex3= {247331323d20227069}
		 $hex4= {247331333d20227069}
		 $hex5= {247331343d20227069}
		 $hex6= {247331353d20227069}
		 $hex7= {247331363d20227069}
		 $hex8= {247331373d20227069}
		 $hex9= {247331383d20227069}
		 $hex10= {247331393d20227069}
		 $hex11= {2473313d2022253464}
		 $hex12= {247332303d20227069}
		 $hex13= {247332313d20225365}
		 $hex14= {247332323d2022536f}
		 $hex15= {247332333d20225f5f}
		 $hex16= {2473323d2022617069}
		 $hex17= {2473333d2022617069}
		 $hex18= {2473343d2022436170}
		 $hex19= {2473353d2022437279}
		 $hex20= {2473363d2022437279}
		 $hex21= {2473373d2022657874}
		 $hex22= {2473383d2022657874}
		 $hex23= {2473393d2022657874}

	condition:
		15 of them
}
