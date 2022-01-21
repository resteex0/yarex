
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Chapak 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Chapak {
	meta: 
		 description= "vx_underground2_Chapak Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-53-53" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "00810b59644d1610f9eb57e2d9e175e4"
		 hash2= "6ec836e7cf86162bb62ed8d3483f770b"
		 hash3= "c21f9c393077da2f80a2010f93173060"

	strings:

	
 		 $s1= "%4d-%02d-%02d-%02d-%02d-%02d-%03d" fullword wide
		 $s2= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s3= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s4= "Capi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s5= "Control PanelDesktopResourceLocale" fullword wide
		 $s6= "CryptProtectMemory failed" fullword wide
		 $s7= "CryptUnprotectMemory failed" fullword wide
		 $s8= ".DEFAULTControl PanelInternational" fullword wide
		 $s9= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s10= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s11= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s12= "http://nsis.sf.net/NSIS_Error" fullword wide
		 $s13= "pi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s14= "pi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s15= "pi-ms-win-core-file-l2-1-1" fullword wide
		 $s16= "pi-ms-win-core-localization-l1-2-1" fullword wide
		 $s17= "pi-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s18= "pi-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s19= "pi-ms-win-core-string-l1-1-0" fullword wide
		 $s20= "pi-ms-win-core-synch-l1-2-0" fullword wide
		 $s21= "pi-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s22= "pi-ms-win-core-winrt-l1-1-0" fullword wide
		 $s23= "pi-ms-win-core-xstate-l2-1-0" fullword wide
		 $s24= "SeCreateSymbolicLinkPrivilege" fullword wide
		 $s25= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s26= "__tmp_rar_sfx_access_check_%u" fullword wide

		 $hex1= {247331303d20226578}
		 $hex2= {247331313d20226578}
		 $hex3= {247331323d20226874}
		 $hex4= {247331333d20227069}
		 $hex5= {247331343d20227069}
		 $hex6= {247331353d20227069}
		 $hex7= {247331363d20227069}
		 $hex8= {247331373d20227069}
		 $hex9= {247331383d20227069}
		 $hex10= {247331393d20227069}
		 $hex11= {2473313d2022253464}
		 $hex12= {247332303d20227069}
		 $hex13= {247332313d20227069}
		 $hex14= {247332323d20227069}
		 $hex15= {247332333d20227069}
		 $hex16= {247332343d20225365}
		 $hex17= {247332353d2022536f}
		 $hex18= {247332363d20225f5f}
		 $hex19= {2473323d2022617069}
		 $hex20= {2473333d2022617069}
		 $hex21= {2473343d2022436170}
		 $hex22= {2473353d2022436f6e}
		 $hex23= {2473363d2022437279}
		 $hex24= {2473373d2022437279}
		 $hex25= {2473383d20222e4445}
		 $hex26= {2473393d2022657874}

	condition:
		17 of them
}
