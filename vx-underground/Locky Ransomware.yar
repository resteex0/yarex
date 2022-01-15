
/*
   YARA Rule Set
   Author: resteex
   Identifier: Locky_Ransomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Locky_Ransomware {
	meta: 
		 description= "Locky_Ransomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-13-11" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0708745aa6cb07941ce21ccd08f2f052"
		 hash2= "0993d209ab4bc09588679a76af1c4748"
		 hash3= "137b69fdbc4c3a1baa26dcb97c01c37e"
		 hash4= "1c529aa744aa47378d70dcc1e9b523c6"
		 hash5= "205130e0483ffccc7e006dcf5b6bb7f9"
		 hash6= "215ffdd86ba7d27f3e379f92af7970d6"
		 hash7= "4b033f726c6e74456225eda95371c9e4"
		 hash8= "72870e8434cdc713803b4f4351086af4"
		 hash9= "a05bd24c8d244f8692f93658f2f7892a"
		 hash10= "a534f1a1ee7fc4d866c2fd7ae24819f9"
		 hash11= "a845bf3351bbb146207d47aee552a1a2"
		 hash12= "b38ebac9c480f75e61a1ec6a6c781231"
		 hash13= "cb87af578aef90b79dcdb05276519997"
		 hash14= "f0ec4e0dc8da5969dd19729b63d575c2"
		 hash15= "f2311e344f690f016572f4c1df241335"

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
