
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_YanluowangRansomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_YanluowangRansomware {
	meta: 
		 description= "vx_underground2_YanluowangRansomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-18-05" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "afaf2d4ebb6dc47e79a955df5ad1fc8a"
		 hash2= "ba95a2f1f1f39a24687ebe3a7a7f7295"

	strings:

	
 		 $s1= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s4= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s5= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s6= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s7= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s8= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s9= "api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s10= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s11= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s12= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s13= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s14= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s15= "Dapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s16= "Dapi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s17= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s18= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s19= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s20= "spanish-dominican republic" fullword wide
		 $a1= ".?AV?$VariableKeyLength@$0BA@$00$0CA@$00$0A@$0BA@@CryptoPP@@" fullword ascii

		 $hex1= {2461313d20222e3f41}
		 $hex2= {247331303d20226170}
		 $hex3= {247331313d20226170}
		 $hex4= {247331323d20226170}
		 $hex5= {247331333d20226170}
		 $hex6= {247331343d20226170}
		 $hex7= {247331353d20224461}
		 $hex8= {247331363d20224461}
		 $hex9= {247331373d20226578}
		 $hex10= {247331383d20226578}
		 $hex11= {247331393d20226578}
		 $hex12= {2473313d2022617069}
		 $hex13= {247332303d20227370}
		 $hex14= {2473323d2022617069}
		 $hex15= {2473333d2022617069}
		 $hex16= {2473343d2022617069}
		 $hex17= {2473353d2022617069}
		 $hex18= {2473363d2022617069}
		 $hex19= {2473373d2022617069}
		 $hex20= {2473383d2022617069}
		 $hex21= {2473393d2022617069}

	condition:
		14 of them
}
