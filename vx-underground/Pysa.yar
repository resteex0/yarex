
/*
   YARA Rule Set
   Author: resteex
   Identifier: Pysa 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Pysa {
	meta: 
		 description= "Pysa Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-17-03" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0b356149cdff77826f11cbcaac9aa98d"
		 hash2= "339165f63aec8d7fd7798129d0fc68ad"
		 hash3= "367734ce59f38110fb0333a4d28a89dd"
		 hash4= "4252a2aba65926b3c5888549cebae854"
		 hash5= "429126aa566b3fd191227b4f2d1890fc"
		 hash6= "4ff21b1cec174bbb5bf0b22e42a56af0"
		 hash7= "50988e480f4106b5705f7559df6a7f79"
		 hash8= "83e1ca89bcd55a87f826bc6901ff7f3e"
		 hash9= "9976373177d217207a692a6d0867e9c4"
		 hash10= "9ff0f8785b73ce6e86b0a269e44c6d1b"
		 hash11= "b6dd099b4c51edae5ea0c867ff2f12a7"
		 hash12= "d3ba2b1e2449ad6525eedbbed7a9e2ce"
		 hash13= "d7b3ed13ed2c94f090df4d138358cb50"
		 hash14= "dc82cd73d0738cfe2e49c499c2fa631e"
		 hash15= "e3da64fd9a0a585ebe00ac7f235104d6"
		 hash16= "e9454a2ff16897e177d8a11083850ec7"
		 hash17= "eec3730b2b99f6fb23134d79681f5122"
		 hash18= "f561cb46e0fc5563800285eb6bceef8f"

	strings:

	
 		 $s1= "!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13" fullword wide
		 $s2= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
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
		 $s19= "Fapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s20= "spanish-dominican republic" fullword wide
		 $a1= "!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13" fullword ascii

		 $hex1= {2461313d2022212325}
		 $hex2= {247331303d20226170}
		 $hex3= {247331313d20226170}
		 $hex4= {247331323d20226170}
		 $hex5= {247331333d20226170}
		 $hex6= {247331343d20226170}
		 $hex7= {247331353d20226170}
		 $hex8= {247331363d20226578}
		 $hex9= {247331373d20226578}
		 $hex10= {247331383d20226578}
		 $hex11= {247331393d20224661}
		 $hex12= {2473313d2022212325}
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
