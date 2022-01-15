
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_ZeroCleare 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_ZeroCleare {
	meta: 
		 description= "Win32_ZeroCleare Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-52-48" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1a69a02b0cd10b1764521fec4b7376c9"
		 hash2= "33f98b613b331b49e272512274669844"
		 hash3= "8afa8a59eebf43ef223be52e08fcdc67"
		 hash4= "c04236b5678af08c8b70a7aa696f87d5"
		 hash5= "f5f8160fe8468a77b6a495155c3dacea"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s2= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s5= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s6= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s7= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s8= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s9= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s10= "@api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s11= "api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s12= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s13= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s14= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s15= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s16= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s17= "Capi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s18= "Capi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s19= "C:windowssystem32cmd.exe" fullword wide
		 $s20= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s21= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s22= "SoftwareOracleVirtualBox" fullword wide
		 $s23= "spanish-dominican republic" fullword wide
		 $s24= "SystemCurrentControlSetControlNetworkProviderOrder" fullword wide
		 $a1= "SystemCurrentControlSetControlNetworkProviderOrder" fullword ascii

		 $hex1= {2461313d2022537973}
		 $hex2= {247331303d20224061}
		 $hex3= {247331313d20226170}
		 $hex4= {247331323d20226170}
		 $hex5= {247331333d20226170}
		 $hex6= {247331343d20226170}
		 $hex7= {247331353d20226170}
		 $hex8= {247331363d20226170}
		 $hex9= {247331373d20224361}
		 $hex10= {247331383d20224361}
		 $hex11= {247331393d2022433a}
		 $hex12= {2473313d2022617069}
		 $hex13= {247332303d20226578}
		 $hex14= {247332313d20226578}
		 $hex15= {247332323d2022536f}
		 $hex16= {247332333d20227370}
		 $hex17= {247332343d20225379}
		 $hex18= {2473323d2022617069}
		 $hex19= {2473333d2022617069}
		 $hex20= {2473343d2022617069}
		 $hex21= {2473353d2022617069}
		 $hex22= {2473363d2022617069}
		 $hex23= {2473373d2022617069}
		 $hex24= {2473383d2022617069}
		 $hex25= {2473393d2022617069}

	condition:
		16 of them
}
