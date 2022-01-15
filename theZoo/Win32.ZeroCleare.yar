
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
		 date = "2022-01-14_21-39-29" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1a69a02b0cd10b1764521fec4b7376c9"
		 hash2= "33f98b613b331b49e272512274669844"
		 hash3= "8afa8a59eebf43ef223be52e08fcdc67"
		 hash4= "c04236b5678af08c8b70a7aa696f87d5"
		 hash5= "f5f8160fe8468a77b6a495155c3dacea"

	strings:

	
 		 $s1= "american english" fullword wide
		 $s2= "american-english" fullword wide
		 $s3= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s4= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s6= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s7= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s8= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s9= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s10= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s11= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s12= "@api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s13= "api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s14= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s15= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s16= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s17= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s18= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s19= "Capi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s20= "Capi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s21= "chinese-hongkong" fullword wide
		 $s22= "chinese-simplified" fullword wide
		 $s23= "chinese-singapore" fullword wide
		 $s24= "chinese-traditional" fullword wide
		 $s25= "C:windowssystem32cmd.exe" fullword wide
		 $s26= "english-american" fullword wide
		 $s27= "english-caribbean" fullword wide
		 $s28= "english-jamaica" fullword wide
		 $s29= "english-south africa" fullword wide
		 $s30= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s31= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s32= "french-canadian" fullword wide
		 $s33= "french-luxembourg" fullword wide
		 $s34= "german-austrian" fullword wide
		 $s35= "german-lichtenstein" fullword wide
		 $s36= "german-luxembourg" fullword wide
		 $s37= "norwegian-bokmal" fullword wide
		 $s38= "norwegian-nynorsk" fullword wide
		 $s39= "portuguese-brazilian" fullword wide
		 $s40= "SoftwareOracleVirtualBox" fullword wide
		 $s41= "spanish-argentina" fullword wide
		 $s42= "spanish-bolivia" fullword wide
		 $s43= "spanish-colombia" fullword wide
		 $s44= "spanish-costa rica" fullword wide
		 $s45= "spanish-dominican republic" fullword wide
		 $s46= "spanish-ecuador" fullword wide
		 $s47= "spanish-el salvador" fullword wide
		 $s48= "spanish-guatemala" fullword wide
		 $s49= "spanish-honduras" fullword wide
		 $s50= "spanish-mexican" fullword wide
		 $s51= "spanish-nicaragua" fullword wide
		 $s52= "spanish-paraguay" fullword wide
		 $s53= "spanish-puerto rico" fullword wide
		 $s54= "spanish-uruguay" fullword wide
		 $s55= "spanish-venezuela" fullword wide
		 $s56= "swedish-finland" fullword wide
		 $s57= "SystemCurrentControlSetControlNetworkProviderOrder" fullword wide
		 $a1= "api-ms-win-core-localization-l1-2-1" fullword ascii
		 $a2= "api-ms-win-core-localization-obsolete-l1-2-0" fullword ascii
		 $a3= "api-ms-win-core-processthreads-l1-1-2" fullword ascii
		 $a4= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword ascii
		 $a5= "api-ms-win-security-systemfunctions-l1-1-0" fullword ascii
		 $a6= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword ascii
		 $a7= "SystemCurrentControlSetControlNetworkProviderOrder" fullword ascii

		 $hex1= {2461313d2022617069}
		 $hex2= {2461323d2022617069}
		 $hex3= {2461333d2022617069}
		 $hex4= {2461343d2022617069}
		 $hex5= {2461353d2022617069}
		 $hex6= {2461363d2022657874}
		 $hex7= {2461373d2022537973}
		 $hex8= {247331303d20226170}
		 $hex9= {247331313d20226170}
		 $hex10= {247331323d20224061}
		 $hex11= {247331333d20226170}
		 $hex12= {247331343d20226170}
		 $hex13= {247331353d20226170}
		 $hex14= {247331363d20226170}
		 $hex15= {247331373d20226170}
		 $hex16= {247331383d20226170}
		 $hex17= {247331393d20224361}
		 $hex18= {2473313d2022616d65}
		 $hex19= {247332303d20224361}
		 $hex20= {247332313d20226368}
		 $hex21= {247332323d20226368}
		 $hex22= {247332333d20226368}
		 $hex23= {247332343d20226368}
		 $hex24= {247332353d2022433a}
		 $hex25= {247332363d2022656e}
		 $hex26= {247332373d2022656e}
		 $hex27= {247332383d2022656e}
		 $hex28= {247332393d2022656e}
		 $hex29= {2473323d2022616d65}
		 $hex30= {247333303d20226578}
		 $hex31= {247333313d20226578}
		 $hex32= {247333323d20226672}
		 $hex33= {247333333d20226672}
		 $hex34= {247333343d20226765}
		 $hex35= {247333353d20226765}
		 $hex36= {247333363d20226765}
		 $hex37= {247333373d20226e6f}
		 $hex38= {247333383d20226e6f}
		 $hex39= {247333393d2022706f}
		 $hex40= {2473333d2022617069}
		 $hex41= {247334303d2022536f}
		 $hex42= {247334313d20227370}
		 $hex43= {247334323d20227370}
		 $hex44= {247334333d20227370}
		 $hex45= {247334343d20227370}
		 $hex46= {247334353d20227370}
		 $hex47= {247334363d20227370}
		 $hex48= {247334373d20227370}
		 $hex49= {247334383d20227370}
		 $hex50= {247334393d20227370}
		 $hex51= {2473343d2022617069}
		 $hex52= {247335303d20227370}
		 $hex53= {247335313d20227370}
		 $hex54= {247335323d20227370}
		 $hex55= {247335333d20227370}
		 $hex56= {247335343d20227370}
		 $hex57= {247335353d20227370}
		 $hex58= {247335363d20227377}
		 $hex59= {247335373d20225379}
		 $hex60= {2473353d2022617069}
		 $hex61= {2473363d2022617069}
		 $hex62= {2473373d2022617069}
		 $hex63= {2473383d2022617069}
		 $hex64= {2473393d2022617069}

	condition:
		21 of them
}
