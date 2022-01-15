
/*
   YARA Rule Set
   Author: resteex
   Identifier: Cobalt_Strike 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Cobalt_Strike {
	meta: 
		 description= "Cobalt_Strike Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-01-26" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2bd9c0ae977d28d89bc7e590e0996274"
		 hash2= "3a11f98d3d4fb8df67c97dc1bd06ff2e"
		 hash3= "9d35e17421e9a1c8458f32cd813bd27f"
		 hash4= "bb4fe58a0d6cbb1237d46f2952d762cc"
		 hash5= "d120e20c7e868c1ce1b94ed63318be6d"
		 hash6= "d3bcd0f68b4d845c0170de30f779946b"

	strings:

	
 		 $s1= "{084F01FA-E634-4D77-83EE-074817C03581}" fullword wide
		 $s2= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s3= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-file-l1-2-2" fullword wide
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
		 $s16= "DocumentSummaryInformation" fullword wide
		 $s17= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s18= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s19= "/login/member/center/logins" fullword wide
		 $s20= "TableStyleMedium2PivotStyleLight16" fullword wide

		 $hex1= {247331303d20226170}
		 $hex2= {247331313d20226170}
		 $hex3= {247331323d20226170}
		 $hex4= {247331333d20226170}
		 $hex5= {247331343d20226170}
		 $hex6= {247331353d20226170}
		 $hex7= {247331363d2022446f}
		 $hex8= {247331373d20226578}
		 $hex9= {247331383d20226578}
		 $hex10= {247331393d20222f6c}
		 $hex11= {2473313d20227b3038}
		 $hex12= {247332303d20225461}
		 $hex13= {2473323d2022617069}
		 $hex14= {2473333d2022617069}
		 $hex15= {2473343d2022617069}
		 $hex16= {2473353d2022617069}
		 $hex17= {2473363d2022617069}
		 $hex18= {2473373d2022617069}
		 $hex19= {2473383d2022617069}
		 $hex20= {2473393d2022617069}

	condition:
		13 of them
}
