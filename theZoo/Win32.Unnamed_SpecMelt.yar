
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Win32_Unnamed_SpecMelt 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Win32_Unnamed_SpecMelt {
	meta: 
		 description= "theZoo_Win32_Unnamed_SpecMelt Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-37-02" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8f188da25ac5dcdaf4bba56d84d83c56"

	strings:

	
 		 $s1= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s4= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s5= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s6= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s7= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s8= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s9= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s10= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s11= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s12= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s13= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s14= "Bapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s15= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s16= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s17= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide

		 $hex1= {247331303d20226170}
		 $hex2= {247331313d20226170}
		 $hex3= {247331323d20226170}
		 $hex4= {247331333d20226170}
		 $hex5= {247331343d20224261}
		 $hex6= {247331353d20226578}
		 $hex7= {247331363d20226578}
		 $hex8= {247331373d20226578}
		 $hex9= {2473313d2022617069}
		 $hex10= {2473323d2022617069}
		 $hex11= {2473333d2022617069}
		 $hex12= {2473343d2022617069}
		 $hex13= {2473353d2022617069}
		 $hex14= {2473363d2022617069}
		 $hex15= {2473373d2022617069}
		 $hex16= {2473383d2022617069}
		 $hex17= {2473393d2022617069}

	condition:
		11 of them
}
