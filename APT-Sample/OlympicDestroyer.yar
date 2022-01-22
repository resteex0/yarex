
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_OlympicDestroyer 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_OlympicDestroyer {
	meta: 
		 description= "APT_Sample_OlympicDestroyer Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-22_17-57-06" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ca0eaca077aa67f2609f612cefe7f1f3"
		 hash2= "cfdd16225e67471f5ef54cab9b3a5558"
		 hash3= "d9c37b937ffde812ae15de885913e101"
		 hash4= "ec724ef33521c4c2965de078e36c8277"

	strings:

	
 		 $s1= "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" fullword wide
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
		 $s16= "Bapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s17= "del %programdata%evtchk.txt" fullword wide
		 $s18= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s19= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s20= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $a1= "MicrosoftOffice16_Data:SSPI:elena.samokhvalova@atos.net(null)" fullword ascii
		 $a2= "MicrosoftOffice16_Data:SSPI:svetlana.vorobieva@atos.net(null)" fullword ascii

		 $hex1= {2461313d20224d6963}
		 $hex2= {2461323d20224d6963}
		 $hex3= {247331303d20226170}
		 $hex4= {247331313d20226170}
		 $hex5= {247331323d20226170}
		 $hex6= {247331333d20226170}
		 $hex7= {247331343d20226170}
		 $hex8= {247331353d20226170}
		 $hex9= {247331363d20224261}
		 $hex10= {247331373d20226465}
		 $hex11= {247331383d20226578}
		 $hex12= {247331393d20226578}
		 $hex13= {2473313d2022253038}
		 $hex14= {247332303d20226578}
		 $hex15= {2473323d2022617069}
		 $hex16= {2473333d2022617069}
		 $hex17= {2473343d2022617069}
		 $hex18= {2473353d2022617069}
		 $hex19= {2473363d2022617069}
		 $hex20= {2473373d2022617069}
		 $hex21= {2473383d2022617069}
		 $hex22= {2473393d2022617069}

	condition:
		14 of them
}
