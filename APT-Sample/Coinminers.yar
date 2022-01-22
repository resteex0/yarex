
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Coinminers 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Coinminers {
	meta: 
		 description= "APT_Sample_Coinminers Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-22_17-55-17" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1ef7d145bf7153292ea33fe7c900ece9"
		 hash2= "71404815f6a0171a29de46846e78a079"
		 hash3= "8a9b94910275355998db5994fd3e579a"
		 hash4= "a50ea10ce3e08bf5095c12503ccc5d95"
		 hash5= "fbfe67defe5443cbdc89dee20fbad068"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s3= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s6= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s7= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s8= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s9= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s10= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s11= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s12= "api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s13= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s14= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s15= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s16= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s17= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s18= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s19= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s20= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s21= "FSoftwareAutoIt v3AutoIt" fullword wide
		 $s22= "GUICTRLCREATELISTVIEWITEM" fullword wide
		 $s23= "GUICTRLCREATETREEVIEWITEM" fullword wide
		 $s24= "GUICTRLREGISTERLISTVIEWSORT" fullword wide
		 $s25= "SeAssignPrimaryTokenPrivilege" fullword wide
		 $s26= "SYSTEMCurrentControlSetControlNlsLanguage" fullword wide

		 $hex1= {247331303d20226170}
		 $hex2= {247331313d20226170}
		 $hex3= {247331323d20226170}
		 $hex4= {247331333d20226170}
		 $hex5= {247331343d20226170}
		 $hex6= {247331353d20226170}
		 $hex7= {247331363d20226170}
		 $hex8= {247331373d20226170}
		 $hex9= {247331383d20226578}
		 $hex10= {247331393d20226578}
		 $hex11= {2473313d2022617069}
		 $hex12= {247332303d20226578}
		 $hex13= {247332313d20224653}
		 $hex14= {247332323d20224755}
		 $hex15= {247332333d20224755}
		 $hex16= {247332343d20224755}
		 $hex17= {247332353d20225365}
		 $hex18= {247332363d20225359}
		 $hex19= {2473323d2022617069}
		 $hex20= {2473333d2022617069}
		 $hex21= {2473343d2022617069}
		 $hex22= {2473353d2022617069}
		 $hex23= {2473363d2022617069}
		 $hex24= {2473373d2022617069}
		 $hex25= {2473383d2022617069}
		 $hex26= {2473393d2022617069}

	condition:
		17 of them
}
