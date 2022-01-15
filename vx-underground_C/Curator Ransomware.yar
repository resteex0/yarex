
/*
   YARA Rule Set
   Author: resteex
   Identifier: Curator_Ransomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Curator_Ransomware {
	meta: 
		 description= "Curator_Ransomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_23-12-38" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "4d2c614ba98df43601b6d9551bd26684"

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
		 $s10= "api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s11= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s12= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s13= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s14= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s15= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s16= "Content-Type: application/octet-stream" fullword wide
		 $s17= "C:Program Files(x86)Intuit" fullword wide
		 $s18= "C:Program Files(x86)MYOB" fullword wide
		 $s19= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s20= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s21= "ithelpnetwork@decorous.cyou" fullword wide
		 $s22= "ithelpnetwork@wholeness.business" fullword wide
		 $s23= "ReportingServecesService.exe" fullword wide
		 $s24= "%s|DELIMITER|Name(domain): %s(%s)" fullword wide

		 $hex1= {247331303d20226170}
		 $hex2= {247331313d20226170}
		 $hex3= {247331323d20226170}
		 $hex4= {247331333d20226170}
		 $hex5= {247331343d20226170}
		 $hex6= {247331353d20226170}
		 $hex7= {247331363d2022436f}
		 $hex8= {247331373d2022433a}
		 $hex9= {247331383d2022433a}
		 $hex10= {247331393d20226578}
		 $hex11= {2473313d2022617069}
		 $hex12= {247332303d20226578}
		 $hex13= {247332313d20226974}
		 $hex14= {247332323d20226974}
		 $hex15= {247332333d20225265}
		 $hex16= {247332343d20222573}
		 $hex17= {2473323d2022617069}
		 $hex18= {2473333d2022617069}
		 $hex19= {2473343d2022617069}
		 $hex20= {2473353d2022617069}
		 $hex21= {2473363d2022617069}
		 $hex22= {2473373d2022617069}
		 $hex23= {2473383d2022617069}
		 $hex24= {2473393d2022617069}

	condition:
		16 of them
}
