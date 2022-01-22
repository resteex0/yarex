
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Trojans 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Trojans {
	meta: 
		 description= "APT_Sample_Trojans Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-22_17-57-15" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "22de52ac8f1e5c5c9741c606a352dc21"
		 hash2= "38634ac90a7a6cc51024fc9e81facddd"
		 hash3= "548a63e9162fbe13dda1dcda1ffda2b6"
		 hash4= "5d455f154ee0a74c1315d4a84b9b5505"
		 hash5= "9319231e507d66161a60eacc23958923"
		 hash6= "fb2ca93f987313108abdd4a6d687783a"

	strings:

	
 		 $s1= "allOyMANYCUTS allOyMANYCUTS" fullword wide
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
		 $s16= "bibdag.Properties.Resources" fullword wide
		 $s17= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s18= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s19= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s20= "GUICTRLCREATELISTVIEWITEM" fullword wide
		 $s21= "GUICTRLCREATETREEVIEWITEM" fullword wide
		 $s22= "GUICTRLREGISTERLISTVIEWSORT" fullword wide
		 $s23= "SeAssignPrimaryTokenPrivilege" fullword wide
		 $s24= "SoftwareAutoIt v3AutoIt" fullword wide
		 $s25= "SoftwareMicrosoftInternet ExplorerIntelliFormsStorage2" fullword wide
		 $s26= "SYSTEMCurrentControlSetControlNlsLanguage" fullword wide
		 $a1= "http://crl.starfieldtech.com/repository/sf_issuing_ca-g2.crt0T" fullword ascii

		 $hex1= {2461313d2022687474}
		 $hex2= {247331303d20226170}
		 $hex3= {247331313d20226170}
		 $hex4= {247331323d20226170}
		 $hex5= {247331333d20226170}
		 $hex6= {247331343d20226170}
		 $hex7= {247331353d20226170}
		 $hex8= {247331363d20226269}
		 $hex9= {247331373d20226578}
		 $hex10= {247331383d20226578}
		 $hex11= {247331393d20226578}
		 $hex12= {2473313d2022616c6c}
		 $hex13= {247332303d20224755}
		 $hex14= {247332313d20224755}
		 $hex15= {247332323d20224755}
		 $hex16= {247332333d20225365}
		 $hex17= {247332343d2022536f}
		 $hex18= {247332353d2022536f}
		 $hex19= {247332363d20225359}
		 $hex20= {2473323d2022617069}
		 $hex21= {2473333d2022617069}
		 $hex22= {2473343d2022617069}
		 $hex23= {2473353d2022617069}
		 $hex24= {2473363d2022617069}
		 $hex25= {2473373d2022617069}
		 $hex26= {2473383d2022617069}
		 $hex27= {2473393d2022617069}

	condition:
		18 of them
}
