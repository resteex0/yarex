
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
		 date = "2022-03-22_14-19-47" 
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

		 $hex1= {4755494354524c4352}
		 $hex2= {4755494354524c5245}
		 $hex3= {53595354454d437572}
		 $hex4= {536541737369676e50}
		 $hex5= {536f66747761726541}
		 $hex6= {536f6674776172654d}
		 $hex7= {616c6c4f794d414e59}
		 $hex8= {6170692d6d732d7769}
		 $hex9= {6269626461672e5072}
		 $hex10= {6578742d6d732d7769}
		 $hex11= {687474703a2f2f6372}

	condition:
		12 of them
}
