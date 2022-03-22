
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
		 date = "2022-03-22_12-18-34" 
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

		 $hex1= {46536f667477617265}
		 $hex2= {4755494354524c4352}
		 $hex3= {4755494354524c5245}
		 $hex4= {53595354454d437572}
		 $hex5= {536541737369676e50}
		 $hex6= {6170692d6d732d7769}
		 $hex7= {6578742d6d732d7769}

	condition:
		3 of them
}
