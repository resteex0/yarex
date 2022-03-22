
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_APT37 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_APT37 {
	meta: 
		 description= "APT_Sample_APT37 Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-22_12-18-04" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0dd50c4a5aa9899504cb4cf95acd981e"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s5= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s6= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s7= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s8= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s9= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s10= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s11= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s12= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s13= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s14= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s15= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s16= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s17= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s18= "spanish-dominican republic" fullword wide

		 $hex1= {6170692d6d732d7769}
		 $hex2= {6578742d6d732d7769}
		 $hex3= {7370616e6973682d64}

	condition:
		2 of them
}
