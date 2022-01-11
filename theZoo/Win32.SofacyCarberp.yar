
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_SofacyCarberp 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_SofacyCarberp {
	meta: 
		 description= "Win32_SofacyCarberp Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-33-52" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "36524c90ca1fac2102e7653dfadb31b2"
		 hash2= "aa2cd9d9fc5d196caa6f8fd5979e3f14"

	strings:

	
 		 $s1= "13.11.5200.20789" fullword wide
		 $s2= "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
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
		 $s16= "Content Delivery Verifier" fullword wide
		 $s17= "dddd, MMMM dd, yyyy" fullword wide
		 $s18= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s19= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s20= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s21= "FileDescription" fullword wide
		 $s22= "Microsoft Corporation" fullword wide
		 $s23= "Microsoft Corporation. All rights reserved." fullword wide
		 $s24= "OriginalFilename" fullword wide
		 $s25= "SeSecurityPrivilege" fullword wide
		 $s26= "VS_VERSION_INFO" fullword wide
		 $a1= "090=0A0E0I0M0Q0U0Y0]0a0e0" fullword ascii
		 $a2= "2@2D2H2L2P2T2X22`2d2h2l2p2t2x2|2" fullword ascii
		 $a3= "2H3L3P3T3X33`3d3h3l3p3t3x3|3" fullword ascii
		 $a4= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a5= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a6= ".?AVbad_array_new_length@std@@" fullword ascii
		 $a7= "CreateProcessAsULookupPrivilegeVOpenProcessToken" fullword ascii
		 $a8= "DisableThreadLibraryCalls" fullword ascii
		 $a9= "GdipCreateBitmapFromHBITMAP" fullword ascii
		 $a10= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a11= "InitializeCriticalSectionEx" fullword ascii
		 $a12= "IsProcessorFeaturePresent" fullword ascii
		 $a13= "SetUnhandledExceptionFilter" fullword ascii

		 $hex1= {246131303d2022496e}
		 $hex2= {246131313d2022496e}
		 $hex3= {246131323d20224973}
		 $hex4= {246131333d20225365}
		 $hex5= {2461313d2022303930}
		 $hex6= {2461323d2022324032}
		 $hex7= {2461333d2022324833}
		 $hex8= {2461343d2022616263}
		 $hex9= {2461353d2022414243}
		 $hex10= {2461363d20222e3f41}
		 $hex11= {2461373d2022437265}
		 $hex12= {2461383d2022446973}
		 $hex13= {2461393d2022476469}
		 $hex14= {247331303d20226170}
		 $hex15= {247331313d20226170}
		 $hex16= {247331323d20226170}
		 $hex17= {247331333d20226170}
		 $hex18= {247331343d20226170}
		 $hex19= {247331353d20226170}
		 $hex20= {247331363d2022436f}
		 $hex21= {247331373d20226464}
		 $hex22= {247331383d20226578}
		 $hex23= {247331393d20226578}
		 $hex24= {2473313d202231332e}
		 $hex25= {247332303d20226578}
		 $hex26= {247332313d20224669}
		 $hex27= {247332323d20224d69}
		 $hex28= {247332333d20224d69}
		 $hex29= {247332343d20224f72}
		 $hex30= {247332353d20225365}
		 $hex31= {247332363d20225653}
		 $hex32= {2473323d2022416170}
		 $hex33= {2473333d2022617069}
		 $hex34= {2473343d2022617069}
		 $hex35= {2473353d2022617069}
		 $hex36= {2473363d2022617069}
		 $hex37= {2473373d2022617069}
		 $hex38= {2473383d2022617069}
		 $hex39= {2473393d2022617069}

	condition:
		4 of them
}
