
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
		 date = "2022-01-14_19-55-12" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "36524c90ca1fac2102e7653dfadb31b2"
		 hash2= "aa2cd9d9fc5d196caa6f8fd5979e3f14"

	strings:

	
 		 $s1= "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s3= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s4= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s5= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s6= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s7= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s8= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide

		 $hex1= {2473313d2022416170}
		 $hex2= {2473323d2022617069}
		 $hex3= {2473333d2022617069}
		 $hex4= {2473343d2022617069}
		 $hex5= {2473353d2022617069}
		 $hex6= {2473363d2022617069}
		 $hex7= {2473373d2022657874}
		 $hex8= {2473383d2022657874}

	condition:
		1 of them
}
