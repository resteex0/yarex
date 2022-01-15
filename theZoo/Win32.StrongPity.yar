
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_StrongPity 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_StrongPity {
	meta: 
		 description= "Win32_StrongPity Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_19-55-12" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "a4d3b78941da8b6f4edad7cb6f35134b"
		 hash2= "cab76ac00e342f77bdfec3e85b6b85a9"

	strings:

	
 		 $s1= "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s3= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s4= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s5= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s6= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s7= "Content-Type: application/x-www-form-urlencoded" fullword wide
		 $s8= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s9= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide

		 $hex1= {2473313d2022416170}
		 $hex2= {2473323d2022617069}
		 $hex3= {2473333d2022617069}
		 $hex4= {2473343d2022617069}
		 $hex5= {2473353d2022617069}
		 $hex6= {2473363d2022617069}
		 $hex7= {2473373d2022436f6e}
		 $hex8= {2473383d2022657874}
		 $hex9= {2473393d2022657874}

	condition:
		1 of them
}
