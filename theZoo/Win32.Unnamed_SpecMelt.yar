
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Unnamed_SpecMelt 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Unnamed_SpecMelt {
	meta: 
		 description= "Win32_Unnamed_SpecMelt Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_19-55-17" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8f188da25ac5dcdaf4bba56d84d83c56"

	strings:

	
 		 $s1= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s2= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s3= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s4= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s5= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s6= "Bapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s7= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s8= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide

		 $hex1= {2473313d2022617069}
		 $hex2= {2473323d2022617069}
		 $hex3= {2473333d2022617069}
		 $hex4= {2473343d2022617069}
		 $hex5= {2473353d2022617069}
		 $hex6= {2473363d2022426170}
		 $hex7= {2473373d2022657874}
		 $hex8= {2473383d2022657874}

	condition:
		1 of them
}
