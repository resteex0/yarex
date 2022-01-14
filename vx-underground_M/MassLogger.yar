
/*
   YARA Rule Set
   Author: resteex
   Identifier: MassLogger 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_MassLogger {
	meta: 
		 description= "MassLogger Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_06-52-32" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "15d1d1f6b45ecb4da929978f8be4ca0f"

	strings:

	
 		 $s1= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s2= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s3= "Capi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s4= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s5= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s6= "pi-ms-win-core-localization-l1-2-1" fullword wide
		 $s7= "pi-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s8= "pi-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s9= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide

		 $hex1= {2473313d2022617069}
		 $hex2= {2473323d2022617069}
		 $hex3= {2473333d2022436170}
		 $hex4= {2473343d2022657874}
		 $hex5= {2473353d2022657874}
		 $hex6= {2473363d202270692d}
		 $hex7= {2473373d202270692d}
		 $hex8= {2473383d202270692d}
		 $hex9= {2473393d2022536f66}

	condition:
		1 of them
}
