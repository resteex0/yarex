
/*
   YARA Rule Set
   Author: resteex
   Identifier: Chapak 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Chapak {
	meta: 
		 description= "Chapak Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_00-28-17" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "00810b59644d1610f9eb57e2d9e175e4"
		 hash2= "6ec836e7cf86162bb62ed8d3483f770b"
		 hash3= "c21f9c393077da2f80a2010f93173060"

	strings:

	
 		 $s1= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s2= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s3= "Capi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s4= "Control PanelDesktopResourceLocale" fullword wide
		 $s5= ".DEFAULTControl PanelInternational" fullword wide
		 $s6= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s7= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s8= "pi-ms-win-core-localization-l1-2-1" fullword wide
		 $s9= "pi-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s10= "pi-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s11= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide

		 $hex1= {247331303d20227069}
		 $hex2= {247331313d2022536f}
		 $hex3= {2473313d2022617069}
		 $hex4= {2473323d2022617069}
		 $hex5= {2473333d2022436170}
		 $hex6= {2473343d2022436f6e}
		 $hex7= {2473353d20222e4445}
		 $hex8= {2473363d2022657874}
		 $hex9= {2473373d2022657874}
		 $hex10= {2473383d202270692d}
		 $hex11= {2473393d202270692d}

	condition:
		1 of them
}
