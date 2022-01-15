
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_LuckyCat 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_LuckyCat {
	meta: 
		 description= "Win32_LuckyCat Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-54-55" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "9f9723c5ff4ec1b7f08eb2005632b8b1"
		 hash2= "c1d73ce5bf0559a86bae0f9045a82e0a"

	strings:

	
 		 $s1= "115.126.6.16:110" fullword wide
		 $s2= "#(-27;@EJOTY^chmrw|" fullword wide
		 $s3= "Adobe Photoshop" fullword wide
		 $s4= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s6= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s7= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s8= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s9= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s10= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s11= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s12= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s13= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s14= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s15= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s16= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s17= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s18= "dalailamatrustindia.ddns.net:110" fullword wide
		 $s19= "dalailamatrustindia.ddns.net:443" fullword wide
		 $s20= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s21= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s22= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s23= "FileDescription" fullword wide
		 $s24= "j-stripe_compound" fullword wide
		 $s25= "OriginalFilename" fullword wide
		 $s26= "VS_VERSION_INFO" fullword wide
		 $a1= "api-ms-win-core-localization-l1-2-1" fullword ascii
		 $a2= "api-ms-win-core-localization-obsolete-l1-2-0" fullword ascii
		 $a3= "api-ms-win-core-processthreads-l1-1-2" fullword ascii
		 $a4= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword ascii
		 $a5= "api-ms-win-security-systemfunctions-l1-1-0" fullword ascii
		 $a6= "ext-ms-win-kernel32-package-current-l1-1-0" fullword ascii
		 $a7= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword ascii

		 $hex1= {2461313d2022617069}
		 $hex2= {2461323d2022617069}
		 $hex3= {2461333d2022617069}
		 $hex4= {2461343d2022617069}
		 $hex5= {2461353d2022617069}
		 $hex6= {2461363d2022657874}
		 $hex7= {2461373d2022657874}
		 $hex8= {247331303d20226170}
		 $hex9= {247331313d20226170}
		 $hex10= {247331323d20226170}
		 $hex11= {247331333d20226170}
		 $hex12= {247331343d20226170}
		 $hex13= {247331353d20226170}
		 $hex14= {247331363d20226170}
		 $hex15= {247331373d20226170}
		 $hex16= {247331383d20226461}
		 $hex17= {247331393d20226461}
		 $hex18= {2473313d2022313135}
		 $hex19= {247332303d20226578}
		 $hex20= {247332313d20226578}
		 $hex21= {247332323d20226578}
		 $hex22= {247332333d20224669}
		 $hex23= {247332343d20226a2d}
		 $hex24= {247332353d20224f72}
		 $hex25= {247332363d20225653}
		 $hex26= {2473323d202223282d}
		 $hex27= {2473333d202241646f}
		 $hex28= {2473343d2022617069}
		 $hex29= {2473353d2022617069}
		 $hex30= {2473363d2022617069}
		 $hex31= {2473373d2022617069}
		 $hex32= {2473383d2022617069}
		 $hex33= {2473393d2022617069}

	condition:
		4 of them
}
