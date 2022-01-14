
/*
   YARA Rule Set
   Author: resteex
   Identifier: Daserf 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Daserf {
	meta: 
		 description= "Daserf Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_00-46-04" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0793e40192cb5916d1aeb03e045ddd58"
		 hash2= "1142d535d2616fb8d9136bb7ae787122"
		 hash3= "12a4388ade3fad199631f6a00894104c"
		 hash4= "1dc550eaf37331a8febe5d9f4176269e"
		 hash5= "3be85c7fb6c58e70e470a3dbdbabd9f4"
		 hash6= "84ae14ac6eb9c6c47c1e5c881a92efb8"
		 hash7= "8cdcd24227b7f20d05562eb9a5168ea3"
		 hash8= "93c30900a62fc456556640b2d49f19fb"
		 hash9= "956b124855184b6fe4e41bc262caa39e"
		 hash10= "a9885f03b8d6ffc7b7331f0c798a370e"
		 hash11= "c85aa9e5d81e00702a4f2ee9026e8cd6"
		 hash12= "cfd6fdebf249975e2953548d7cce5e3e"
		 hash13= "d7a713e57405859e14321f8bebd9916b"

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
