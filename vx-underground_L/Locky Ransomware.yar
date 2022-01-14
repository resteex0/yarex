
/*
   YARA Rule Set
   Author: resteex
   Identifier: Locky_Ransomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Locky_Ransomware {
	meta: 
		 description= "Locky_Ransomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_04-07-05" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0708745aa6cb07941ce21ccd08f2f052"
		 hash2= "0993d209ab4bc09588679a76af1c4748"
		 hash3= "137b69fdbc4c3a1baa26dcb97c01c37e"
		 hash4= "1c529aa744aa47378d70dcc1e9b523c6"
		 hash5= "205130e0483ffccc7e006dcf5b6bb7f9"
		 hash6= "215ffdd86ba7d27f3e379f92af7970d6"
		 hash7= "4b033f726c6e74456225eda95371c9e4"
		 hash8= "72870e8434cdc713803b4f4351086af4"
		 hash9= "a05bd24c8d244f8692f93658f2f7892a"
		 hash10= "a534f1a1ee7fc4d866c2fd7ae24819f9"
		 hash11= "a845bf3351bbb146207d47aee552a1a2"
		 hash12= "b38ebac9c480f75e61a1ec6a6c781231"
		 hash13= "cb87af578aef90b79dcdb05276519997"
		 hash14= "f0ec4e0dc8da5969dd19729b63d575c2"
		 hash15= "f2311e344f690f016572f4c1df241335"

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
