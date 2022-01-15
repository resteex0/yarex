
/*
   YARA Rule Set
   Author: resteex
   Identifier: NetFilter 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_NetFilter {
	meta: 
		 description= "NetFilter Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-15-52" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "c664fc54853d9b50d7e33bad5bd7070e"
		 hash2= "ccea678c13f13a8d6438a314e26cdc2a"

	strings:

	
 		 $s1= "%04d-%02d-%02d %02d:%02d:%02d" fullword wide
		 $s2= "/%04d-%02d-%02d %02d:%02d:%02d" fullword wide
		 $s3= "DefaultConnectionSettings" fullword wide
		 $s4= "D:P(A;;GA;;;SY)(A;;GA;;;BA)" fullword wide
		 $s5= "EnableLegacyAutoProxyFeatures" fullword wide
		 $s6= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword wide
		 $a1= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword ascii

		 $hex1= {2461313d2022536f66}
		 $hex2= {2473313d2022253034}
		 $hex3= {2473323d20222f2530}
		 $hex4= {2473333d2022446566}
		 $hex5= {2473343d2022443a50}
		 $hex6= {2473353d2022456e61}
		 $hex7= {2473363d2022536f66}

	condition:
		4 of them
}
