
/*
   YARA Rule Set
   Author: resteex
   Identifier: Medusa_Locker 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Medusa_Locker {
	meta: 
		 description= "Medusa_Locker Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_06-52-33" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "501d18da4a3dd7f3118e4c8419c29dc3"

	strings:

	
 		 $s1= "{8761ABBD-7F85-42EE-B272-A76179687C63}" fullword wide
		 $s2= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s3= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s4= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s5= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s6= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s7= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s8= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s9= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s10= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s11= "SOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s12= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $a1= "SOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {247331303d20226d69}
		 $hex3= {247331313d2022534f}
		 $hex4= {247331323d2022536f}
		 $hex5= {2473313d20227b3837}
		 $hex6= {2473323d2022617069}
		 $hex7= {2473333d2022617069}
		 $hex8= {2473343d2022617069}
		 $hex9= {2473353d2022617069}
		 $hex10= {2473363d2022617069}
		 $hex11= {2473373d20225f5f63}
		 $hex12= {2473383d20225f5f63}
		 $hex13= {2473393d2022657874}

	condition:
		1 of them
}
