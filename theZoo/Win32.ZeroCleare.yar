
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_ZeroCleare 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_ZeroCleare {
	meta: 
		 description= "Win32_ZeroCleare Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_19-55-19" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1a69a02b0cd10b1764521fec4b7376c9"
		 hash2= "33f98b613b331b49e272512274669844"
		 hash3= "8afa8a59eebf43ef223be52e08fcdc67"
		 hash4= "c04236b5678af08c8b70a7aa696f87d5"
		 hash5= "f5f8160fe8468a77b6a495155c3dacea"

	strings:

	
 		 $s1= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s2= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s3= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s4= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s5= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s6= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s7= "SystemCurrentControlSetControlNetworkProviderOrder" fullword wide
		 $a1= "SystemCurrentControlSetControlNetworkProviderOrder" fullword ascii

		 $hex1= {2461313d2022537973}
		 $hex2= {2473313d2022617069}
		 $hex3= {2473323d2022617069}
		 $hex4= {2473333d2022617069}
		 $hex5= {2473343d2022617069}
		 $hex6= {2473353d2022617069}
		 $hex7= {2473363d2022657874}
		 $hex8= {2473373d2022537973}

	condition:
		1 of them
}
