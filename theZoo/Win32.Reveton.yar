
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Reveton 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Reveton {
	meta: 
		 description= "Win32_Reveton Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-33-43" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2cdb29c8aa709cdb75f42248c84fe5d7"
		 hash2= "8334d2692aa97076a5bd95a9d9fdfcd5"

	strings:

	
 		 $s1= "5Vvc6uY9l1L0nb9" fullword wide
		 $s2= "65Gi9VWDrzZPCTw" fullword wide
		 $s3= "pec2tAK0tzEqLZkk" fullword wide
		 $s4= "xhbu0bF8Rk0YKSNe" fullword wide
		 $a1= "FillConsoleOutputCharacterW" fullword ascii
		 $a2= "FindNextVolumeMountPointA" fullword ascii
		 $a3= "FindVolumeMountPointClose" fullword ascii
		 $a4= "PseudocodeWidgetSubdirectory" fullword ascii
		 $a5= "YP+P[0:@4aa=[-.@v{_Y-P~q(Q|uU$Dot?7Nq?s$rV{uYBCeO" fullword ascii

		 $hex1= {2461313d202246696c}
		 $hex2= {2461323d202246696e}
		 $hex3= {2461333d202246696e}
		 $hex4= {2461343d2022507365}
		 $hex5= {2461353d202259502b}
		 $hex6= {2473313d2022355676}
		 $hex7= {2473323d2022363547}
		 $hex8= {2473333d2022706563}
		 $hex9= {2473343d2022786862}

	condition:
		1 of them
}
