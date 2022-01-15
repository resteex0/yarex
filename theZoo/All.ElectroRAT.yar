
/*
   YARA Rule Set
   Author: resteex
   Identifier: All_ElectroRAT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_All_ElectroRAT {
	meta: 
		 description= "All_ElectroRAT Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_19-53-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0468127a19daf4c7bc41015c5640fe1f"
		 hash2= "2a3b92f6180367306d750e59c9b6446b"
		 hash3= "b154ac015c0d1d6250032f63c749f9cf"
		 hash4= "b96bd6bbf0e3f4f98b606a2ab5db4a69"
		 hash5= "bb8e52face5b076cc890bbfaaf4bb73e"
		 hash6= "ca467e332368cbae652245faa4978aa4"
		 hash7= "e93d6f4ce34d4f594d7aed76cfde0fad"
		 hash8= "fa5390bbcc4ab768dd81f31eac0950f6"

	strings:

	
 		 $s1= "@api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s3= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s4= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s5= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s6= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s7= "Content-Type: application/x-www-form-urlencoded" fullword wide
		 $s8= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s9= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide

		 $hex1= {2473313d2022406170}
		 $hex2= {2473323d2022617069}
		 $hex3= {2473333d2022617069}
		 $hex4= {2473343d2022617069}
		 $hex5= {2473353d2022617069}
		 $hex6= {2473363d2022617069}
		 $hex7= {2473373d2022436f6e}
		 $hex8= {2473383d2022657874}
		 $hex9= {2473393d2022657874}

	condition:
		1 of them
}
