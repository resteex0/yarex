
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
		 date = "2022-01-20_04-42-02" 
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
		 $s2= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s3= "@api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s5= "@api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s6= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s7= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s8= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s9= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s10= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s11= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s12= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s13= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s14= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s15= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s16= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s17= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s18= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s19= "Bapi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s20= "Bapi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s21= "Content-Type: application/x-www-form-urlencoded" fullword wide
		 $s22= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s23= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s24= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $a1= "2http://crl3.digicert.com/DigiCertAssuredIDCA-1.crl08" fullword ascii
		 $a2= "2http://crl4.digicert.com/DigiCertAssuredIDCA-1.crl0w" fullword ascii
		 $a3= "5http://cacerts.digicert.com/DigiCertAssuredIDCA-1.crt0" fullword ascii
		 $a4= "/http://crl3.digicert.com/sha2-assured-cs-g1.crl05" fullword ascii
		 $a5= "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
		 $a6= "Local SettingsSoftwareMicrosoftWindowsShellMuiCache" fullword ascii

		 $hex1= {2461313d2022326874}
		 $hex2= {2461323d2022326874}
		 $hex3= {2461333d2022356874}
		 $hex4= {2461343d20222f6874}
		 $hex5= {2461353d20222f6874}
		 $hex6= {2461363d20224c6f63}
		 $hex7= {247331303d20226170}
		 $hex8= {247331313d20226170}
		 $hex9= {247331323d20226170}
		 $hex10= {247331333d20226170}
		 $hex11= {247331343d20226170}
		 $hex12= {247331353d20226170}
		 $hex13= {247331363d20226170}
		 $hex14= {247331373d20226170}
		 $hex15= {247331383d20226170}
		 $hex16= {247331393d20224261}
		 $hex17= {2473313d2022406170}
		 $hex18= {247332303d20224261}
		 $hex19= {247332313d2022436f}
		 $hex20= {247332323d20226578}
		 $hex21= {247332333d20226578}
		 $hex22= {247332343d20226578}
		 $hex23= {2473323d2022617069}
		 $hex24= {2473333d2022406170}
		 $hex25= {2473343d2022617069}
		 $hex26= {2473353d2022406170}
		 $hex27= {2473363d2022617069}
		 $hex28= {2473373d2022617069}
		 $hex29= {2473383d2022617069}
		 $hex30= {2473393d2022617069}

	condition:
		20 of them
}
