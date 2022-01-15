
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
		 date = "2022-01-14_21-37-10" 
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

	
 		 $s1= "Access violation" fullword wide
		 $s2= "AFX_DIALOG_LAYOUT" fullword wide
		 $s3= "@api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s4= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s5= "@api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s6= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s7= "@api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s8= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s9= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s10= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s11= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s12= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s13= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s14= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s15= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s16= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s17= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s18= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s19= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s20= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s21= "Assertion failed" fullword wide
		 $s22= "August September" fullword wide
		 $s23= "Bapi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s24= "Bapi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s25= "Content-Type: application/x-www-form-urlencoded" fullword wide
		 $s26= "Enhanced Metafiles" fullword wide
		 $s27= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s28= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s29= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s30= "[f(yx{iI_{" fullword wide
		 $s31= "Invalid argument" fullword wide
		 $s32= "Invalid filename" fullword wide
		 $s33= "kwoghvhecyrccrreaooisah" fullword wide
		 $s34= "MfcFontComboBox" fullword wide
		 $s35= "msctls_progress32" fullword wide
		 $s36= "msctls_trackbar32" fullword wide
		 $s37= "SysDateTimePick32" fullword wide
		 $s38= "SysTabControl32" fullword wide
		 $s39= "Tuesday Wednesday" fullword wide
		 $s40= "Variant overflow" fullword wide
		 $s41= "vbmfghjgfjkfghjfg" fullword wide
		 $a1= "@api-ms-win-appmodel-runtime-l1-1-1" fullword ascii
		 $a2= "api-ms-win-core-localization-l1-2-1" fullword ascii
		 $a3= "api-ms-win-core-localization-obsolete-l1-2-0" fullword ascii
		 $a4= "api-ms-win-core-processthreads-l1-1-2" fullword ascii
		 $a5= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword ascii
		 $a6= "api-ms-win-security-systemfunctions-l1-1-0" fullword ascii
		 $a7= "Content-Type: application/x-www-form-urlencoded" fullword ascii
		 $a8= "ext-ms-win-kernel32-package-current-l1-1-0" fullword ascii
		 $a9= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword ascii

		 $hex1= {2461313d2022406170}
		 $hex2= {2461323d2022617069}
		 $hex3= {2461333d2022617069}
		 $hex4= {2461343d2022617069}
		 $hex5= {2461353d2022617069}
		 $hex6= {2461363d2022617069}
		 $hex7= {2461373d2022436f6e}
		 $hex8= {2461383d2022657874}
		 $hex9= {2461393d2022657874}
		 $hex10= {247331303d20226170}
		 $hex11= {247331313d20226170}
		 $hex12= {247331323d20226170}
		 $hex13= {247331333d20226170}
		 $hex14= {247331343d20226170}
		 $hex15= {247331353d20226170}
		 $hex16= {247331363d20226170}
		 $hex17= {247331373d20226170}
		 $hex18= {247331383d20226170}
		 $hex19= {247331393d20226170}
		 $hex20= {2473313d2022416363}
		 $hex21= {247332303d20226170}
		 $hex22= {247332313d20224173}
		 $hex23= {247332323d20224175}
		 $hex24= {247332333d20224261}
		 $hex25= {247332343d20224261}
		 $hex26= {247332353d2022436f}
		 $hex27= {247332363d2022456e}
		 $hex28= {247332373d20226578}
		 $hex29= {247332383d20226578}
		 $hex30= {247332393d20226578}
		 $hex31= {2473323d2022414658}
		 $hex32= {247333303d20225b66}
		 $hex33= {247333313d2022496e}
		 $hex34= {247333323d2022496e}
		 $hex35= {247333333d20226b77}
		 $hex36= {247333343d20224d66}
		 $hex37= {247333353d20226d73}
		 $hex38= {247333363d20226d73}
		 $hex39= {247333373d20225379}
		 $hex40= {247333383d20225379}
		 $hex41= {247333393d20225475}
		 $hex42= {2473333d2022406170}
		 $hex43= {247334303d20225661}
		 $hex44= {247334313d20227662}
		 $hex45= {2473343d2022617069}
		 $hex46= {2473353d2022406170}
		 $hex47= {2473363d2022617069}
		 $hex48= {2473373d2022406170}
		 $hex49= {2473383d2022617069}
		 $hex50= {2473393d2022617069}

	condition:
		16 of them
}
