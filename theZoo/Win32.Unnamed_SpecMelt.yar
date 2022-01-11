
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Unnamed_SpecMelt 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Unnamed_SpecMelt {
	meta: 
		 description= "Win32_Unnamed_SpecMelt Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-35-03" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8f188da25ac5dcdaf4bba56d84d83c56"

	strings:

	
 		 $s1= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s4= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s5= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s6= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s7= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s8= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s9= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s10= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s11= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s12= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s13= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s14= "Bapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s15= "dddd, MMMM dd, yyyy" fullword wide
		 $s16= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s17= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s18= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s19= "UTF-16LEUNICODE" fullword wide
		 $a1= "30848@8D8H8L8P8T8X88`8d8p8t8x8|8" fullword ascii
		 $a2= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a3= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a4= "email._header_value_parser)" fullword ascii
		 $a5= "ExpandEnvironmentStringsW" fullword ascii
		 $a6= "GetFileInformationByHandleEx" fullword ascii
		 $a7= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a8= "InitializeCriticalSectionEx" fullword ascii
		 $a9= "IsProcessorFeaturePresent" fullword ascii
		 $a10= "Py_FileSystemDefaultEncoding" fullword ascii
		 $a11= "pyi-windows-manifest-filename" fullword ascii
		 $a12= "PyMarshal_ReadObjectFromString" fullword ascii
		 $a13= "PyUnicode_DecodeFSDefault" fullword ascii
		 $a14= "SetUnhandledExceptionFilter" fullword ascii
		 $a15= "SystemTimeToTzSpecificLocalTime" fullword ascii

		 $hex1= {246131303d20225079}
		 $hex2= {246131313d20227079}
		 $hex3= {246131323d20225079}
		 $hex4= {246131333d20225079}
		 $hex5= {246131343d20225365}
		 $hex6= {246131353d20225379}
		 $hex7= {2461313d2022333038}
		 $hex8= {2461323d2022616263}
		 $hex9= {2461333d2022414243}
		 $hex10= {2461343d2022656d61}
		 $hex11= {2461353d2022457870}
		 $hex12= {2461363d2022476574}
		 $hex13= {2461373d2022496e69}
		 $hex14= {2461383d2022496e69}
		 $hex15= {2461393d2022497350}
		 $hex16= {247331303d20226170}
		 $hex17= {247331313d20226170}
		 $hex18= {247331323d20226170}
		 $hex19= {247331333d20226170}
		 $hex20= {247331343d20224261}
		 $hex21= {247331353d20226464}
		 $hex22= {247331363d20226578}
		 $hex23= {247331373d20226578}
		 $hex24= {247331383d20226578}
		 $hex25= {247331393d20225554}
		 $hex26= {2473313d2022617069}
		 $hex27= {2473323d2022617069}
		 $hex28= {2473333d2022617069}
		 $hex29= {2473343d2022617069}
		 $hex30= {2473353d2022617069}
		 $hex31= {2473363d2022617069}
		 $hex32= {2473373d2022617069}
		 $hex33= {2473383d2022617069}
		 $hex34= {2473393d2022617069}

	condition:
		4 of them
}
