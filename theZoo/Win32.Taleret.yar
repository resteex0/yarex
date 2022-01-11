
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Taleret 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Taleret {
	meta: 
		 description= "Win32_Taleret Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-33-56" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "c4de3fea790f8ff6452016db5d7aa33f"
		 hash2= "d9940a3da42eb2bb8e19a84235d86e91"
		 hash3= "fed166a667ab9cbb1ef6331b8e9d7894"

	strings:

	
 		 $s1= "- abort() has been called" fullword wide
		 $s2= "- Attempt to initialize the CRT more than once." fullword wide
		 $s3= "- Attempt to use MSIL code from this assembly during native code initialization" fullword wide
		 $s4= "/clr) function from a native constructor or from DllMain." fullword wide
		 $s5= "- CRT not initialized" fullword wide
		 $s6= "dddd, MMMM dd, yyyy" fullword wide
		 $s7= "DocumentSummaryInformation" fullword wide
		 $s8= "- floating point support not loaded" fullword wide
		 $s9= "@Microsoft Visual C++ Runtime Library" fullword wide
		 $s10= "- not enough space for arguments" fullword wide
		 $s11= "- not enough space for environment" fullword wide
		 $s12= "- not enough space for locale information" fullword wide
		 $s13= "- not enough space for lowio initialization" fullword wide
		 $s14= "- not enough space for _onexit/atexit table" fullword wide
		 $s15= "- not enough space for stdio initialization" fullword wide
		 $s16= "- not enough space for thread data" fullword wide
		 $s17= "program name unknown>" fullword wide
		 $s18= "- pure virtual function call" fullword wide
		 $s19= "SummaryInformation" fullword wide
		 $s20= "This indicates a bug in your application." fullword wide
		 $s21= "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (" fullword wide
		 $s22= "Times New Roman" fullword wide
		 $s23= "- unable to initialize heap" fullword wide
		 $s24= "- unable to open console device" fullword wide
		 $s25= "- unexpected heap error" fullword wide
		 $s26= "- unexpected multithread lock error" fullword wide
		 $a1= "%02X-%02X-%02X-%02X-%02X-%02X" fullword ascii
		 $a2= "617db52426b2982f4d6d99616a24125f>]" fullword ascii
		 $a3= "{A8A88C49-5EB2-4990-A1A2-0876022C854F}" fullword ascii
		 $a4= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a5= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a6= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii
		 $a7= "{AEBA21FA-782A-4A90-978D-B72164C80120}" fullword ascii
		 $a8= "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" fullword ascii
		 $a9= "DefaultConnectionSettings" fullword ascii
		 $a10= "ExpandEnvironmentStringsA" fullword ascii
		 $a11= "GetUserObjectInformationW" fullword ascii
		 $a12= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a13= "IsProcessorFeaturePresent" fullword ascii
		 $a14= "RegisterServiceCtrlHandlerW" fullword ascii
		 $a15= "SetUnhandledExceptionFilter" fullword ascii
		 $a16= "SoftwareMicrosoftSysInternal" fullword ascii
		 $a17= "theme/theme/_rels/themeManager.xml.rels" fullword ascii
		 $a18= "theme/theme/_rels/themeManager.xml.relsPK" fullword ascii
		 $a19= "theme/theme/themeManager.xml" fullword ascii
		 $a20= "theme/theme/themeManager.xmlPK" fullword ascii
		 $a21= "urn:schemas-microsoft-com:office:smarttags" fullword ascii

		 $hex1= {246131303d20224578}
		 $hex2= {246131313d20224765}
		 $hex3= {246131323d2022496e}
		 $hex4= {246131333d20224973}
		 $hex5= {246131343d20225265}
		 $hex6= {246131353d20225365}
		 $hex7= {246131363d2022536f}
		 $hex8= {246131373d20227468}
		 $hex9= {246131383d20227468}
		 $hex10= {246131393d20227468}
		 $hex11= {2461313d2022253032}
		 $hex12= {246132303d20227468}
		 $hex13= {246132313d20227572}
		 $hex14= {2461323d2022363137}
		 $hex15= {2461333d20227b4138}
		 $hex16= {2461343d2022616263}
		 $hex17= {2461353d2022414243}
		 $hex18= {2461363d2022414243}
		 $hex19= {2461373d20227b4145}
		 $hex20= {2461383d2022444444}
		 $hex21= {2461393d2022446566}
		 $hex22= {247331303d20222d20}
		 $hex23= {247331313d20222d20}
		 $hex24= {247331323d20222d20}
		 $hex25= {247331333d20222d20}
		 $hex26= {247331343d20222d20}
		 $hex27= {247331353d20222d20}
		 $hex28= {247331363d20222d20}
		 $hex29= {247331373d20227072}
		 $hex30= {247331383d20222d20}
		 $hex31= {247331393d20225375}
		 $hex32= {2473313d20222d2061}
		 $hex33= {247332303d20225468}
		 $hex34= {247332313d20225468}
		 $hex35= {247332323d20225469}
		 $hex36= {247332333d20222d20}
		 $hex37= {247332343d20222d20}
		 $hex38= {247332353d20222d20}
		 $hex39= {247332363d20222d20}
		 $hex40= {2473323d20222d2041}
		 $hex41= {2473333d20222d2041}
		 $hex42= {2473343d20222f636c}
		 $hex43= {2473353d20222d2043}
		 $hex44= {2473363d2022646464}
		 $hex45= {2473373d2022446f63}
		 $hex46= {2473383d20222d2066}
		 $hex47= {2473393d2022404d69}

	condition:
		5 of them
}
