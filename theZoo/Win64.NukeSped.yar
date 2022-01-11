
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win64_NukeSped 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win64_NukeSped {
	meta: 
		 description= "Win64_NukeSped Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-35-23" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "379d680a2accaa48444524968d1aa782"
		 hash2= "cebc3a9192d6b516e7937038acb689b0"
		 hash3= "e1068cacba806002b1cba6ebfb35e4f4"

	strings:

	
 		 $s1= "%04d-%02d-%02d %02d:%02d:%02d" fullword wide
		 $s2= "%08x-%04d-%02d-%04x%04x" fullword wide
		 $s3= "6.1.7600.16385 (win7_rtm.090713-1255)" fullword wide
		 $s4= "- abort() has been called" fullword wide
		 $s5= "- Attempt to initialize the CRT more than once." fullword wide
		 $s6= "- Attempt to use MSIL code from this assembly during native code initialization" fullword wide
		 $s7= "BMicrosoft Visual C++ Runtime Library" fullword wide
		 $s8= "/clr) function from a native constructor or from DllMain." fullword wide
		 $s9= "- CRT not initialized" fullword wide
		 $s10= "dddd, MMMM dd, yyyy" fullword wide
		 $s11= "FileDescription" fullword wide
		 $s12= "- floating point support not loaded" fullword wide
		 $s13= "HARDWAREDESCRIPTIONSystemCentralProcessor0" fullword wide
		 $s14= "Host Process for Windows Tasks" fullword wide
		 $s15= "Microsoft Corporation" fullword wide
		 $s16= "Microsoft Corporation. All rights reserved." fullword wide
		 $s17= "Microsoft Visual C++ Runtime Library" fullword wide
		 $s18= "Network Compatible Module" fullword wide
		 $s19= "- not enough space for arguments" fullword wide
		 $s20= "- not enough space for environment" fullword wide
		 $s21= "- not enough space for locale information" fullword wide
		 $s22= "- not enough space for lowio initialization" fullword wide
		 $s23= "- not enough space for _onexit/atexit table" fullword wide
		 $s24= "- not enough space for stdio initialization" fullword wide
		 $s25= "- not enough space for thread data" fullword wide
		 $s26= "Operating System" fullword wide
		 $s27= "OriginalFilename" fullword wide
		 $s28= "PROCESSOR_ARCHITECTURE" fullword wide
		 $s29= "ProcessorNameString" fullword wide
		 $s30= "program name unknown>" fullword wide
		 $s31= "- pure virtual function call" fullword wide
		 $s32= "SeAssignPrimaryTokenPrivilege" fullword wide
		 $s33= "SeIncreaseQuotaPrivilege" fullword wide
		 $s34= "SeTakeOwnershipPrivilege" fullword wide
		 $s35= "SOFTWAREMICROSOFTWINDOWS NTCURRENTVERSION" fullword wide
		 $s36= "SYSTEMCurrentControlSetControlSession ManagerEnvironment" fullword wide
		 $s37= "This indicates a bug in your application." fullword wide
		 $s38= "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (" fullword wide
		 $s39= "- unable to initialize heap" fullword wide
		 $s40= "- unable to open console device" fullword wide
		 $s41= "- unexpected heap error" fullword wide
		 $s42= "- unexpected multithread lock error" fullword wide
		 $s43= "VS_VERSION_INFO" fullword wide
		 $s44= "winsta0default" fullword wide
		 $a1= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a2= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a3= "GetUserObjectInformationW" fullword ascii
		 $a4= "InitializeCriticalSection" fullword ascii
		 $a5= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a6= "IsProcessorFeaturePresent" fullword ascii
		 $a7= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a8= "RegisterServiceCtrlHandlerExW" fullword ascii
		 $a9= "SetUnhandledExceptionFilter" fullword ascii
		 $a10= "WTSGetActiveConsoleSessionId" fullword ascii
		 $a11= "WTSQuerySessionInformationW" fullword ascii

		 $hex1= {246131303d20225754}
		 $hex2= {246131313d20225754}
		 $hex3= {2461313d2022616263}
		 $hex4= {2461323d2022414243}
		 $hex5= {2461333d2022476574}
		 $hex6= {2461343d2022496e69}
		 $hex7= {2461353d2022496e69}
		 $hex8= {2461363d2022497350}
		 $hex9= {2461373d20224a616e}
		 $hex10= {2461383d2022526567}
		 $hex11= {2461393d2022536574}
		 $hex12= {247331303d20226464}
		 $hex13= {247331313d20224669}
		 $hex14= {247331323d20222d20}
		 $hex15= {247331333d20224841}
		 $hex16= {247331343d2022486f}
		 $hex17= {247331353d20224d69}
		 $hex18= {247331363d20224d69}
		 $hex19= {247331373d20224d69}
		 $hex20= {247331383d20224e65}
		 $hex21= {247331393d20222d20}
		 $hex22= {2473313d2022253034}
		 $hex23= {247332303d20222d20}
		 $hex24= {247332313d20222d20}
		 $hex25= {247332323d20222d20}
		 $hex26= {247332333d20222d20}
		 $hex27= {247332343d20222d20}
		 $hex28= {247332353d20222d20}
		 $hex29= {247332363d20224f70}
		 $hex30= {247332373d20224f72}
		 $hex31= {247332383d20225052}
		 $hex32= {247332393d20225072}
		 $hex33= {2473323d2022253038}
		 $hex34= {247333303d20227072}
		 $hex35= {247333313d20222d20}
		 $hex36= {247333323d20225365}
		 $hex37= {247333333d20225365}
		 $hex38= {247333343d20225365}
		 $hex39= {247333353d2022534f}
		 $hex40= {247333363d20225359}
		 $hex41= {247333373d20225468}
		 $hex42= {247333383d20225468}
		 $hex43= {247333393d20222d20}
		 $hex44= {2473333d2022362e31}
		 $hex45= {247334303d20222d20}
		 $hex46= {247334313d20222d20}
		 $hex47= {247334323d20222d20}
		 $hex48= {247334333d20225653}
		 $hex49= {247334343d20227769}
		 $hex50= {2473343d20222d2061}
		 $hex51= {2473353d20222d2041}
		 $hex52= {2473363d20222d2041}
		 $hex53= {2473373d2022424d69}
		 $hex54= {2473383d20222f636c}
		 $hex55= {2473393d20222d2043}

	condition:
		6 of them
}
