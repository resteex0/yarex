
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_OnionDuke_B 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_OnionDuke_B {
	meta: 
		 description= "Win32_OnionDuke_B Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-33-18" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "c8eb6040fd02d77660d19057a38ff769"

	strings:

	
 		 $s1= "- abort() has been called" fullword wide
		 $s2= "- Attempt to initialize the CRT more than once." fullword wide
		 $s3= "- Attempt to use MSIL code from this assembly during native code initialization" fullword wide
		 $s4= "/clr) function from a native constructor or from DllMain." fullword wide
		 $s5= "- CRT not initialized" fullword wide
		 $s6= "dddd, MMMM dd, yyyy" fullword wide
		 $s7= "- floating point support not loaded" fullword wide
		 $s8= "Microsoft Visual C++ Runtime Library" fullword wide
		 $s9= "- not enough space for arguments" fullword wide
		 $s10= "- not enough space for environment" fullword wide
		 $s11= "- not enough space for locale information" fullword wide
		 $s12= "- not enough space for lowio initialization" fullword wide
		 $s13= "- not enough space for _onexit/atexit table" fullword wide
		 $s14= "- not enough space for stdio initialization" fullword wide
		 $s15= "- not enough space for thread data" fullword wide
		 $s16= "program name unknown>" fullword wide
		 $s17= "- pure virtual function call" fullword wide
		 $s18= "This indicates a bug in your application." fullword wide
		 $s19= "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (" fullword wide
		 $s20= "- unable to initialize heap" fullword wide
		 $s21= "- unable to open console device" fullword wide
		 $s22= "- unexpected heap error" fullword wide
		 $s23= "- unexpected multithread lock error" fullword wide
		 $a1= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a2= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a3= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii
		 $a4= ".?AVCryptedCfgCtlModule@@" fullword ascii
		 $a5= ".?AVIHostIdentification@@" fullword ascii
		 $a6= ".?AVITempFileCreator@NtHttpModule_UrlDownloadToFile@@" fullword ascii
		 $a7= ".?AVNtHttpClient_UrlDownloadToFile@@" fullword ascii
		 $a8= ".?AVNtHttpModule_UrlDownloadToFile@@" fullword ascii
		 $a9= ".?AVNtStartup_ExplorerShellFolders@@" fullword ascii
		 $a10= "dZ]{GGCtVGzvcAKJp]UZTuApFAAV]Gf@VA" fullword ascii
		 $a11= "ExpandEnvironmentStringsW" fullword ascii
		 $a12= "GetUserObjectInformationW" fullword ascii
		 $a13= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a14= "IsProcessorFeaturePresent" fullword ascii
		 $a15= "SetUnhandledExceptionFilter" fullword ascii

		 $hex1= {246131303d2022645a}
		 $hex2= {246131313d20224578}
		 $hex3= {246131323d20224765}
		 $hex4= {246131333d2022496e}
		 $hex5= {246131343d20224973}
		 $hex6= {246131353d20225365}
		 $hex7= {2461313d2022616263}
		 $hex8= {2461323d2022414243}
		 $hex9= {2461333d2022414243}
		 $hex10= {2461343d20222e3f41}
		 $hex11= {2461353d20222e3f41}
		 $hex12= {2461363d20222e3f41}
		 $hex13= {2461373d20222e3f41}
		 $hex14= {2461383d20222e3f41}
		 $hex15= {2461393d20222e3f41}
		 $hex16= {247331303d20222d20}
		 $hex17= {247331313d20222d20}
		 $hex18= {247331323d20222d20}
		 $hex19= {247331333d20222d20}
		 $hex20= {247331343d20222d20}
		 $hex21= {247331353d20222d20}
		 $hex22= {247331363d20227072}
		 $hex23= {247331373d20222d20}
		 $hex24= {247331383d20225468}
		 $hex25= {247331393d20225468}
		 $hex26= {2473313d20222d2061}
		 $hex27= {247332303d20222d20}
		 $hex28= {247332313d20222d20}
		 $hex29= {247332323d20222d20}
		 $hex30= {247332333d20222d20}
		 $hex31= {2473323d20222d2041}
		 $hex32= {2473333d20222d2041}
		 $hex33= {2473343d20222f636c}
		 $hex34= {2473353d20222d2043}
		 $hex35= {2473363d2022646464}
		 $hex36= {2473373d20222d2066}
		 $hex37= {2473383d20224d6963}
		 $hex38= {2473393d20222d206e}

	condition:
		4 of them
}
