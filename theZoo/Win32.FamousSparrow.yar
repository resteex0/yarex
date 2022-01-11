
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_FamousSparrow 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_FamousSparrow {
	meta: 
		 description= "Win32_FamousSparrow Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-32-27" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "b162026b29d75a870543ad9c044c28c2"
		 hash2= "c40a2f5f25157e6a434602017531d608"
		 hash3= "f44b04364b2b33a84adc172f337aa1d1"
		 hash4= "fdf677939cb36c29a6b4b139fad5acde"

	strings:

	
 		 $s1= "- abort() has been called" fullword wide
		 $s2= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s3= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s6= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s7= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s8= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s9= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s10= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s11= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s12= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s13= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s14= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s15= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s16= "- Attempt to initialize the CRT more than once." fullword wide
		 $s17= "- Attempt to use MSIL code from this assembly during native code initialization" fullword wide
		 $s18= "/clr) function from a native constructor or from DllMain." fullword wide
		 $s19= "Copyright (C) 2003-2011 K7 Computing Pvt Ltd" fullword wide
		 $s20= "- CRT not initialized" fullword wide
		 $s21= "dddd, MMMM dd, yyyy" fullword wide
		 $s22= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s23= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s24= "FileDescription" fullword wide
		 $s25= "- floating point support not loaded" fullword wide
		 $s26= "K7 Computing Pvt Ltd" fullword wide
		 $s27= "K7Security Suite of Products" fullword wide
		 $s28= "K7TotalSecurity Log View Manager" fullword wide
		 $s29= "Microsoft Visual C++ Runtime Library" fullword wide
		 $s30= "- not enough space for arguments" fullword wide
		 $s31= "- not enough space for environment" fullword wide
		 $s32= "- not enough space for locale information" fullword wide
		 $s33= "- not enough space for lowio initialization" fullword wide
		 $s34= "- not enough space for _onexit/atexit table" fullword wide
		 $s35= "- not enough space for stdio initialization" fullword wide
		 $s36= "- not enough space for thread data" fullword wide
		 $s37= "OriginalFilename" fullword wide
		 $s38= "program name unknown>" fullword wide
		 $s39= "- pure virtual function call" fullword wide
		 $s40= "This indicates a bug in your application." fullword wide
		 $s41= "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (" fullword wide
		 $s42= "- unable to initialize heap" fullword wide
		 $s43= "- unable to open console device" fullword wide
		 $s44= "- unexpected heap error" fullword wide
		 $s45= "- unexpected multithread lock error" fullword wide
		 $s46= "VS_VERSION_INFO" fullword wide
		 $a1= "0http://crl.verisign.com/ThawteTimestampingCA.crl0" fullword ascii
		 $a2= "1&1,141;1@1H1Q1]1b1g1m1q1w1|1" fullword ascii
		 $a3= "@4D4H4L4P4T4X44`4d4h4l4p4t4x4|4" fullword ascii
		 $a4= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a5= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a6= "AppPolicyGetProcessTerminationMethod" fullword ascii
		 $a7= "?@?D?H?L?P?T?X??`?d?h?l?p?t?" fullword ascii
		 $a8= ":@:D:H:L:P:T:X::`:d:h:l:p:t:x:|:" fullword ascii
		 $a9= "fgdebc`anolmjkhivwturspq~" fullword ascii
		 $a10= "GetUserObjectInformationA" fullword ascii
		 $a11= "GetUserObjectInformationW" fullword ascii
		 $a12= "#http://crl.verisign.com/pca3-g5.crl04" fullword ascii
		 $a13= "/http://csc3-2010-aia.verisign.com/CSC3-2010.cer0" fullword ascii
		 $a14= "/http://csc3-2010-crl.verisign.com/CSC3-2010.crl0D" fullword ascii
		 $a15= "#http://logo.verisign.com/vslogo.gif04" fullword ascii
		 $a16= "http://ocsp.verisign.com0" fullword ascii
		 $a17= "http://ocsp.verisign.com0;" fullword ascii
		 $a18= "https://www.verisign.com/cps0*" fullword ascii
		 $a19= "https://www.verisign.com/rpa0" fullword ascii
		 $a20= "InitializeCriticalSection" fullword ascii
		 $a21= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a22= "InitializeCriticalSectionEx" fullword ascii
		 $a23= "InterlockedCompareExchange" fullword ascii
		 $a24= "InterlockedPushEntrySList" fullword ascii
		 $a25= "IsProcessorFeaturePresent" fullword ascii
		 $a26= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a27= "SetUnhandledExceptionFilter" fullword ascii
		 $a28= "WritePrivateProfileStringA" fullword ascii
		 $a29= "|}z{xyFGDEBC@ANOLMJKHIVWTURSPQ^_]Z[XY" fullword ascii

		 $hex1= {246131303d20224765}
		 $hex2= {246131313d20224765}
		 $hex3= {246131323d20222368}
		 $hex4= {246131333d20222f68}
		 $hex5= {246131343d20222f68}
		 $hex6= {246131353d20222368}
		 $hex7= {246131363d20226874}
		 $hex8= {246131373d20226874}
		 $hex9= {246131383d20226874}
		 $hex10= {246131393d20226874}
		 $hex11= {2461313d2022306874}
		 $hex12= {246132303d2022496e}
		 $hex13= {246132313d2022496e}
		 $hex14= {246132323d2022496e}
		 $hex15= {246132333d2022496e}
		 $hex16= {246132343d2022496e}
		 $hex17= {246132353d20224973}
		 $hex18= {246132363d20224a61}
		 $hex19= {246132373d20225365}
		 $hex20= {246132383d20225772}
		 $hex21= {246132393d20227c7d}
		 $hex22= {2461323d2022312631}
		 $hex23= {2461333d2022403444}
		 $hex24= {2461343d2022616263}
		 $hex25= {2461353d2022414243}
		 $hex26= {2461363d2022417070}
		 $hex27= {2461373d20223f403f}
		 $hex28= {2461383d20223a403a}
		 $hex29= {2461393d2022666764}
		 $hex30= {247331303d20226170}
		 $hex31= {247331313d20226170}
		 $hex32= {247331323d20226170}
		 $hex33= {247331333d20226170}
		 $hex34= {247331343d20226170}
		 $hex35= {247331353d20226170}
		 $hex36= {247331363d20222d20}
		 $hex37= {247331373d20222d20}
		 $hex38= {247331383d20222f63}
		 $hex39= {247331393d2022436f}
		 $hex40= {2473313d20222d2061}
		 $hex41= {247332303d20222d20}
		 $hex42= {247332313d20226464}
		 $hex43= {247332323d20226578}
		 $hex44= {247332333d20226578}
		 $hex45= {247332343d20224669}
		 $hex46= {247332353d20222d20}
		 $hex47= {247332363d20224b37}
		 $hex48= {247332373d20224b37}
		 $hex49= {247332383d20224b37}
		 $hex50= {247332393d20224d69}
		 $hex51= {2473323d2022617069}
		 $hex52= {247333303d20222d20}
		 $hex53= {247333313d20222d20}
		 $hex54= {247333323d20222d20}
		 $hex55= {247333333d20222d20}
		 $hex56= {247333343d20222d20}
		 $hex57= {247333353d20222d20}
		 $hex58= {247333363d20222d20}
		 $hex59= {247333373d20224f72}
		 $hex60= {247333383d20227072}
		 $hex61= {247333393d20222d20}
		 $hex62= {2473333d2022617069}
		 $hex63= {247334303d20225468}
		 $hex64= {247334313d20225468}
		 $hex65= {247334323d20222d20}
		 $hex66= {247334333d20222d20}
		 $hex67= {247334343d20222d20}
		 $hex68= {247334353d20222d20}
		 $hex69= {247334363d20225653}
		 $hex70= {2473343d2022617069}
		 $hex71= {2473353d2022617069}
		 $hex72= {2473363d2022617069}
		 $hex73= {2473373d2022617069}
		 $hex74= {2473383d2022617069}
		 $hex75= {2473393d2022617069}

	condition:
		9 of them
}
