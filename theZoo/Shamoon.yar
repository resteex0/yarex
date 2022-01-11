
/*
   YARA Rule Set
   Author: resteex
   Identifier: Shamoon 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Shamoon {
	meta: 
		 description= "Shamoon Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-29-55" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "b14299fd4d1cbfb4cc7486d978398214"
		 hash2= "d214c717a357fe3a455610b197c390aa"

	strings:

	
 		 $s1= "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
		 $s2= "- abort() has been called" fullword wide
		 $s3= "AMicrosoft Visual C++ Runtime Library" fullword wide
		 $s4= "and efficient maintenance of links within the domain. If this service is disabled, any services tha" fullword wide
		 $s5= "- Attempt to initialize the CRT more than once." fullword wide
		 $s6= "- Attempt to use MSIL code from this assembly during native code initialization" fullword wide
		 $s7= "/clr) function from a native constructor or from DllMain." fullword wide
		 $s8= "- CRT not initialized" fullword wide
		 $s9= "C:Windowssystem32svchost.exe -k netsvcs" fullword wide
		 $s10= "dddd, MMMM dd, yyyy" fullword wide
		 $s11= "Distributed Link Tracking Server" fullword wide
		 $s12= "Enables the Distributed Link Tracking Client service within the same domain to provide more reliable" fullword wide
		 $s13= "FileDescription" fullword wide
		 $s14= "- floating point support not loaded" fullword wide
		 $s15= "infnetft429.pnf" fullword wide
		 $s16= "@LanmanWorkstation" fullword wide
		 $s17= "Microsoft Corporation" fullword wide
		 $s18= "Microsoft Corporation. All rights reserved." fullword wide
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
		 $s29= "program name unknown>" fullword wide
		 $s30= "- pure virtual function call" fullword wide
		 $s31= "system32csrss.exe" fullword wide
		 $s32= "system32kernel32.dll" fullword wide
		 $s33= "SYSTEMCurrentControlSetControlSession ManagerEnvironment" fullword wide
		 $s34= "SYSTEMCurrentControlSetServicesTrkSvr" fullword wide
		 $s35= "t explicitly depend on it will fail to start." fullword wide
		 $s36= "This indicates a bug in your application." fullword wide
		 $s37= "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (" fullword wide
		 $s38= "- unable to initialize heap" fullword wide
		 $s39= "- unable to open console device" fullword wide
		 $s40= "- unexpected heap error" fullword wide
		 $s41= "- unexpected multithread lock error" fullword wide
		 $s42= "VS_VERSION_INFO" fullword wide
		 $a1= "((((((((((((((((((((((((((((((((((((((((((((((((((" fullword ascii
		 $a2= "2!2%2)2-2125292=2A2E2I2M2Q2U2Y2]2a2e2i2m2q2u2y2}2" fullword ascii
		 $a3= "3&3-343;3B3I3P3X3`3h3t3}3" fullword ascii
		 $a4= "7@7D7H7L7P7T7X77`7d7h7l7H8L8P8T8h8l8" fullword ascii
		 $a5= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a6= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a7= ".?AV?$basic_filebuf@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a8= ".?AV?$basic_fstream@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a9= ".?AV?$basic_ios@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a10= ".?AV?$basic_iostream@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a11= ".?AV?$basic_istream@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a12= ".?AV?$basic_ostream@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a13= ".?AV?$basic_streambuf@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a14= ".?AVfailure@ios_base@std@@" fullword ascii
		 $a15= ".?AV_Generic_error_category@std@@" fullword ascii
		 $a16= ".?AV_Iostream_error_category@std@@" fullword ascii
		 $a17= ".?AV_System_error_category@std@@" fullword ascii
		 $a18= "c:windowstempout17626867.txt" fullword ascii
		 $a19= "%E@ioF@RoF@]#E@UoF@>oF@]#E@1oF@" fullword ascii
		 $a20= "+F@0*F@]#E@5*F@b%F@]#E@e%F@%%F@" fullword ascii
		 $a21= "F@+}F@u(E@-}F@7|F@)(E@)|F@" fullword ascii
		 $a22= "GetUserObjectInformationW" fullword ascii
		 $a23= "gF@sfF@a*E@efF@,fF@u+E@!fF@" fullword ascii
		 $a24= "InitializeCriticalSection" fullword ascii
		 $a25= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a26= "IsProcessorFeaturePresent" fullword ascii
		 $a27= "pF@zsF@]#E@usF@TsF@]#E@IsF@" fullword ascii
		 $a28= "RegisterServiceCtrlHandlerW" fullword ascii
		 $a29= "SetUnhandledExceptionFilter" fullword ascii
		 $a30= "sF@nrF@u+E@arF@FrF@]#E@9rF@'rF@]#E@ rF@" fullword ascii
		 $a31= "StartServiceCtrlDispatcherW" fullword ascii
		 $a32= "Wow64DisableWow64FsRedirection" fullword ascii
		 $a33= "Wow64RevertWow64FsRedirection" fullword ascii

		 $hex1= {246131303d20222e3f}
		 $hex2= {246131313d20222e3f}
		 $hex3= {246131323d20222e3f}
		 $hex4= {246131333d20222e3f}
		 $hex5= {246131343d20222e3f}
		 $hex6= {246131353d20222e3f}
		 $hex7= {246131363d20222e3f}
		 $hex8= {246131373d20222e3f}
		 $hex9= {246131383d2022633a}
		 $hex10= {246131393d20222545}
		 $hex11= {2461313d2022282828}
		 $hex12= {246132303d20222b46}
		 $hex13= {246132313d20224640}
		 $hex14= {246132323d20224765}
		 $hex15= {246132333d20226746}
		 $hex16= {246132343d2022496e}
		 $hex17= {246132353d2022496e}
		 $hex18= {246132363d20224973}
		 $hex19= {246132373d20227046}
		 $hex20= {246132383d20225265}
		 $hex21= {246132393d20225365}
		 $hex22= {2461323d2022322132}
		 $hex23= {246133303d20227346}
		 $hex24= {246133313d20225374}
		 $hex25= {246133323d2022576f}
		 $hex26= {246133333d2022576f}
		 $hex27= {2461333d2022332633}
		 $hex28= {2461343d2022374037}
		 $hex29= {2461353d2022616263}
		 $hex30= {2461363d2022414243}
		 $hex31= {2461373d20222e3f41}
		 $hex32= {2461383d20222e3f41}
		 $hex33= {2461393d20222e3f41}
		 $hex34= {247331303d20226464}
		 $hex35= {247331313d20224469}
		 $hex36= {247331323d2022456e}
		 $hex37= {247331333d20224669}
		 $hex38= {247331343d20222d20}
		 $hex39= {247331353d2022696e}
		 $hex40= {247331363d2022404c}
		 $hex41= {247331373d20224d69}
		 $hex42= {247331383d20224d69}
		 $hex43= {247331393d20222d20}
		 $hex44= {2473313d2022352e32}
		 $hex45= {247332303d20222d20}
		 $hex46= {247332313d20222d20}
		 $hex47= {247332323d20222d20}
		 $hex48= {247332333d20222d20}
		 $hex49= {247332343d20222d20}
		 $hex50= {247332353d20222d20}
		 $hex51= {247332363d20224f70}
		 $hex52= {247332373d20224f72}
		 $hex53= {247332383d20225052}
		 $hex54= {247332393d20227072}
		 $hex55= {2473323d20222d2061}
		 $hex56= {247333303d20222d20}
		 $hex57= {247333313d20227379}
		 $hex58= {247333323d20227379}
		 $hex59= {247333333d20225359}
		 $hex60= {247333343d20225359}
		 $hex61= {247333353d20227420}
		 $hex62= {247333363d20225468}
		 $hex63= {247333373d20225468}
		 $hex64= {247333383d20222d20}
		 $hex65= {247333393d20222d20}
		 $hex66= {2473333d2022414d69}
		 $hex67= {247334303d20222d20}
		 $hex68= {247334313d20222d20}
		 $hex69= {247334323d20225653}
		 $hex70= {2473343d2022616e64}
		 $hex71= {2473353d20222d2041}
		 $hex72= {2473363d20222d2041}
		 $hex73= {2473373d20222f636c}
		 $hex74= {2473383d20222d2043}
		 $hex75= {2473393d2022433a57}

	condition:
		9 of them
}
