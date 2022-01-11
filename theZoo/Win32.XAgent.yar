
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_XAgent 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_XAgent {
	meta: 
		 description= "Win32_XAgent Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-35-13" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "2f6d1bed602a3ad749301e7aa3800139"

	strings:

	
 		 $s1= "- abort() has been called" fullword wide
		 $s2= "All rights reserved." fullword wide
		 $s3= "- Attempt to initialize the CRT more than once." fullword wide
		 $s4= "- Attempt to use MSIL code from this assembly during native code initialization" fullword wide
		 $s5= "/clr) function from a native constructor or from DllMain." fullword wide
		 $s6= "- CRT not initialized" fullword wide
		 $s7= "dddd, MMMM dd, yyyy" fullword wide
		 $s8= "FileDescription" fullword wide
		 $s9= "- floating point support not loaded" fullword wide
		 $s10= "Microsoft Certificates Service Provider" fullword wide
		 $s11= "Microsoft Corporation. " fullword wide
		 $s12= "Microsoft Corporation" fullword wide
		 $s13= "Microsoft Visual C++ Runtime Library" fullword wide
		 $s14= "Microsoft Windows Operating System" fullword wide
		 $s15= "- not enough space for arguments" fullword wide
		 $s16= "- not enough space for environment" fullword wide
		 $s17= "- not enough space for locale information" fullword wide
		 $s18= "- not enough space for lowio initialization" fullword wide
		 $s19= "- not enough space for _onexit/atexit table" fullword wide
		 $s20= "- not enough space for stdio initialization" fullword wide
		 $s21= "- not enough space for thread data" fullword wide
		 $s22= "OriginalFilename" fullword wide
		 $s23= "program name unknown>" fullword wide
		 $s24= "- pure virtual function call" fullword wide
		 $s25= "RegisterServiceCtrlHandler" fullword wide
		 $s26= "%s failed with %d" fullword wide
		 $s27= "StartServiceCtrlDispatcher" fullword wide
		 $s28= "This indicates a bug in your application." fullword wide
		 $s29= "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (" fullword wide
		 $s30= "- unable to initialize heap" fullword wide
		 $s31= "- unable to open console device" fullword wide
		 $s32= "- unexpected heap error" fullword wide
		 $s33= "- unexpected multithread lock error" fullword wide
		 $s34= "VS_VERSION_INFO" fullword wide
		 $a1= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a2= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a3= ".?AV?$_Ref_count@D@tr1@std@@" fullword ascii
		 $a4= ".?AV?$_Ref_count@Udata_channels@?1??uzLuTALpZgTerhiajGHV@xCdCffWUTWoDKLURRxrS@@UEAA_NXZ@@tr1@std@@" fullword ascii
		 $a5= ".?AV?$_Ref_count@VbYihchDvnQauECWaXFjI@@@tr1@std@@" fullword ascii
		 $a6= ".?AV?$_Ref_count@VMaJPNzbCAMfKjjIfSNiT@@@tr1@std@@" fullword ascii
		 $a7= ".?AVDCeZEgcGlvkjUAVByAEV@@" fullword ascii
		 $a8= ".?AVDzhZUdsLPdKjrqpXmClK@@" fullword ascii
		 $a9= ".?AVfIuRvNZlsGCDJrznaIDO@@" fullword ascii
		 $a10= ".?AVhPZZGzygYBZzqjjljpsT@@" fullword ascii
		 $a11= ".?AVIrwJVaQrBWjgrNbGtXML@@" fullword ascii
		 $a12= ".?AVjCjFTtyhlStvyKAzXMsh@@" fullword ascii
		 $a13= ".?AVkPvcanJMLQsbMDyGNjHL@@" fullword ascii
		 $a14= ".?AVLgVAyiZLPRQBTTPZQZsU@@" fullword ascii
		 $a15= ".?AVOkMtbEopOoLSTIByrjKC@@" fullword ascii
		 $a16= ".?AVpKlMWvvPDtmxCBJPBImx@@" fullword ascii
		 $a17= ".?AVpRqxvVlUqIWSpWdCfjVc@@" fullword ascii
		 $a18= ".?AVqkocRWQxBlfdRHLYAQcr@@" fullword ascii
		 $a19= ".?AV_Ref_count_base@tr1@std@@" fullword ascii
		 $a20= ".?AVSwffypPannErGmyGZpCp@@" fullword ascii
		 $a21= ".?AVvkrREjkNPlvCrRXBScFk@@" fullword ascii
		 $a22= ".?AVwbKNLLNNoPpvUsyFecFb@@" fullword ascii
		 $a23= ".?AVxCdCffWUTWoDKLURRxrS@@" fullword ascii
		 $a24= ".?AVZrEdkXtznbKOReTTwIJe@@" fullword ascii
		 $a25= "ExpandEnvironmentStringsW" fullword ascii
		 $a26= "GetUserObjectInformationW" fullword ascii
		 $a27= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a28= "InternetQueryDataAvailable" fullword ascii
		 $a29= "RegisterServiceCtrlHandlerW" fullword ascii
		 $a30= "SetUnhandledExceptionFilter" fullword ascii
		 $a31= "StartServiceCtrlDispatcherW" fullword ascii
		 $a32= "SystemTimeToTzSpecificLocalTime" fullword ascii

		 $hex1= {246131303d20222e3f}
		 $hex2= {246131313d20222e3f}
		 $hex3= {246131323d20222e3f}
		 $hex4= {246131333d20222e3f}
		 $hex5= {246131343d20222e3f}
		 $hex6= {246131353d20222e3f}
		 $hex7= {246131363d20222e3f}
		 $hex8= {246131373d20222e3f}
		 $hex9= {246131383d20222e3f}
		 $hex10= {246131393d20222e3f}
		 $hex11= {2461313d2022616263}
		 $hex12= {246132303d20222e3f}
		 $hex13= {246132313d20222e3f}
		 $hex14= {246132323d20222e3f}
		 $hex15= {246132333d20222e3f}
		 $hex16= {246132343d20222e3f}
		 $hex17= {246132353d20224578}
		 $hex18= {246132363d20224765}
		 $hex19= {246132373d2022496e}
		 $hex20= {246132383d2022496e}
		 $hex21= {246132393d20225265}
		 $hex22= {2461323d2022414243}
		 $hex23= {246133303d20225365}
		 $hex24= {246133313d20225374}
		 $hex25= {246133323d20225379}
		 $hex26= {2461333d20222e3f41}
		 $hex27= {2461343d20222e3f41}
		 $hex28= {2461353d20222e3f41}
		 $hex29= {2461363d20222e3f41}
		 $hex30= {2461373d20222e3f41}
		 $hex31= {2461383d20222e3f41}
		 $hex32= {2461393d20222e3f41}
		 $hex33= {247331303d20224d69}
		 $hex34= {247331313d20224d69}
		 $hex35= {247331323d20224d69}
		 $hex36= {247331333d20224d69}
		 $hex37= {247331343d20224d69}
		 $hex38= {247331353d20222d20}
		 $hex39= {247331363d20222d20}
		 $hex40= {247331373d20222d20}
		 $hex41= {247331383d20222d20}
		 $hex42= {247331393d20222d20}
		 $hex43= {2473313d20222d2061}
		 $hex44= {247332303d20222d20}
		 $hex45= {247332313d20222d20}
		 $hex46= {247332323d20224f72}
		 $hex47= {247332333d20227072}
		 $hex48= {247332343d20222d20}
		 $hex49= {247332353d20225265}
		 $hex50= {247332363d20222573}
		 $hex51= {247332373d20225374}
		 $hex52= {247332383d20225468}
		 $hex53= {247332393d20225468}
		 $hex54= {2473323d2022416c6c}
		 $hex55= {247333303d20222d20}
		 $hex56= {247333313d20222d20}
		 $hex57= {247333323d20222d20}
		 $hex58= {247333333d20222d20}
		 $hex59= {247333343d20225653}
		 $hex60= {2473333d20222d2041}
		 $hex61= {2473343d20222d2041}
		 $hex62= {2473353d20222f636c}
		 $hex63= {2473363d20222d2043}
		 $hex64= {2473373d2022646464}
		 $hex65= {2473383d202246696c}
		 $hex66= {2473393d20222d2066}

	condition:
		8 of them
}
