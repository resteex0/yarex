
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Lephic 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Lephic {
	meta: 
		 description= "Win32_Lephic Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-33-07" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "39192da38ad821d5e6cd6b68843dc81d"

	strings:

	
 		 $s1= "- abort() has been called" fullword wide
		 $s2= "AMicrosoft Visual C++ Runtime Library" fullword wide
		 $s3= "- Attempt to initialize the CRT more than once." fullword wide
		 $s4= "- Attempt to use MSIL code from this assembly during native code initialization" fullword wide
		 $s5= "/clr) function from a native constructor or from DllMain." fullword wide
		 $s6= "- CRT not initialized" fullword wide
		 $s7= "dddd, MMMM dd, yyyy" fullword wide
		 $s8= "FileDescription" fullword wide
		 $s9= "- floating point support not loaded" fullword wide
		 $s10= "NAT Software 2007" fullword wide
		 $s11= "NAT Software, Germany." fullword wide
		 $s12= "- not enough space for arguments" fullword wide
		 $s13= "- not enough space for environment" fullword wide
		 $s14= "- not enough space for locale information" fullword wide
		 $s15= "- not enough space for lowio initialization" fullword wide
		 $s16= "- not enough space for _onexit/atexit table" fullword wide
		 $s17= "- not enough space for stdio initialization" fullword wide
		 $s18= "- not enough space for thread data" fullword wide
		 $s19= "OriginalFilename" fullword wide
		 $s20= "program name unknown>" fullword wide
		 $s21= "- pure virtual function call" fullword wide
		 $s22= "This indicates a bug in your application." fullword wide
		 $s23= "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (" fullword wide
		 $s24= "- unable to initialize heap" fullword wide
		 $s25= "- unable to open console device" fullword wide
		 $s26= "- unexpected heap error" fullword wide
		 $s27= "- unexpected multithread lock error" fullword wide
		 $s28= "VS_VERSION_INFO" fullword wide
		 $s29= "www.nat32.com/xampp" fullword wide
		 $s30= "XAMPP Control Panel" fullword wide
		 $s31= "XAMPP Control Panel for Windows" fullword wide
		 $a1= "%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz" fullword ascii
		 $a2= "&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz" fullword ascii
		 $a3= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a4= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a5= "GetUserObjectInformationW" fullword ascii
		 $a6= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a7= "IsProcessorFeaturePresent" fullword ascii
		 $a8= "MsgWaitForMultipleObjects" fullword ascii
		 $a9= "RetrieveUrlCacheEntryStreamW" fullword ascii
		 $a10= "SetSoftwareUpdateAdvertisementState" fullword ascii
		 $a11= "SetUnhandledExceptionFilter" fullword ascii

		 $hex1= {246131303d20225365}
		 $hex2= {246131313d20225365}
		 $hex3= {2461313d2022252627}
		 $hex4= {2461323d2022262728}
		 $hex5= {2461333d2022616263}
		 $hex6= {2461343d2022414243}
		 $hex7= {2461353d2022476574}
		 $hex8= {2461363d2022496e69}
		 $hex9= {2461373d2022497350}
		 $hex10= {2461383d20224d7367}
		 $hex11= {2461393d2022526574}
		 $hex12= {247331303d20224e41}
		 $hex13= {247331313d20224e41}
		 $hex14= {247331323d20222d20}
		 $hex15= {247331333d20222d20}
		 $hex16= {247331343d20222d20}
		 $hex17= {247331353d20222d20}
		 $hex18= {247331363d20222d20}
		 $hex19= {247331373d20222d20}
		 $hex20= {247331383d20222d20}
		 $hex21= {247331393d20224f72}
		 $hex22= {2473313d20222d2061}
		 $hex23= {247332303d20227072}
		 $hex24= {247332313d20222d20}
		 $hex25= {247332323d20225468}
		 $hex26= {247332333d20225468}
		 $hex27= {247332343d20222d20}
		 $hex28= {247332353d20222d20}
		 $hex29= {247332363d20222d20}
		 $hex30= {247332373d20222d20}
		 $hex31= {247332383d20225653}
		 $hex32= {247332393d20227777}
		 $hex33= {2473323d2022414d69}
		 $hex34= {247333303d20225841}
		 $hex35= {247333313d20225841}
		 $hex36= {2473333d20222d2041}
		 $hex37= {2473343d20222d2041}
		 $hex38= {2473353d20222f636c}
		 $hex39= {2473363d20222d2043}
		 $hex40= {2473373d2022646464}
		 $hex41= {2473383d202246696c}
		 $hex42= {2473393d20222d2066}

	condition:
		5 of them
}
