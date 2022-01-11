
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Matsnu 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Matsnu {
	meta: 
		 description= "Ransomware_Matsnu Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-27-44" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1b2d2a4b97c7c2727d571bbf9376f54f"

	strings:

	
 		 $s1= "- abort() has been called" fullword wide
		 $s2= "- Attempt to initialize the CRT more than once." fullword wide
		 $s3= "- Attempt to use MSIL code from this assembly during native code initialization" fullword wide
		 $s4= "/clr) function from a native constructor or from DllMain." fullword wide
		 $s5= "- CRT not initialized" fullword wide
		 $s6= "dddd, MMMM dd, yyyy" fullword wide
		 $s7= "FileDescription" fullword wide
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
		 $s19= "This indicates a bug in your application." fullword wide
		 $s20= "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (" fullword wide
		 $s21= "- unable to initialize heap" fullword wide
		 $s22= "- unable to open console device" fullword wide
		 $s23= "- unexpected heap error" fullword wide
		 $s24= "- unexpected multithread lock error" fullword wide
		 $s25= "VS_VERSION_INFO" fullword wide
		 $a1= "3#3)31363>3C3K3P3W3f3k3q3z3" fullword ascii
		 $a2= "7@7D7H7L7X77`7d7h7l7p7t7x7|7" fullword ascii
		 $a3= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a4= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a5= "GetUserObjectInformationW" fullword ascii
		 $a6= ":H=L=P=T=X==`=d=h=l=p=t=x=|=" fullword ascii
		 $a7= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a8= "IsProcessorFeaturePresent" fullword ascii
		 $a9= "LookupPrivilegeDisplayNameW" fullword ascii
		 $a10= "SetUnhandledExceptionFilter" fullword ascii

		 $hex1= {246131303d20225365}
		 $hex2= {2461313d2022332333}
		 $hex3= {2461323d2022374037}
		 $hex4= {2461333d2022616263}
		 $hex5= {2461343d2022414243}
		 $hex6= {2461353d2022476574}
		 $hex7= {2461363d20223a483d}
		 $hex8= {2461373d2022496e69}
		 $hex9= {2461383d2022497350}
		 $hex10= {2461393d20224c6f6f}
		 $hex11= {247331303d20222d20}
		 $hex12= {247331313d20222d20}
		 $hex13= {247331323d20222d20}
		 $hex14= {247331333d20222d20}
		 $hex15= {247331343d20222d20}
		 $hex16= {247331353d20222d20}
		 $hex17= {247331363d20222d20}
		 $hex18= {247331373d20227072}
		 $hex19= {247331383d20222d20}
		 $hex20= {247331393d20225468}
		 $hex21= {2473313d20222d2061}
		 $hex22= {247332303d20225468}
		 $hex23= {247332313d20222d20}
		 $hex24= {247332323d20222d20}
		 $hex25= {247332333d20222d20}
		 $hex26= {247332343d20222d20}
		 $hex27= {247332353d20225653}
		 $hex28= {2473323d20222d2041}
		 $hex29= {2473333d20222d2041}
		 $hex30= {2473343d20222f636c}
		 $hex31= {2473353d20222d2043}
		 $hex32= {2473363d2022646464}
		 $hex33= {2473373d202246696c}
		 $hex34= {2473383d20222d2066}
		 $hex35= {2473393d2022404d69}

	condition:
		4 of them
}
