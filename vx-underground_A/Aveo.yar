
/*
   YARA Rule Set
   Author: resteex
   Identifier: Aveo 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Aveo {
	meta: 
		 description= "Aveo Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_19-49-04" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ae2b5bd70945b1622fb27496ec9e15fe"
		 hash2= "cd6d979280146c3205010ac3c4b81d02"

	strings:

	
 		 $s1= "- abort() has been called" fullword wide
		 $s2= "- Attempt to initialize the CRT more than once." fullword wide
		 $s3= "- Attempt to use MSIL code from this assembly during native code initialization" fullword wide
		 $s4= "/clr) function from a native constructor or from DllMain." fullword wide
		 $s5= "CryptProtectMemory failed" fullword wide
		 $s6= "CryptUnprotectMemory failed" fullword wide
		 $s7= "- floating point support not loaded" fullword wide
		 $s8= "Maximum allowed array size (%u) is exceeded" fullword wide
		 $s9= "@Microsoft Visual C++ Runtime Library" fullword wide
		 $s10= "- not enough space for arguments" fullword wide
		 $s11= "- not enough space for environment" fullword wide
		 $s12= "- not enough space for locale information" fullword wide
		 $s13= "- not enough space for lowio initialization" fullword wide
		 $s14= "- not enough space for _onexit/atexit table" fullword wide
		 $s15= "- not enough space for stdio initialization" fullword wide
		 $s16= "- not enough space for thread data" fullword wide
		 $s17= "- pure virtual function call" fullword wide
		 $s18= "SeCreateSymbolicLinkPrivilege" fullword wide
		 $s19= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s20= "This indicates a bug in your application." fullword wide
		 $s21= "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (" fullword wide
		 $s22= "Thread pool initialization failed." fullword wide
		 $s23= "__tmp_rar_sfx_access_check_%u" fullword wide
		 $s24= "- unable to initialize heap" fullword wide
		 $s25= "- unable to open console device" fullword wide
		 $s26= "- unexpected multithread lock error" fullword wide
		 $s27= "WaitForMultipleObjects error %d, GetLastError %d" fullword wide

		 $hex1= {247331303d20222d20}
		 $hex2= {247331313d20222d20}
		 $hex3= {247331323d20222d20}
		 $hex4= {247331333d20222d20}
		 $hex5= {247331343d20222d20}
		 $hex6= {247331353d20222d20}
		 $hex7= {247331363d20222d20}
		 $hex8= {247331373d20222d20}
		 $hex9= {247331383d20225365}
		 $hex10= {247331393d2022536f}
		 $hex11= {2473313d20222d2061}
		 $hex12= {247332303d20225468}
		 $hex13= {247332313d20225468}
		 $hex14= {247332323d20225468}
		 $hex15= {247332333d20225f5f}
		 $hex16= {247332343d20222d20}
		 $hex17= {247332353d20222d20}
		 $hex18= {247332363d20222d20}
		 $hex19= {247332373d20225761}
		 $hex20= {2473323d20222d2041}
		 $hex21= {2473333d20222d2041}
		 $hex22= {2473343d20222f636c}
		 $hex23= {2473353d2022437279}
		 $hex24= {2473363d2022437279}
		 $hex25= {2473373d20222d2066}
		 $hex26= {2473383d20224d6178}
		 $hex27= {2473393d2022404d69}

	condition:
		3 of them
}
