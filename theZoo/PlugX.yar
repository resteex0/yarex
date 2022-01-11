
/*
   YARA Rule Set
   Author: resteex
   Identifier: PlugX 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_PlugX {
	meta: 
		 description= "PlugX Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-27-13" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "3bc9e9b78ac6dee1a44436859849bbbf"
		 hash2= "3c74a85c2cf883bd9d4b9f8b9746030f"
		 hash3= "5f9f8ac1f749b0637eca6ef15910bf21"
		 hash4= "6b97b3cd2fcfb4b74985143230441463"
		 hash5= "901fa02ffd43de5b2d7c8c6b8c2f6a43"
		 hash6= "97c11e7d6b1926cd4be13804b36239ac"
		 hash7= "c116cd083284cc599c024c3479ca9b70"
		 hash8= "fc88beeb7425aefa5e8936e06849f484"

	strings:

	
 		 $s1= "2013-05-05 11:11:12 | C:WINDOWSsystem32cmd.exe | C:WINDOWSsystem32cmd.exe" fullword wide
		 $s2= "2013-05-05 11:11:32 | C:MyTranslationslangpack.exe | Regshot 1.8.2" fullword wide
		 $s3= "Copyright 2006 - 2011" fullword wide
		 $s4= "DocumentSummaryInformation" fullword wide
		 $s5= "FileDescription" fullword wide
		 $s6= "GlobalDelSelf(%8.8X)" fullword wide
		 $s7= "LegalTrademarks" fullword wide
		 $s8= "OriginalFilename" fullword wide
		 $s9= "%sSidebar.dll.doc" fullword wide
		 $s10= "strings: Warning: 'theZoo/malware/Binaries/PlugX/PlugX/originalfile' is a directory" fullword wide
		 $s11= "SummaryInformation" fullword wide
		 $s12= "TENCENT SideBar" fullword wide
		 $s13= "Times New Roman" fullword wide
		 $s14= "VS_VERSION_INFO" fullword wide
		 $a1= "001464a5c7a5316bcd56492e47a8f1c7cce1a26447efedb6a2fafa9c07ac1f20b447214da0c4d6da31740GIS" fullword ascii
		 $a2= "0http://crl.verisign.com/ThawteTimestampingCA.crl0" fullword ascii
		 $a3= "3http://csc3-2009-2-aia.verisign.com/CSC3-2009-2.cer0" fullword ascii
		 $a4= "3http://csc3-2009-2-crl.verisign.com/CSC3-2009-2.crl0D" fullword ascii
		 $a5= "4%4+42494@4G4N4U44d4l4t4" fullword ascii
		 $a6= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a7= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a8= "GetUserObjectInformationA" fullword ascii
		 $a9= "#http://logo.verisign.com/vslogo.gif0" fullword ascii
		 $a10= "http://ocsp.verisign.com0" fullword ascii
		 $a11= "http://ocsp.verisign.com0?" fullword ascii
		 $a12= "http://ocsp.verisign.com01" fullword ascii
		 $a13= "https://www.verisign.com/cps0*" fullword ascii
		 $a14= "https://www.verisign.com/rpa0" fullword ascii
		 $a15= "InitializeCriticalSection" fullword ascii
		 $a16= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a17= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a18= "SetUnhandledExceptionFilter" fullword ascii

		 $hex1= {246131303d20226874}
		 $hex2= {246131313d20226874}
		 $hex3= {246131323d20226874}
		 $hex4= {246131333d20226874}
		 $hex5= {246131343d20226874}
		 $hex6= {246131353d2022496e}
		 $hex7= {246131363d2022496e}
		 $hex8= {246131373d20224a61}
		 $hex9= {246131383d20225365}
		 $hex10= {2461313d2022303031}
		 $hex11= {2461323d2022306874}
		 $hex12= {2461333d2022336874}
		 $hex13= {2461343d2022336874}
		 $hex14= {2461353d2022342534}
		 $hex15= {2461363d2022616263}
		 $hex16= {2461373d2022414243}
		 $hex17= {2461383d2022476574}
		 $hex18= {2461393d2022236874}
		 $hex19= {247331303d20227374}
		 $hex20= {247331313d20225375}
		 $hex21= {247331323d20225445}
		 $hex22= {247331333d20225469}
		 $hex23= {247331343d20225653}
		 $hex24= {2473313d2022323031}
		 $hex25= {2473323d2022323031}
		 $hex26= {2473333d2022436f70}
		 $hex27= {2473343d2022446f63}
		 $hex28= {2473353d202246696c}
		 $hex29= {2473363d2022476c6f}
		 $hex30= {2473373d20224c6567}
		 $hex31= {2473383d20224f7269}
		 $hex32= {2473393d2022257353}

	condition:
		4 of them
}
