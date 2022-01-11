
/*
   YARA Rule Set
   Author: resteex
   Identifier: Careto_Feb2014 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Careto_Feb2014 {
	meta: 
		 description= "Careto_Feb2014 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-38" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "5cfd31b1573461a381f5bffa49ea1ed6"
		 hash2= "8102aef50b9c7456f62cdbeefa5fa9de"
		 hash3= "ad6590e0df575228911852b1e401d46e"
		 hash4= "c2ba81c0de01038a54703de26b18e9ee"

	strings:

	
 		 $s1= "6.1.7601.17965 (win7sp1_gdr.121004-0333)" fullword wide
		 $s2= "7.00.5730.13 (longhorn(wmbla).070711-1130)" fullword wide
		 $s3= "BaseNamedObjects" fullword wide
		 $s4= "FileDescription" fullword wide
		 $s5= "Internet Explorer" fullword wide
		 $s6= "Microsoft Corporation" fullword wide
		 $s7= "Microsoft Corporation. All rights reserved." fullword wide
		 $s8= "Operating System" fullword wide
		 $s9= "OriginalFilename" fullword wide
		 $s10= "Shell implementation manager" fullword wide
		 $s11= "VS_VERSION_INFO" fullword wide
		 $s12= "Wang Laboratories, Inc." fullword wide
		 $s13= "Wang Laboratories, Inc. 1989-1995" fullword wide
		 $s14= "WinFXDocObj.exe" fullword wide
		 $s15= "WinFX Runtime Components" fullword wide
		 $a1= "++++++++++++++++++++++++++++++++++++++++++++" fullword ascii
		 $a2= "%02.2X-%02.2X-%02.2X-%02.2X-%02.2X-%02.2X" fullword ascii
		 $a3= "DisableThreadLibraryCalls" fullword ascii
		 $a4= "ExpandEnvironmentStringsA" fullword ascii
		 $a5= "ExpandEnvironmentStringsW" fullword ascii
		 $a6= "GetQueuedCompletionStatus" fullword ascii
		 $a7= "#http://crl.verisign.com/pca3-g5.crl04" fullword ascii
		 $a8= "/http://csc3-2010-aia.verisign.com/CSC3-2010.cer0" fullword ascii
		 $a9= "/http://csc3-2010-crl.verisign.com/CSC3-2010.crl0D" fullword ascii
		 $a10= "#http://logo.verisign.com/vslogo.gif04" fullword ascii
		 $a11= "http://ocsp.verisign.com0" fullword ascii
		 $a12= "http://ocsp.verisign.com0;" fullword ascii
		 $a13= "http://ocsp.verisign.com0>" fullword ascii
		 $a14= "https://www.verisign.com/cps0" fullword ascii
		 $a15= "https://www.verisign.com/cps0*" fullword ascii
		 $a16= "https://www.verisign.com/rpa0" fullword ascii
		 $a17= "InterlockedCompareExchange" fullword ascii
		 $a18= "JJI'KJIAJJIRJJI[JJIVJJIDJJI-NNM" fullword ascii
		 $a19= "NtQueryInformationProcess" fullword ascii
		 $a20= "+++++++++++++++++++++++++O+" fullword ascii
		 $a21= "PostQueuedCompletionStatus" fullword ascii
		 $a22= "%s %d %02d-%02d-%4d %s" fullword ascii
		 $a23= "SetUnhandledExceptionFilter" fullword ascii

		 $hex1= {246131303d20222368}
		 $hex2= {246131313d20226874}
		 $hex3= {246131323d20226874}
		 $hex4= {246131333d20226874}
		 $hex5= {246131343d20226874}
		 $hex6= {246131353d20226874}
		 $hex7= {246131363d20226874}
		 $hex8= {246131373d2022496e}
		 $hex9= {246131383d20224a4a}
		 $hex10= {246131393d20224e74}
		 $hex11= {2461313d20222b2b2b}
		 $hex12= {246132303d20222b2b}
		 $hex13= {246132313d2022506f}
		 $hex14= {246132323d20222573}
		 $hex15= {246132333d20225365}
		 $hex16= {2461323d2022253032}
		 $hex17= {2461333d2022446973}
		 $hex18= {2461343d2022457870}
		 $hex19= {2461353d2022457870}
		 $hex20= {2461363d2022476574}
		 $hex21= {2461373d2022236874}
		 $hex22= {2461383d20222f6874}
		 $hex23= {2461393d20222f6874}
		 $hex24= {247331303d20225368}
		 $hex25= {247331313d20225653}
		 $hex26= {247331323d20225761}
		 $hex27= {247331333d20225761}
		 $hex28= {247331343d20225769}
		 $hex29= {247331353d20225769}
		 $hex30= {2473313d2022362e31}
		 $hex31= {2473323d2022372e30}
		 $hex32= {2473333d2022426173}
		 $hex33= {2473343d202246696c}
		 $hex34= {2473353d2022496e74}
		 $hex35= {2473363d20224d6963}
		 $hex36= {2473373d20224d6963}
		 $hex37= {2473383d20224f7065}
		 $hex38= {2473393d20224f7269}

	condition:
		4 of them
}
