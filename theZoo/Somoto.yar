
/*
   YARA Rule Set
   Author: resteex
   Identifier: Somoto 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Somoto {
	meta: 
		 description= "Somoto Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-30-01" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "02e0b78e2876087f678f070ed60e4c30"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "MSCTLS_PROGRESS32" fullword wide
		 $s3= "Powered by BetterInstaller" fullword wide
		 $s4= "VS_VERSION_INFO" fullword wide
		 $a1= "0http://crl.comodoca.com/COMODOCodeSigningCA2.crl0r" fullword ascii
		 $a2= "0http://crt.comodoca.com/COMODOCodeSigningCA2.crt0$" fullword ascii
		 $a3= "1http://crl.usertrust.com/UTN-USERFirst-Object.crl05" fullword ascii
		 $a4= "1http://crl.usertrust.com/UTN-USERFirst-Object.crl0t" fullword ascii
		 $a5= "1http://crt.usertrust.com/UTNAddTrustObject_CA.crt0%" fullword ascii
		 $a6= "ExpandEnvironmentStringsA" fullword ascii
		 $a7= "http://nsis.sf.net/NSIS_Error" fullword ascii
		 $a8= "http://ocsp.comodoca.com0" fullword ascii
		 $a9= "http://ocsp.usertrust.com0" fullword ascii
		 $a10= "https://secure.comodo.net/CPS0A" fullword ascii
		 $a11= "http://www.usertrust.com1" fullword ascii
		 $a12= "SHGetSpecialFolderLocation" fullword ascii
		 $a13= "SoftwareMicrosoftWindowsCurrentVersion" fullword ascii
		 $a14= "WritePrivateProfileStringA" fullword ascii

		 $hex1= {246131303d20226874}
		 $hex2= {246131313d20226874}
		 $hex3= {246131323d20225348}
		 $hex4= {246131333d2022536f}
		 $hex5= {246131343d20225772}
		 $hex6= {2461313d2022306874}
		 $hex7= {2461323d2022306874}
		 $hex8= {2461333d2022316874}
		 $hex9= {2461343d2022316874}
		 $hex10= {2461353d2022316874}
		 $hex11= {2461363d2022457870}
		 $hex12= {2461373d2022687474}
		 $hex13= {2461383d2022687474}
		 $hex14= {2461393d2022687474}
		 $hex15= {2473313d202246696c}
		 $hex16= {2473323d20224d5343}
		 $hex17= {2473333d2022506f77}
		 $hex18= {2473343d202256535f}

	condition:
		2 of them
}
