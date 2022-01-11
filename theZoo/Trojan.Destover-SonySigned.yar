
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Destover_SonySigned 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Destover_SonySigned {
	meta: 
		 description= "Trojan_Destover_SonySigned Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-30-38" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "e904bf93403c0fb08b9683a9e858c73e"

	strings:

	
 		 $s1= "203.131.222.102" fullword wide
		 $s2= "208.105.226.235" fullword wide
		 $s3= "Advanced Server " fullword wide
		 $s4= "Cluster Server " fullword wide
		 $s5= "Compute Cluster " fullword wide
		 $s6= "Datacenter(Core) " fullword wide
		 $s7= "Datacenter(Itanium) " fullword wide
		 $s8= "Datacenter Server " fullword wide
		 $s9= "Datacenter x64 " fullword wide
		 $s10= "eement which limit liability and are incorporated herein by reference" fullword wide
		 $s11= "Enterprise(Core) " fullword wide
		 $s12= "Enterprise(Itanium) " fullword wide
		 $s13= "Enterprise x64 " fullword wide
		 $s14= "FileDescription" fullword wide
		 $s15= "igfxstartup Module" fullword wide
		 $s16= "LegalTrademarks" fullword wide
		 $s17= "Microsoft Corporation" fullword wide
		 $s18= "Microsoft Corporation. All rights reserved." fullword wide
		 $s19= "Operating System" fullword wide
		 $s20= "OriginalFilename" fullword wide
		 $s21= "Parameter Error" fullword wide
		 $s22= "RAny use of this Certificate constitutes acceptance of the DigiCert CP/CPS and the Relying Party Agr" fullword wide
		 $s23= "Server2003(R2) " fullword wide
		 $s24= "Server2008(R2) " fullword wide
		 $s25= "Server2012(R2) " fullword wide
		 $s26= "Standard(Core) " fullword wide
		 $s27= "Storage Server2003 " fullword wide
		 $s28= "VS_VERSION_INFO" fullword wide
		 $a1= "1http://crl.usertrust.com/UTN-USERFirst-Object.crl05" fullword ascii
		 $a2= "abcdefghijklmnopqrstuvwxyz012345" fullword ascii
		 $a3= "---------------End--------------!" fullword ascii
		 $a4= "@http://cacerts.digicert.com/DigiCertAssuredIDCodeSigningCA-1.crt0" fullword ascii
		 $a5= "-http://crl3.digicert.com/assured-cs-2011a.crl03" fullword ascii
		 $a6= "-http://crl4.digicert.com/assured-cs-2011a.crl0" fullword ascii
		 $a7= "http://ocsp.digicert.com0C" fullword ascii
		 $a8= "http://ocsp.digicert.com0L" fullword ascii
		 $a9= "http://ocsp.usertrust.com0" fullword ascii
		 $a10= ".http://www.digicert.com/ssl-cps-repository.htm0" fullword ascii
		 $a11= "http://www.usertrust.com1" fullword ascii
		 $a12= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a13= "SetUnhandledExceptionFilter" fullword ascii

		 $hex1= {246131303d20222e68}
		 $hex2= {246131313d20226874}
		 $hex3= {246131323d20224a61}
		 $hex4= {246131333d20225365}
		 $hex5= {2461313d2022316874}
		 $hex6= {2461323d2022616263}
		 $hex7= {2461333d20222d2d2d}
		 $hex8= {2461343d2022406874}
		 $hex9= {2461353d20222d6874}
		 $hex10= {2461363d20222d6874}
		 $hex11= {2461373d2022687474}
		 $hex12= {2461383d2022687474}
		 $hex13= {2461393d2022687474}
		 $hex14= {247331303d20226565}
		 $hex15= {247331313d2022456e}
		 $hex16= {247331323d2022456e}
		 $hex17= {247331333d2022456e}
		 $hex18= {247331343d20224669}
		 $hex19= {247331353d20226967}
		 $hex20= {247331363d20224c65}
		 $hex21= {247331373d20224d69}
		 $hex22= {247331383d20224d69}
		 $hex23= {247331393d20224f70}
		 $hex24= {2473313d2022323033}
		 $hex25= {247332303d20224f72}
		 $hex26= {247332313d20225061}
		 $hex27= {247332323d20225241}
		 $hex28= {247332333d20225365}
		 $hex29= {247332343d20225365}
		 $hex30= {247332353d20225365}
		 $hex31= {247332363d20225374}
		 $hex32= {247332373d20225374}
		 $hex33= {247332383d20225653}
		 $hex34= {2473323d2022323038}
		 $hex35= {2473333d2022416476}
		 $hex36= {2473343d2022436c75}
		 $hex37= {2473353d2022436f6d}
		 $hex38= {2473363d2022446174}
		 $hex39= {2473373d2022446174}
		 $hex40= {2473383d2022446174}
		 $hex41= {2473393d2022446174}

	condition:
		5 of them
}
