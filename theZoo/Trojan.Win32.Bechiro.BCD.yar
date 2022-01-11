
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Win32_Bechiro_BCD 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Win32_Bechiro_BCD {
	meta: 
		 description= "Trojan_Win32_Bechiro_BCD Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-30-53" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "0d06681f63f3026260aa1e15d86520a0"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "OriginalFilename" fullword wide
		 $s3= "VS_VERSION_INFO" fullword wide
		 $a1= "0http://crl.comodoca.com/COMODOCodeSigningCA2.crl0r" fullword ascii
		 $a2= "0http://crt.comodoca.com/COMODOCodeSigningCA2.crt0$" fullword ascii
		 $a3= "1http://crl.usertrust.com/UTN-USERFirst-Object.crl0t" fullword ascii
		 $a4= "1http://crt.usertrust.com/UTNAddTrustObject_CA.crt0%" fullword ascii
		 $a5= "e:4878377;u:4fe0cf9f-1fe4-4abb-905a-57915bc06f2f" fullword ascii
		 $a6= ".http://crl.thawte.com/ThawteTimestampingCA.crl0" fullword ascii
		 $a7= "http://ocsp.comodoca.com0-" fullword ascii
		 $a8= "http://ocsp.usertrust.com0" fullword ascii
		 $a9= "https://secure.comodo.net/CPS0A" fullword ascii
		 $a10= "+http://ts-crl.ws.symantec.com/tss-ca-g2.crl0(" fullword ascii
		 $a11= "http://ts-ocsp.ws.symantec.com07" fullword ascii
		 $a12= "http://www.usertrust.com1" fullword ascii

		 $hex1= {246131303d20222b68}
		 $hex2= {246131313d20226874}
		 $hex3= {246131323d20226874}
		 $hex4= {2461313d2022306874}
		 $hex5= {2461323d2022306874}
		 $hex6= {2461333d2022316874}
		 $hex7= {2461343d2022316874}
		 $hex8= {2461353d2022653a34}
		 $hex9= {2461363d20222e6874}
		 $hex10= {2461373d2022687474}
		 $hex11= {2461383d2022687474}
		 $hex12= {2461393d2022687474}
		 $hex13= {2473313d202246696c}
		 $hex14= {2473323d20224f7269}
		 $hex15= {2473333d202256535f}

	condition:
		1 of them
}
