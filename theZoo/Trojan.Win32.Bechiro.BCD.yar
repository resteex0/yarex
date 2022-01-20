
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
		 date = "2022-01-20_04-43-53" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0d06681f63f3026260aa1e15d86520a0"

	strings:

	
 		 $a1= "0http://crl.comodoca.com/COMODOCodeSigningCA2.crl0r" fullword ascii
		 $a2= "0http://crt.comodoca.com/COMODOCodeSigningCA2.crt0$" fullword ascii
		 $a3= "1http://crl.usertrust.com/UTN-USERFirst-Object.crl0t" fullword ascii
		 $a4= "1http://crt.usertrust.com/UTNAddTrustObject_CA.crt0%" fullword ascii

		 $hex1= {2461313d2022306874}
		 $hex2= {2461323d2022306874}
		 $hex3= {2461333d2022316874}
		 $hex4= {2461343d2022316874}

	condition:
		2 of them
}
