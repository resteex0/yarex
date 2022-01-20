
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
		 date = "2022-01-20_04-43-27" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "02e0b78e2876087f678f070ed60e4c30"

	strings:

	
 		 $a1= "0http://crl.comodoca.com/COMODOCodeSigningCA2.crl0r" fullword ascii
		 $a2= "0http://crt.comodoca.com/COMODOCodeSigningCA2.crt0$" fullword ascii
		 $a3= "1http://crl.usertrust.com/UTN-USERFirst-Object.crl05" fullword ascii
		 $a4= "1http://crl.usertrust.com/UTN-USERFirst-Object.crl0t" fullword ascii
		 $a5= "1http://crt.usertrust.com/UTNAddTrustObject_CA.crt0%" fullword ascii

		 $hex1= {2461313d2022306874}
		 $hex2= {2461323d2022306874}
		 $hex3= {2461333d2022316874}
		 $hex4= {2461343d2022316874}
		 $hex5= {2461353d2022316874}

	condition:
		3 of them
}
