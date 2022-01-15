
/*
   YARA Rule Set
   Author: resteex
   Identifier: W97M_Class_AU 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W97M_Class_AU {
	meta: 
		 description= "W97M_Class_AU Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-54-23" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "345e5ed6361e5f0f6ed521c3f2f3881c"
		 hash2= "58f3e1cb3d85ec986263cc61ea1cfec7"
		 hash3= "5c71303a31853917f08adc37a8ec32eb"
		 hash4= "6dc6f027f195e1c6e39971ea8d33d86f"

	strings:

	
 		 $s1= "(1Normal.ThisDocument" fullword wide
		 $s2= "|| C:WINDOWSDesktopVAMP_DEMO.doc" fullword wide
		 $s3= "||%C:WINDOWSDesktopVAMPVAMP_DEMO.doc" fullword wide
		 $s4= "DocumentSummaryInformation" fullword wide
		 $s5= "D:sokdemoVAMP_DEMO.doc" fullword wide
		 $s6= "{F7EC565B-91B3-11D2-8861-004033E0078E}" fullword wide
		 $s7= "Project.ThisDocument.AutoOpen" fullword wide
		 $s8= "SummaryInformation" fullword wide
		 $a1= "|| C:WINDOWSDesktopVAMP_DEMO.doc" fullword ascii
		 $a2= "||%C:WINDOWSDesktopVAMPVAMP_DEMO.doc" fullword ascii
		 $a3= "{F7EC565B-91B3-11D2-8861-004033E0078E}" fullword ascii

		 $hex1= {2461313d20227c7c20}
		 $hex2= {2461323d20227c7c25}
		 $hex3= {2461333d20227b4637}
		 $hex4= {2473313d202228314e}
		 $hex5= {2473323d20227c7c20}
		 $hex6= {2473333d20227c7c25}
		 $hex7= {2473343d2022446f63}
		 $hex8= {2473353d2022443a73}
		 $hex9= {2473363d20227b4637}
		 $hex10= {2473373d202250726f}
		 $hex11= {2473383d202253756d}

	condition:
		1 of them
}
