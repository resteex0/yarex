
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_W97M_Class_AU 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_W97M_Class_AU {
	meta: 
		 description= "theZoo_W97M_Class_AU Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-36-09" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "345e5ed6361e5f0f6ed521c3f2f3881c"
		 hash2= "58f3e1cb3d85ec986263cc61ea1cfec7"
		 hash3= "5c71303a31853917f08adc37a8ec32eb"
		 hash4= "6dc6f027f195e1c6e39971ea8d33d86f"

	strings:

	
 		 $s1= "|| C:WINDOWSDesktopVAMP_DEMO.doc" fullword wide
		 $s2= "||%C:WINDOWSDesktopVAMPVAMP_DEMO.doc" fullword wide
		 $s3= "DocumentSummaryInformation" fullword wide
		 $s4= "D:sokdemoVAMP_DEMO.doc" fullword wide
		 $s5= "{F7EC565B-91B3-11D2-8861-004033E0078E}" fullword wide
		 $s6= "Project.ThisDocument.AutoOpen" fullword wide
		 $a1= "With ActiveDocument.VBProject.VBComponents.Item(1).CodeModule" fullword ascii

		 $hex1= {2461313d2022576974}
		 $hex2= {2473313d20227c7c20}
		 $hex3= {2473323d20227c7c25}
		 $hex4= {2473333d2022446f63}
		 $hex5= {2473343d2022443a73}
		 $hex6= {2473353d20227b4637}
		 $hex7= {2473363d202250726f}

	condition:
		4 of them
}
