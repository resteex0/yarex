
/*
   YARA Rule Set
   Author: resteex
   Identifier: WM_Concept_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_WM_Concept_A {
	meta: 
		 description= "WM_Concept_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-45-23" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "5a6ecfa0a84258cd8aa40fcab60ed8d2"
		 hash2= "5d398c444dbaf19ef7dc0e804439761a"
		 hash3= "a3e28b177b2a95c24f69c80c1ba2dff8"

	strings:

	
 		 $s1= "DocumentSummaryInformation" fullword wide
		 $a1= "James Saunders(C:WINDOWSDesktopvirusMacrois003.doc" fullword ascii

		 $hex1= {2461313d20224a616d}
		 $hex2= {2473313d2022446f63}

	condition:
		1 of them
}
