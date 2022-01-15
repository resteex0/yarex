
/*
   YARA Rule Set
   Author: resteex
   Identifier: Bartalex 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Bartalex {
	meta: 
		 description= "Bartalex Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-01-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "05be09f648bf2b62ebf9cd79ccfd0087"
		 hash2= "22a7aafe5190a5cdcc92bfd304a21f7d"
		 hash3= "91207439790ffe5f0d177c27cf4d68ac"
		 hash4= "a5cfe37d8ecfc22a60954f8462273e3f"

	strings:

	
 		 $s1= "6.7.2300.5512 (xpsp.080413-2108)" fullword wide
		 $s2= "DocumentSummaryInformation" fullword wide
		 $s3= "Project.ThisDocument.Auto_Open" fullword wide
		 $s4= "Project.ThisDocument.AutoOpen" fullword wide

		 $hex1= {2473313d2022362e37}
		 $hex2= {2473323d2022446f63}
		 $hex3= {2473333d202250726f}
		 $hex4= {2473343d202250726f}

	condition:
		2 of them
}
