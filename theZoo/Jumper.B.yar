
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Jumper_B 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Jumper_B {
	meta: 
		 description= "theZoo_Jumper_B Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-35-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "3235e962f69939e6a43fef3abf620d56"
		 hash2= "de35afe288d64ea01f201e2a24f3a732"

	strings:

	
 		 $a1= ";?CLONE@CBACKGROUNDVIDEOBITMAPGENERATOR@@VECPEVCFCOBJECT@@XZ$" fullword ascii
		 $a2= "?CLOSEGROUP@CFCFILE@@RECFI@Z!?CREATEGROUP@CFCFILE@@RECFPED0I@Z" fullword ascii
		 $a3= "=?GETTHISCOMPONENT@CVIDEOBITMAPGENERATOR@@VECPEVCCOMPONENT@@XZ$" fullword ascii

		 $hex1= {2461313d20223b3f43}
		 $hex2= {2461323d20223f434c}
		 $hex3= {2461333d20223d3f47}

	condition:
		2 of them
}
