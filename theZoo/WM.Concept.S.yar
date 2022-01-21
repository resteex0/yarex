
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_WM_Concept_S 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_WM_Concept_S {
	meta: 
		 description= "theZoo_WM_Concept_S Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-37-13" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "800ffaff2914cfc7994249d167284192"

	strings:

	
 		 $a1= "p8 CTFin83=TCCL-11/6F/200P/BB/MB/LS/HS/inYYY/withPwd901109do" fullword ascii
		 $a2= "T.S.H.>do" fullword ascii

		 $hex1= {2461313d2022703820}
		 $hex2= {2461323d2022542e53}

	condition:
		1 of them
}
