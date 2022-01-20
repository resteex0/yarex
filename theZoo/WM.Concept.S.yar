
/*
   YARA Rule Set
   Author: resteex
   Identifier: WM_Concept_S 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_WM_Concept_S {
	meta: 
		 description= "WM_Concept_S Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-45-24" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "800ffaff2914cfc7994249d167284192"

	strings:

	
 		 $a1= "p3 CTForders:>~msg>pulic;*public;public*>echo_youdo" fullword ascii
		 $a2= "p8 CTFin83=TCCL-11/6F/200P/BB/MB/LS/HS/inYYY/withPwd901109do" fullword ascii
		 $a3= "T.S.H.>do" fullword ascii

		 $hex1= {2461313d2022703320}
		 $hex2= {2461323d2022703820}
		 $hex3= {2461333d2022542e53}

	condition:
		2 of them
}
