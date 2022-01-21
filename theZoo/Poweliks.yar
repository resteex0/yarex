
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Poweliks 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Poweliks {
	meta: 
		 description= "theZoo_Poweliks Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-35-13" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0181850239cd26b8fb8b72afb0e95eac"
		 hash2= "02884b95d5c3fde46c8ecd6ca409abd4"
		 hash3= "4a7ca7f2ad4cd92aa224485b687f52d9"
		 hash4= "a7ae1d1645bdbdf40471b1a3dc2a95f6"
		 hash5= "aeb9f61412c640319b61e1687d0860e5"
		 hash6= "c042511df4ce1f0305fb0cb1b84780a9"
		 hash7= "d6725d6f8c84afcb2e7eabe4683e0512"

	strings:

	
 		 $s1= "%windir%system32rundll32.exe" fullword wide
		 $a1= "Cesscoryshodpyro0hazynthgunsraga1-0-.Combawedsati_takeyap_._" fullword ascii

		 $hex1= {2461313d2022436573}
		 $hex2= {2473313d2022257769}

	condition:
		1 of them
}
