
/*
   YARA Rule Set
   Author: resteex
   Identifier: Poweliks 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Poweliks {
	meta: 
		 description= "Poweliks Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-42-48" 
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
		 $a2= "type=%s&version=1.0&aid=%s&builddate=%s&id=%s&os=%s_%s" fullword ascii
		 $a3= "%windir%system32windowspowershellv1.0powershell.exe" fullword ascii

		 $hex1= {2461313d2022436573}
		 $hex2= {2461323d2022747970}
		 $hex3= {2461333d2022257769}
		 $hex4= {2473313d2022257769}

	condition:
		2 of them
}
