
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_WannaCry_Plus 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_WannaCry_Plus {
	meta: 
		 description= "Ransomware_WannaCry_Plus Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-43-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "30fe2f9a048d7a734c8d9233f64810ba"

	strings:

	
 		 $a1= "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" fullword ascii

		 $hex1= {2461313d2022687474}

	condition:
		0 of them
}
