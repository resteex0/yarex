
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Waski_Upatre 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Waski_Upatre {
	meta: 
		 description= "theZoo_Waski_Upatre Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-36-12" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "41859ac8b90080471dfb315bf439d6f4"
		 hash2= "4d6c045c4cca49f8e556a7fb96e28635"
		 hash3= "6e67fb3835da739a11570bba44a19dbc"
		 hash4= "7a1f26753d6e70076f15149feffbe233"
		 hash5= "f44b714297a01a8d72e21fe658946782"

	strings:

	
 		 $s1= "guswdfpjqmhujolohbpulannxkeqeem" fullword wide
		 $s2= "jjoiewbstfyjvworwmohmvkshxjv" fullword wide

		 $hex1= {2473313d2022677573}
		 $hex2= {2473323d20226a6a6f}

	condition:
		1 of them
}
