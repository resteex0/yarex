
/*
   YARA Rule Set
   Author: resteex
   Identifier: CryptoLocker_22Jan2014 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_CryptoLocker_22Jan2014 {
	meta: 
		 description= "CryptoLocker_22Jan2014 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-42-19" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0246bb54723bd4a49444aa4ca254845a"
		 hash2= "829dde7015c32d7d77d8128665390dab"

	strings:

	
 		 $a1= "3System.Resources.Tools.StronglyTypedResourceBuilder" fullword ascii

		 $hex1= {2461313d2022335379}

	condition:
		0 of them
}
