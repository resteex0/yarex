
/*
   YARA Rule Set
   Author: resteex
   Identifier: PlugX 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_PlugX {
	meta: 
		 description= "PlugX Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-42-47" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "3bc9e9b78ac6dee1a44436859849bbbf"
		 hash2= "3c74a85c2cf883bd9d4b9f8b9746030f"
		 hash3= "5f9f8ac1f749b0637eca6ef15910bf21"
		 hash4= "6b97b3cd2fcfb4b74985143230441463"
		 hash5= "901fa02ffd43de5b2d7c8c6b8c2f6a43"
		 hash6= "97c11e7d6b1926cd4be13804b36239ac"
		 hash7= "c116cd083284cc599c024c3479ca9b70"
		 hash8= "fc88beeb7425aefa5e8936e06849f484"

	strings:

	
 		 $s1= "DocumentSummaryInformation" fullword wide
		 $a1= "0http://crl.verisign.com/ThawteTimestampingCA.crl0" fullword ascii
		 $a2= "3http://csc3-2009-2-aia.verisign.com/CSC3-2009-2.cer0" fullword ascii
		 $a3= "3http://csc3-2009-2-crl.verisign.com/CSC3-2009-2.crl0D" fullword ascii

		 $hex1= {2461313d2022306874}
		 $hex2= {2461323d2022336874}
		 $hex3= {2461333d2022336874}
		 $hex4= {2473313d2022446f63}

	condition:
		2 of them
}
