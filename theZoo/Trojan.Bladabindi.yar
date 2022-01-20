
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Bladabindi 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Bladabindi {
	meta: 
		 description= "Trojan_Bladabindi Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-43-48" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "5a559b6d223c79f3736dc52794636cfd"

	strings:

	
 		 $a1= "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii

		 $hex1= {2461313d2022345379}

	condition:
		0 of them
}
