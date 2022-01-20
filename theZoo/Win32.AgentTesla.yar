
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_AgentTesla 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_AgentTesla {
	meta: 
		 description= "Win32_AgentTesla Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-10" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2b294b3499d1cce794badffc959b7618"

	strings:

	
 		 $a1= "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii

		 $hex1= {2461313d2022345379}

	condition:
		0 of them
}
