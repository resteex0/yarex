
/*
   YARA Rule Set
   Author: resteex
   Identifier: Linux_Mirai_B 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Linux_Mirai_B {
	meta: 
		 description= "Linux_Mirai_B Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-42-34" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0a5852e0dd9ac8cc990d852ea1b7fdee"
		 hash2= "390f1382237b5a01dd46bf1404c223e7"
		 hash3= "9a6e4b8a6ba5b4f5a408919d2c169d92"
		 hash4= "f94541b48f85af92ea43e53d8b011aad"

	strings:

	
 		 $a1= "Connection-Type: application/x-www-form-urlencoded" fullword ascii
		 $a2= "SOAPAction: urn:dslforum-org:service:Time:1#SetNTPServers" fullword ascii

		 $hex1= {2461313d2022436f6e}
		 $hex2= {2461323d2022534f41}

	condition:
		1 of them
}
