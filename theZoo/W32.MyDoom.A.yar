
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_MyDoom_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_MyDoom_A {
	meta: 
		 description= "W32_MyDoom_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-05" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "10a5ce311f8f925a5d180d01aa62b560"
		 hash2= "2eb21132d838154920b4808820d6a63d"
		 hash3= "53df39092394741514bc050f3d6a06a9"
		 hash4= "6cee152928b02f883867a51c89633106"
		 hash5= "91800f7d2ca85deedba2735c8b4505ce"

	strings:

	
 		 $a1= "HKEY_LOCAL_MACHINESYSTEMCurrentControlSetServices" fullword ascii
		 $a2= "HKEY_LOCAL_MACHINESystemCurrentControlSetServicesEventLog" fullword ascii
		 $a3= "/HTML>" fullword ascii
		 $a4= "REGISTRYMachineSYSTEMCurrentControlSetServices" fullword ascii
		 $a5= "SYSTEMCurrentControlSetServicesF-PROT Gatekeeper" fullword ascii
		 $a6= "SYSTEMCurrentControlSetServicesF-Secure Gatekeeper" fullword ascii

		 $hex1= {2461313d2022484b45}
		 $hex2= {2461323d2022484b45}
		 $hex3= {2461333d20222f4854}
		 $hex4= {2461343d2022524547}
		 $hex5= {2461353d2022535953}
		 $hex6= {2461363d2022535953}

	condition:
		4 of them
}
