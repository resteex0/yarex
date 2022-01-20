
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win64_NukeSped 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win64_NukeSped {
	meta: 
		 description= "Win64_NukeSped Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-45-18" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "379d680a2accaa48444524968d1aa782"
		 hash2= "cebc3a9192d6b516e7937038acb689b0"
		 hash3= "e1068cacba806002b1cba6ebfb35e4f4"

	strings:

	
 		 $s1= "%04d-%02d-%02d %02d:%02d:%02d" fullword wide
		 $s2= "6.1.7600.16385 (win7_rtm.090713-1255)" fullword wide
		 $s3= "HARDWAREDESCRIPTIONSystemCentralProcessor0" fullword wide
		 $s4= "SeAssignPrimaryTokenPrivilege" fullword wide
		 $s5= "SOFTWAREMICROSOFTWINDOWS NTCURRENTVERSION" fullword wide
		 $s6= "SYSTEMCurrentControlSetControlSession ManagerEnvironment" fullword wide

		 $hex1= {2473313d2022253034}
		 $hex2= {2473323d2022362e31}
		 $hex3= {2473333d2022484152}
		 $hex4= {2473343d2022536541}
		 $hex5= {2473353d2022534f46}
		 $hex6= {2473363d2022535953}

	condition:
		4 of them
}
